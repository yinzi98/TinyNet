#!/usr/bin/python
# -*- coding: UTF-8 -*-

'''
struct 是一个将Python的数据类型转换为C语言中的数据类型的字节流的模块
fnctl.ioctl 用来对设备的一些特性进行控制，比如这里来设定要启用的虚拟网卡的类型和网卡名称
select 是 I/O多路复用 的一个实现，用来在单线程中高效的利用网络I/O
ipaddress 模块是Python3新增的模块，用来解析IP地址的
'''
import os
import time
import struct
import socket
from fcntl import ioctl
from select import select
from threading import Thread
from ipaddress import ip_network

DEBUG = True
PASSWORD = b'4fb88ca224e'

BIND_ADDRESS = '0.0.0.0', 8283
NETWORK = '10.0.0.0/24'
BUFFER_SIZE = 4096
MTU = 1400

IPRANGE = list(map(str, ip_network(NETWORK)))[1:]
LOCAL_IP = IPRANGE.pop(0)

'''
这三个常量实际上是定义在 linux/if_tun.h 这个头文件中，
因为用Python来实现 tun 隧道,所以也需要使用这三个常量。
TUNSETIFF 这个常量是告诉 ioctl 要完成虚拟网卡的注册，
而IFF_TUN 和 IFF_TAP 则表示是要使用 tun 类型还是 tap 类型的虚拟网卡
'''
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002


'''
默认使用 tun 类型的虚拟网卡。
使用 ioctl 来创建一个虚拟网卡，并返回创建成功后的网卡名称，
默认是按照 tun0，tun1 依次增加的。
'''


def create_tunnel(tun_name='tun%d', tun_mode=IFF_TUN):
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    ifn = ioctl(tun_fd, TUNSETIFF, struct.pack(
        b"16sH", tun_name.encode(), tun_mode))
    tun_name = ifn[:16].decode().strip("\x00")
    return tun_fd, tun_name


'''
使用 ifconfig 命令为虚拟网卡配置IP地址。
MTU 之所以设置为 1400 因为Linux默认网卡的 MTU 是 1500，
但是隧道来的数据包还要包裹一层 udp 封装发往对端，
如果隧道的 MTU 也设置为 1500 的话，
那最终通过 udp 封装后肯定会超出物理网卡的界限，
最终会被拆分为两个数据包发送二照成不必要的浪费。
'''


def start_tunnel(tun_name, peer_IP):
    os.popen('ifconfig %s %s dstaddr %s mtu %s up' %
             (tun_name, LOCAL_IP, peer_IP, MTU)).read()


def get_format_now():
    return time.strftime('[%Y/%m/%d %H:%M:%S] ')


class Server():

    '''
    self.sessions = [] 用来保存连接的用户会话
    self.readables = [] 保存为每个会话创建的隧道的文件描述符
    self.tun_info 定义了每个会话保存的隧道信息
    '''

    def __init__(self):
        self.sessions = []
        self.readables = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(BIND_ADDRESS)
        self.readables.append(self.udp)
        self.tun_info = {
            'tun_name': None, 'tun_fd': None,
            'addr': None, 'tun_addr': None, 'last_time': None
        }
        print('Server listen on %s:%s...' % BIND_ADDRESS)

    '''
    通过接受到数据包的来源信息确定需要注入到哪条隧道
    '''

    def get_tun_by_addr(self, addr):
        for session in self.sessions:
            if session['addr'] == addr:
                return session['tun_fd']
        return -1

    '''
    根据从隧道来的数据找到是要通过 udp 发往哪个主机
    '''

    def get_addr_by_tun(self, tun_fd):
        for session in self.sessions:
            if session['tun_fd'] == tun_fd:
                return session['addr']
        return -1

    '''
    client连接成功后为它创建一个会话和相应的虚拟网卡.
    并且将client的网卡配置信息通过 udp 发送过去
    '''

    def create_session(self, addr):
        tun_fd, tun_name = create_tunnel()
        tun_addr = IPRANGE.pop(0)
        start_tunnel(tun_name, tun_addr)
        self.sessions.append(
            {
                'tun_name': tun_name, 'tun_fd': tun_fd,
                'addr': addr, 'tun_addr': tun_addr,
                'last_time': time.time()
            }
        )
        self.readables.append(tun_fd)
        reply = '%s;%s' % (tun_addr, LOCAL_IP)
        self.udp.sendto(reply.encode(), addr)

    '''
    清理用户会话和虚拟网卡
    '''

    def del_session_by_tun(self, tun_fd):
        if tun_fd == -1:
            return False
        for session in self.sessions:
            if session['tun_fd'] == tun_fd:
                self.sessions.remove(session)
                IPRANGE.append(session['tun_addr'])
        self.readables.remove(tun_fd)
        os.close(tun_fd)
        return True

    '''
    client发送来心跳包后更新用户最后一次发送心跳包的时间戳
    '''

    def update_last_time(self, tun_fd):
        for session in self.sessions:
            if session['tun_fd'] == tun_fd:
                session['last_time'] = time.time()

    '''
    清理已经超过一分钟没有发来心跳包的client，
    认为这个client已经失去了连接，
    但是可能因为网络故障等原因没有正常关闭隧道
    '''

    def clean_expire_tun(self):
        while True:
            for session in self.sessions:
                if (time.time() - session['last_time']) > 60:
                    self.del_session_by_tun(session['tun_fd'])
                    if DEBUG:
                        print('Session: %s:%s expired!' % session['addr'])
            time.sleep(True)

    '''
    对client发来的数据进行处理，
    client发来 b'\x00' 则表明这是一个心跳包，
    但是如果并不存在这个心跳包源主机的会话，
    可能因为网络原因服务端清理了这个client的会话，
    就发送 b'r' 告诉client重新认证。
    否则就更新这个会话的最后心跳包的时间戳。
    client在退出的时候会发送 b'e' 到服务端，
    然后服务端会主动清理这个client的会话。
    最后会匹配数据包是否是认证密码，
    如果认证成功了就返回 True 程序会继续处理。
    '''

    def auth(self, addr, data, tun_fd):
        if data == b'\x00':
            if tun_fd == -1:
                self.udp.sendto(b'r', addr)
            else:
                self.update_last_time(tun_fd)
            return False
        if data == b'e':
            self.del_session_by_tun(tun_fd)
            if DEBUG:
                print("Client %s:%s is disconnect" % addr)
            return False
        if data == PASSWORD:
            return True
        else:
            if DEBUG:
                print('Clinet %s:%s connect failed' % addr)
            return False

    '''
    使用一个新线程启动会话清理方法，然后进入事件循环，
    使用 select 监听 udp 网络套接字和隧道套接字的可读事件，
    一旦某个套接字有数据过来了 select 则会返回这个套接字对象，
    然后判断这个套接字是网络套接字还是隧道套接字，
    如果是网络套接字则首先尝试将数据写入到客户端所在的隧道中，
    如果数据内容不是一个正确的网络数据包格式或者没有找到这个客户端地址相关联的隧道，
    就进入异常处理模式，因为新客户端的连接和心跳包导致进入异常处理的频率比较小,
    所以并不会对整体性能照成很大的影响，
    如果在一开始就进行数据内容判断就非常影响程序的性能了，
    因为毕竟接收到的大多都是合法的能写入到隧道的数据包。
    接着如果可读对象是一个隧道文件描述符的话，就找到客户端的网络地址，
    通过 udp 将读取到的数据包发送给客户端，并且如果出现了任何异常的话就跳过。
    '''

    def run_forever(self):
        clean_thread = Thread(target=self.clean_expire_tun)
        clean_thread.setDaemon(True)
        clean_thread.start()
        while True:
            readab = select(self.readables, [], [], 1)[0]
            for r in readab:
                if r == self.udp:
                    data, addr = self.udp.recvfrom(BUFFER_SIZE)
                    if DEBUG:
                        print(get_format_now()+'from    (%s:%s)' %
                              addr, data[:10])
                    try:
                        tun_fd = self.get_tun_by_addr(addr)
                        try:
                            os.write(tun_fd, data)
                        except OSError:
                            if not self.auth(addr, data, tun_fd):
                                continue
                            self.create_session(addr)
                            if DEBUG:
                                print('Clinet %s:%s connect successful' % addr)
                    except OSError:
                        continue
                else:
                    try:
                        addr = self.get_addr_by_tun(r)
                        data = os.read(r, BUFFER_SIZE)
                        self.udp.sendto(data, addr)
                        if DEBUG:
                            print(get_format_now()+'to      (%s:%s)' %
                                  addr, data[:10])
                    except Exception:
                        continue


if __name__ == '__main__':
    try:
        Server().run_forever()
    except KeyboardInterrupt:
        print('Closing vpn server ...')
