#!/usr/bin/python
# -*- coding: UTF-8 -*-

from __future__ import print_function
from __future__ import unicode_literals
import os
import sys
import time
import struct
import socket
from fcntl import ioctl
from select import select
from threading import Thread

PASSWORD = b'4fb88ca224e'

MTU = 1400
BUFFER_SIZE = 4096
KEEPALIVE = 10

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


def start_tunnel(tun_name, local_IP, peer_IP):
    os.popen('ifconfig %s %s dstaddr %s mtu %s up' %
             (tun_name, local_IP, peer_IP, MTU)).read()


class Client():
    def __init__(self, SERVER_ADDRESS):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(5)
        self.to = SERVER_ADDRESS

    def keepalive(self):
        def _keepalive(udp, to):
            while True:
                time.sleep(KEEPALIVE)
                udp.sendto(b'\x00', to)
        k = Thread(target=_keepalive, args=(
            self.udp, self.to), name='keepalive')
        k.setDaemon(True)
        k.start()

    def login(self):
        self.udp.sendto(PASSWORD, self.to)
        try:
            data, addr = self.udp.recvfrom(BUFFER_SIZE)
            tun_fd, tun_name = create_tunnel()
            local_IP, peer_IP = data.decode().split(';')
            print('Local ip: %s\tPeer ip: %s' % (local_IP, peer_IP))
            start_tunnel(tun_name, local_IP, peer_IP)
            return tun_fd
        except socket.timeout:
            return False

    def run_forever(self):
        print('Start connect to server...')
        tun_fd = self.login()
        if not tun_fd:
            print("Connect failed!")
            sys.exit(0)
        print('Connect to server successful')
        self.keepalive()
        readables = [self.udp, tun_fd]
        while True:
            try:
                readab = select(readables, [], [], 10)[0]
            except KeyboardInterrupt:
                self.udp.sendto(b'e', self.to)
                raise KeyboardInterrupt
            for r in readab:
                if r == self.udp:
                    data, addr = self.udp.recvfrom(BUFFER_SIZE)
                    try:
                        os.write(tun_fd, data)
                    except OSError:
                        if data == b'r':
                            os.close(tun_fd)
                            readables.remove(tun_fd)
                            print('Reconnecting...')
                            tun_fd = self.login()
                            readables.append(tun_fd)
                        continue
                else:
                    data = os.read(tun_fd, BUFFER_SIZE)
                    self.udp.sendto(data, self.to)


if __name__ == '__main__':
    try:
        SERVER_ADDRESS = (sys.argv[1], int(sys.argv[2]))
        Client(SERVER_ADDRESS).run_forever()
    except IndexError:
        print('Usage: %s [remote_ip] [remote_port]' % sys.argv[0])
    except KeyboardInterrupt:
        print('Closing vpn client ...')
