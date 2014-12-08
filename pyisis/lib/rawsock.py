#
# November 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.
#
from __future__ import absolute_import, division, nested_scopes, print_function, unicode_literals

from fcntl import ioctl
from ctypes import cast, c_void_p, c_uint16, Structure
import pyisis.clns as clns
import ipaddress
import logbook
import re
import socket
import struct
import subprocess
import sys

logger = logbook.Logger(__name__)

# From bits/ioctls.h
SIOCGIFHWADDR = 0x8927 # Get hardware address
SIOCGIFADDR = 0x8915 # get PA address
SIOCGIFNETMASK = 0x891b # get network PA mask
SIOCGIFNAME = 0x8910 # get iface name
SIOCSIFLINK = 0x8911 # set iface channel
SIOCGIFCONF = 0x8912 # get iface list
SIOCGIFFLAGS = 0x8913 # get flags
SIOCSIFFLAGS = 0x8914 # set flags
SIOCGIFINDEX = 0x8933 # name -> if_index mapping
SIOCGIFCOUNT = 0x8938 # get number of devices
SIOCGSTAMP = 0x8906 # get packet timestamp (as a timeval)

# From if.h
IFF_UP = 0x1 # Interface is up.
IFF_BROADCAST = 0x2 # Broadcast address valid.
IFF_DEBUG = 0x4 # Turn on debugging.
IFF_LOOPBACK = 0x8 # Is a loopback net.
IFF_POINTOPOINT = 0x10 # Interface is point-to-point link.
IFF_NOTRAILERS = 0x20 # Avoid use of trailers.
IFF_RUNNING = 0x40 # Resources allocated.
IFF_NOARP = 0x80 # No address resolution protocol.
IFF_PROMISC = 0x100 # Receive all packets.

# From netpacket/packet.h
PACKET_ADD_MEMBERSHIP = 1
PACKET_DROP_MEMBERSHIP = 2
PACKET_RECV_OUTPUT = 3
PACKET_RX_RING = 5
PACKET_STATISTICS = 6
PACKET_MR_MULTICAST = 0
PACKET_MR_PROMISC = 1
PACKET_MR_ALLMULTI = 2

# From bits/socket.h
SOL_PACKET = 263
# From asm/socket.h
SO_ATTACH_FILTER = 26
SOL_SOCKET = 1


def get_if(iff, cmd):
    s = socket.socket()

    if sys.version_info >= (3, 0):
        ifreq = ioctl(s, cmd, struct.pack("16s16x", bytes(iff, "ascii")))
    else:
        ifreq = ioctl(s, cmd, struct.pack("16s16x", iff))
    s.close()
    return ifreq


def get_if_index(iff):
    return int(struct.unpack("I", get_if(iff, SIOCGIFINDEX)[16:20])[0])


def set_promisc(s, iff, val):
    mreq = struct.pack("IHH8s", get_if_index(iff), PACKET_MR_PROMISC, 0, "")
    if val:
        cmd = PACKET_ADD_MEMBERSHIP
    else:
        cmd = PACKET_DROP_MEMBERSHIP
    s.setsockopt(SOL_PACKET, cmd, mreq)


class RawInterface (object):
    def __init__ (self, ifname):
        ETH_P_ALL = 3
        self.name = ifname
        self.ifindex = get_if_index(ifname)
        # Open an available BPF device
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        # _flush_fd(self.ins)
        # set_promisc(self.socket, ifname, True)
        self.socket.bind((ifname, ETH_P_ALL))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 ** 30)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 ** 30)
        self.buflen = 65535

    def set_filter (self, insns):
        class BPFProgram (Structure):
            _fields_ = [
                ("bf_len", c_uint16),
                ("bf_insns", c_void_p), ]

        # Attach BPF filter
        bf_len = len(insns) // 8                            # 8 == 2 + 1 + 1 + 4
        bf_insns = cast(insns, c_void_p)
        program = BPFProgram(bf_len, bf_insns)
        self.socket.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER,
                               struct.pack("HP", program.bf_len, program.bf_insns))

    def add_drop_group (self, add, maddr):
        if sys.version_info >= (3, 0):
            mreq = struct.pack("IHH6s2s", self.ifindex, PACKET_MR_MULTICAST, 6, maddr, bytes())
        else:
            mreq = struct.pack("IHH6s2s", self.ifindex, PACKET_MR_MULTICAST, 6, maddr, b"")
        if add:
            cmd = PACKET_ADD_MEMBERSHIP
        else:
            cmd = PACKET_DROP_MEMBERSHIP
        self.socket.setsockopt(SOL_PACKET, cmd, mreq)

    def recv_pkt (self):
        pkt, sa_ll = self.socket.recvfrom(self.buflen)
        if pkt is None:
            return None
        if sa_ll[2] == socket.PACKET_OUTGOING:
            return None
        return pkt

    def fileno (self):
        return self.socket.fileno()

    def write (self, pkt):
        return self.writev([pkt])

    def writev (self, buffers):
        from pyisis.bstr import sendv                       # pylint: disable=E0611
        return sendv(self.socket, buffers)

    def get_if_addrs (self):
        ifname = self.name
        # codes are different for mac and linux
        output = subprocess.check_output("/sbin/ifconfig {}".format(ifname),
                                         shell=True,
                                         universal_newlines=True)
        match = re.search(r"HWaddr ([a-zA-Z0-9:]+)", output)
        assert match
        mac_addr = clns.mac_encode(match.group(1))

        # inet addr:192.168.1.10  Bcast:192.168.1.255  Mask:255.255.255.0
        match = re.search(r"inet addr:([0-9\.]+).*Mask:([0-9\.]+)", output)
        # mask = ipaddress.ip_address(match.group(2))
        ipv4_prefix = ipaddress.ip_interface('{}/{}'.format(*match.groups()))
        # ipv4_prefix = ipaddress.ip_interface('{}/24'.format(match.group(1)))
        # ipv4_prefix = ipaddress.ip_interface('{}/24'.format(match.group(1)))

        return mac_addr, ipv4_prefix

__author__ = 'Christian Hopps'
__date__ = 'October 28 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
