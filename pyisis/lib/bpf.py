#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import absolute_import, division, nested_scopes, print_function, unicode_literals
from pyisis.lib.util import xrange3

import errno
import ipaddress
import os
from fcntl import ioctl
import re
import struct
import subprocess
import logbook

from ctypes import cast, sizeof, POINTER
from ctypes import Structure
from ctypes import c_uint8, c_uint16, c_uint32, c_uint, c_void_p

import pyisis.clns as clns
from pyisis.bstr import writev                              # pylint: disable=E0611

logger = logbook.Logger(__name__)

BIOCGBLEN = 0x40044266
BIOCSBLEN = 0xc0044266
BIOCSETF = 0x80104267
BIOCFLUSH = 0x20004268
BIOCPROMISC = 0x20004269
BIOCGDLT = 0x4004426a
BIOCGETIF = 0x4020426b
BIOCSETIF = 0x8020426c
BIOCSRTIMEOUT = 0x8010426d
BIOCGRTIMEOUT = 0x4010426e
BIOCGSTATS = 0x4008426f
BIOCIMMEDIATE = 0x80044270
BIOCVERSION = 0x40044271
BIOCGRSIG = 0x40044272
BIOCSRSIG = 0x80044273
BIOCGHDRCMPLT = 0x40044274
BIOCSHDRCMPLT = 0x80044275
BIOCGSEESENT = 0x40044276
BIOCSSEESENT = 0x80044277
BIOCSDLT = 0x80044278
BIOCGDLTLIST = 0xc00c4279
BIOCSETFNR = 0x8010427e


class BPFHeader (Structure):
    _fields_ = [
        ("tv_sec", c_uint32),
        ("tv_usec", c_uint32),
        ("bh_caplen", c_uint32),
        ("bh_datalen", c_uint32),
        ("bh_hdrlen", c_uint16), ]


def bpf_class(code):
    return ((code) & 0x07)
BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07


# ld/ldx fields
def bpf_size(code):
    return ((code) & 0x18)
BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10


def bpf_mode(code):
    return ((code) & 0xe0)
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xa0


# alu/jmp fields
def bpf_op(code):
    return ((code) & 0xf0)
BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40


def bpf_src(code):
    return ((code) & 0x08)
BPF_K = 0x00
BPF_X = 0x08


# ret - BPF_K and BPF_X also apply
def bpf_rval(code):
    return ((code) & 0x18)
BPF_A = 0x10


# misc
def bpf_miscop(code):
    return ((code) & 0xf8)
BPF_TAX = 0x00
BPF_TXA = 0x80


class BPFInsn (Structure):
    _fields_ = [
        ("code", c_uint16),
        ("jt", c_uint8),
        ("jf", c_uint8),
        ("k", c_uint32), ]


def bpf_stmt(code, k):
    return struct.pack("HBBI", code, 0, 0, k)


def bpf_jump(code, k, jt, jf):
    return struct.pack("HBBI", code, jt, jf, k)


class BPFProgram (Structure):
    _fields_ = [
        ("bf_len", c_uint),
        ("bf_insns", c_void_p), ]

iso_filter = (  # pylint: disable=C0103
    # 0: Load 2 bytes from offset 12
    bpf_stmt(BPF_LD | BPF_H | BPF_ABS, 12) +
    # 1: Jump fwd + 1 if 0x8870 (jumboframe) otherwise fwd + 0 (continue)
    bpf_jump(BPF_JMP | BPF_JEQ, 0x8870, 1, 0) +
    # 2: Jump fwd + 3 if > 1500 (drop) otherwise fwd + 0 (continue)
    bpf_jump(BPF_JMP | BPF_JGT, 1500, 3, 0) +
    # 3: Load 2 bytes from offset 14
    bpf_stmt(BPF_LD | BPF_H | BPF_ABS, 14) +
    # 4: Jump fwd + 0 if 0xfefe (keep) otherwise fwd + 1 (drop)
    bpf_jump(BPF_JMP | BPF_JEQ, 0xfefe, 0, 1) +
    # 5: Keep
    bpf_stmt(BPF_RET, 0xffff) +
    # 6: Drop
    bpf_stmt(BPF_RET, 0)
)


class BPFInterface (object):

    def __init__ (self, ifname):
        self.name = ifname
        # Open an available BPF device
        for i in xrange3(0, 100):
            try:
                self.fd = os.open("/dev/bpf{}".format(i),
                                  os.O_RDWR | os.O_NONBLOCK | os.O_NDELAY)
                assert self.fd != -1
                self.bpf = os.fdopen(self.fd, "r+b", 0)
                # self.bpf = open("/dev/bpf{}".format(i), "r+b", buffering=False)
                break
            except OSError as error:
                if error.errno == errno.EBUSY:
                    pass
        else:
            raise IOError(errno.ENOENT, "No bpf device available")

        # Bind to our interface
        rval = ioctl(self.bpf, BIOCSETIF, struct.pack("16s", ifname))
        assert rval is not None

        # Set immediate return
        rval = ioctl(self.bpf, BIOCIMMEDIATE, struct.pack("I", 1))
        assert rval is not None

        # Get the BPF buffer length
        rval = ioctl(self.bpf, BIOCGBLEN, rval)
        assert rval is not None
        self.buflen = struct.unpack("I", rval)[0]

    def set_filter (self, insns):
        bf_len = len(insns) // sizeof(BPFInsn)
        bf_insns = cast(insns, c_void_p)
        program = BPFProgram(bf_len, bf_insns)
        rval = ioctl(self.bpf, BIOCSETF, struct.pack("IP", program.bf_len, program.bf_insns))
        assert rval is not None

    def recv_pkt (self):
        pkt = self.bpf.read(self.buflen)
        if pkt is None:
            return None

        header = cast(pkt, POINTER(BPFHeader)).contents
        hdrlen = header.bh_hdrlen
        caplen = header.bh_caplen
        if caplen < header.bh_datalen:
            logger.warning("Captured less than full frame")

        # Pkt points to actual packet data.
        return pkt[hdrlen:caplen + hdrlen]

    def fileno (self):
        return self.bpf.fileno()

    def write (self, pkt):
        return self.bpf.writev([pkt])

    def writev (self, buffers):
        return writev(self.bpf, buffers)

    def get_if_addrs (self):
        ifname = self.name
        # codes are different for mac and linux
        output = subprocess.check_output("/sbin/ifconfig {}".format(ifname),
                                         shell=True,
                                         universal_newlines=True)
        match = re.search(r"ether ([a-zA-Z0-9:]+)", output)
        assert match
        mac_addr = clns.mac_encode(match.group(1))

        match = re.search(r"inet ([0-9\.]+) netmask 0x([a-fA-F0-9]+) ", output)
        mask = ipaddress.ip_address(struct.pack('>I', int(match.group(2), 16)))
        ipv4_prefix = ipaddress.ip_interface('{}/{}'.format(match.group(1), mask))

        return mac_addr, ipv4_prefix


__author__ = 'Christian Hopps'
__date__ = 'October 30 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
