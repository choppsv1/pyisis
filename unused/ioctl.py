#
# October 30 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.

IOCPARM_MASK = 0x1fff
IOC_VOID = 0x20000000
IOC_IN = 0x80000000
IOC_OUT = 0x40000000


def _IOC(inout, group, num, length):
    return (inout | ((length & IOCPARM_MASK) << 16) | (ord(group) << 8) | (num))


def _IO(g, n):
    return _IOC(IOC_VOID, g, n, 0)


def _IOR(g, n, t):
    return _IOC(IOC_OUT, g, n, t)


def _IOW(g, n, t):
    return _IOC(IOC_IN, g, n, t)


def _IOWR(g, n, t):
    return _IOC(IOC_IN | IOC_OUT, g, n, t)

__author__ = 'Christian Hopps'
__date__ = 'October 30 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
