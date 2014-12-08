#
# November 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
from ctypes import BigEndianStructure, addressof, memmove, c_uint8, CDLL
import pdb
import pytest
import pyisis.clns as clns
import sys

# libc = CDLL(u"libc.so.6")
# libc.printf("Hello World")
# libc.printf("\n")
# print(libc.strlen("Hello World\n"))
# libc.printf(b"Hello World\n")
# print(libc.strlen(b"Hello World\n"))
# libc.printf("\n")

if sys.version_info >= (3, 0):
    PY3 = True
else:
    PY3 = False

#============================================================================
# NOTE: This module is counting on unicode_literals to be enabled python 2.7
#============================================================================

class NetObject (BigEndianStructure):
    _pack_ = 1
    _fields_ = [("arr1", c_uint8 * 2),
                ("arr2", c_uint8 * 2)]

# These are the things we wish to do:
# Initialize
#       - ctype object from binary string
# Read
#       - ctype array into a binary string
#       - ctype object into a binary string
# Read Element
#       - read value from ctype array.
# Write
#       - binary string into a ctype array.
# Write Element
#       - write value into ctype array.
# Slice
# Compare
#       - ctype array with binary string
#

#--------------
# Initializing
#--------------

#------
# Read
#------


def test_read_ctype_array ():
    # Setup object
    obj = NetObject()
    bstr = b"\x6f\x6b"
    memmove(addressof(obj.arr1), bstr, len(bstr))
    if PY3:
        assert(bytearray(obj.arr1) == bytearray("ok".encode('ascii')))
    else:
        assert(bytearray(obj.arr1) == bytearray("ok".encode('ascii')))

    # bytearray works on both, but it's a writeable array.
    assert(bytearray(memoryview(obj.arr1)) == u"ok".encode('ascii'))
    if PY3:
        assert(bytes(obj.arr1) == u"ok".encode('ascii'))
        assert(bytes(memoryview(obj.arr1)) == u"ok".encode('ascii'))
    else:
        assert(str(buffer(obj.arr1)) == u"ok".encode('ascii'))
        assert(not (str(memoryview(obj.arr1)) == u"ok".encode('ascii')))
        assert(not (bytes(obj.arr1) == u"ok".encode('ascii')))

#-------
# Write
#-------


def test_write_ctype_array ():
    # obj = NetObject(b"\x6f\x6b",
    #                 b"\x01\x02")
    obj = NetObject()
    bstr = b"\x6f\x6b"
    memmove(addressof(obj.arr1), bstr, len(bstr))
    if PY3:
        assert(bytearray(obj.arr1) == bytearray("ok".encode('ascii')))
    else:
        assert(bytearray(obj.arr1) == bytearray("ok".encode('ascii')))

    sstr = u"\x6f\x6b".encode('ascii')
    memmove(addressof(obj.arr2), sstr, len(sstr))
    if PY3:
        assert(bytearray(obj.arr2) == bytearray("ok".encode('ascii')))
    else:
        assert(bytearray(obj.arr2) == bytearray("ok".encode('ascii')))

    sstr = "\x6f\x6b"
    memmove(addressof(obj.arr2), sstr, len(sstr))
    if PY3:
        assert(bytearray(obj.arr2) == bytearray("o\x00".encode('ascii')))
    else:
        assert(bytearray(obj.arr2) == bytearray("o\x00".encode('ascii')))


__author__ = 'Christian Hopps'
__date__ = 'November 2 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
