#
# November 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.

from pyisis.util import tlvrdb, tlvwrb


def test_tlvrdb ():
    b = b'\x01\x02'
    bm = memoryview(b)
    assert tlvrdb(b[0]) == 1
    assert tlvrdb(bm[1]) == 2


def test_tlvwrb ():
    ba = bytearray(2)
    bam = memoryview(ba)
    ba[0] = tlvwrb(3)
    assert ba == b'\x03\x00'
    bam[1] = tlvwrb(4)
    assert ba == b'\x03\x04'

__author__ = 'Christian Hopps'
__date__ = 'November 3 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
