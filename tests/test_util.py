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


from pyisis.lib.util import tlvrdb, tlvwrb


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
