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
from pyisis.bstr import bchr, memspan                       # pylint: disable=E0611
from pyisis.lib.util import tlvwrb, xrange3
import pyisis.tlv as tlv


def test_tlv_append ():
    """
    >>> buf = bytearray(10)
    >>> bufdata = bytearray(b'\\xff\\xff\\xff')
    >>> tlvview = memoryview(buf)
    >>> tlvdata = tlvview[2:]
    >>> tlvview[0] = tlvwrb(3)
    >>> tlvview, tlvdata = tlv.tlv_append_value(tlvview, tlvdata, bufdata)
    >>> tlvdata.tobytes() == b'\\x00\\x00\\x00\\x00\\x00'
    True
    >>> bufdata = bytearray(b'\\xfe\\xfe\\xfe')
    >>> tlvview, tlvdata = tlv.tlv_append_value(tlvview, tlvdata, bufdata)
    >>> len(tlvdata)
    2
    >>> tlvview.tobytes() == b'\\x03\\x00\\xff\\xff\\xff\\xfe\\xfe\\xfe\\x00\\x00'
    True
    >>> tlv.tlv_append_value(tlvview, tlvdata, bufdata)
    (None, None)
    >>> ntlvview, tlvdata = tlv.tlv_append_close(tlvview, tlvdata)
    >>> tlvview.tobytes() == b'\\x03\\x06\\xff\\xff\\xff\\xfe\\xfe\\xfe\\x00\\x00'
    True
    >>> ntlvview.tobytes() == b'\\x00\\x00'
    True
    >>> tlvdata.tobytes() == b''
    True
    """


def test_tlv_insert_entries ():
    testval = b"\x01\x02\x03\x04\x05\x06\x07\x08"

    def get_value_iter (count):
        def value_iter ():
            for unused in xrange3(0, count):
                yield testval
        return value_iter

    def new_buf_func (tlvview, args):
        buflist = args[0]
        sz = args[1]
        buf = memoryview(bytearray(b"\xAF" * sz))
        buflist.append(buf)
        return buf, args

    # Test insertion of 2 TLVs with no space leftover
    code = 2
    bufsize = len(testval) * 2 + 2
    buflist = []
    buf = new_buf_func(None, (buflist, bufsize))[0]
    tlvbuf, args = tlv.tlv_insert_entries(code,
                                          buf,
                                          get_value_iter(2),
                                          new_buf_func,
                                          (buflist, bufsize))
    assert len(args[0]) == 1
    assert args[0][0] == buf
    assert buf == bchr(code) + bchr(16) + testval * 2
    assert memspan(buf, tlvbuf) == bufsize
    assert len(tlvbuf) == 0

    # Test insertion of 2 TLVS with 1 byte leftover
    bufsize = len(testval) * 2 + 3
    buflist = []
    buf = new_buf_func(None, (buflist, bufsize))[0]
    tlvbuf, args = tlv.tlv_insert_entries(code,
                                          buf,
                                          get_value_iter(2),
                                          new_buf_func,
                                          (buflist, bufsize))
    assert len(args[0]) == 1
    assert args[0][0] == buf
    assert buf == bchr(code) + bchr(16) + testval * 2 + b"\xAF"
    assert memspan(buf, tlvbuf) == bufsize - 1
    assert len(tlvbuf) == 1

    # Test insertion of 2 TLVS using new_buf_func
    bufsize = len(testval) * 2 + 3
    buflist = []
    tlvbuf, args = tlv.tlv_insert_entries(code,
                                          None,
                                          get_value_iter(2),
                                          new_buf_func,
                                          (buflist, bufsize))
    assert len(args[0]) == 1
    buf = args[0][0]
    assert buf == bchr(code) + bchr(16) + testval * 2 + b"\xAF"
    assert memspan(buf, tlvbuf) == bufsize - 1
    assert len(tlvbuf) == 1

    # Test insertion of 3 TLVS using new_buf_func
    bufsize = len(testval) * 2 + 3
    buflist = []
    tlvbuf, args = tlv.tlv_insert_entries(code,
                                          None,
                                          get_value_iter(3),
                                          new_buf_func,
                                          (buflist, bufsize))
    assert len(args[0]) == 2
    buf = args[0][0]
    assert buf == bchr(code) + bchr(len(testval) * 2) + testval * 2 + b"\xAF"

    buf = args[0][1]
    assert len(tlvbuf) == 1 + len(testval)
    assert buf == bchr(code) + bchr(len(testval)) + testval + b"\xAF" * (len(testval) + 1)

    # XXX test case where tlvbuf is len == 1 or len == 0

__author__ = 'Christian Hopps'
__date__ = 'November 2 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
