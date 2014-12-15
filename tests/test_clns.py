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

from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
import pytest
import pyisis.clns as clns


def test_iso_decode ():
    # There is no way to do this right now.
    assert(not clns.iso_decode(b"\xaf\x01\x02\x03\xfa\xeb\xdc\xfa") ==
           "af.0102.03fa.ebdc.fa")

    assert(clns.iso_decode(b"\x01\x02\x03\xfa\xeb\xdc\xfa", True) ==
           "0102.03fa.ebdc.fa")

    assert(clns.iso_decode(b"\xaf\x01\x02\x03\xfa\xeb\xdc", False) ==
           "af.0102.03fa.ebdc")

    assert(clns.iso_decode(b"\x01\x02\x03\xfa\xeb\xdc") ==
           "0102.03fa.ebdc")

    assert(clns.iso_decode(b"\x01") ==
           "01")

    assert(clns.iso_decode(b"\x01") ==
           "01")


def test_iso_encode ():
    assert(clns.iso_encode("af.0102.03fa.ebdc.fa") ==
           b"\xaf\x01\x02\x03\xfa\xeb\xdc\xfa")

    assert(clns.iso_encode("0102.03fa.ebdc.fa") ==
           b"\x01\x02\x03\xfa\xeb\xdc\xfa")

    assert(clns.iso_encode("af.0102.03fa.ebdc") ==
           b"\xaf\x01\x02\x03\xfa\xeb\xdc")

    assert(clns.iso_encode("0102.03fa.ebdc") ==
           b"\x01\x02\x03\xfa\xeb\xdc")

    assert(clns.iso_encode("01") ==
           b"\x01")

    assert(clns.iso_encode("01") ==
           b"\x01")

    with pytest.raises(ValueError):  # pylint: disable=E1101
        clns.iso_encode("2")
        clns.iso_encode("002")
        clns.iso_encode("0g")
        clns.iso_encode("01.02.03")
        clns.iso_encode("01.213.03")
        clns.iso_encode("0102.0203")
        clns.iso_encode("0102.0203")


def test_snpa_decode ():
    assert(clns.snpa_decode(b"\x01\x02\x03\xfa\xeb\xdc") ==
           "0102.03fa.ebdc")

    with pytest.raises(ValueError):  # pylint: disable=E1101
        clns.snpa_decode(b"\x01\x02\x03\xfa\xeb")
        clns.snpa_decode(b"\x01\x02\x03\xfa\xeb\xdc\xfa")


def test_snpa_encode ():
    assert(clns.snpa_encode("0102.03fa.ebdc") ==
           b"\x01\x02\x03\xfa\xeb\xdc")

    # Not sure if we want this to work or not but currently it will do to the
    # fact that we use iso_encode underneath.
    assert(clns.snpa_encode("01.0203.faeb.dc") ==
           b"\x01\x02\x03\xfa\xeb\xdc")

    with pytest.raises(ValueError):  # pylint: disable=E1101
        clns.snpa_encode("2")
        clns.snpa_encode("002")
        clns.snpa_encode("0g")
        clns.snpa_encode("01.02.03")
        clns.snpa_encode("01.213.03")
        clns.snpa_encode("01.0203.04")
        clns.snpa_encode("0102.0203")
        clns.snpa_encode("0102.0203.dead.ef")


def test_mac_decode ():
    assert(clns.mac_decode(b"\x01\x02\x03\xfa\xeb\xdc") ==
           "01:02:03:fa:eb:dc")

    with pytest.raises(ValueError):  # pylint: disable=E1101
        clns.mac_decode(b"\x01\x02\x03\xfa\xeb")
        clns.mac_decode(b"\x01\x02\x03\xfa\xeb\xdc\xfa")


def test_mac_encode ():
    assert(clns.mac_encode("01:02:03:fa:eb:dc") ==
           b"\x01\x02\x03\xfa\xeb\xdc")

    with pytest.raises(ValueError):  # pylint: disable=E1101
        clns.mac_encode("2")
        clns.mac_encode("002")
        clns.mac_encode("0g")
        clns.mac_encode("01:02:03")
        clns.mac_encode("01:213:03")
        clns.mac_encode("01:0203:04")
        clns.mac_encode("0102:0203")
        clns.mac_encode("01:02:02:03:de:ad:ef")
        clns.mac_encode("fa:01:02:02:03:de:ad:ef")


__author__ = "Christian Hopps"
__date__ = "November 4 2014"
__version__ = "1.0"
__docformat__ = "restructuredtext en"
