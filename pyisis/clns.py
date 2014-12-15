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
#
# from __future__ import absolute_import, division, print_function, nested_scopes
from __future__ import absolute_import, division, nested_scopes, print_function, unicode_literals
from pyisis.lib.util import chr3, tlvrdb
import logbook
import struct
import sys

logger = logbook.Logger(__name__)


def mac_encode (desc):
    """
    Encode a mac string of the format HH:HH:HH:HH:HH:HH into a string of bytes.

    Will raise ValueError if format of desc is wrong.

    >>> mac_encode("01:02:03:fa:eb:dc") == b'\\x01\\x02\\x03\\xfa\\xeb\\xdc'
    True
    """
    elts = desc.split(":")
    if len(elts) != 6:
        raise ValueError("{} not in form HH:HH:HH:HH:HH:HH".format(desc))
    # XXX python3 we can use bytes()
    if sys.version_info >= (3, 0):
        return bytes([ int(x, 16) for x in elts ])
    else:
        # return bytearray([ int(x, 16) for x in elts ])
        return b"".join([ chr(int(x, 16)) for x in elts ])


def mac_decode (data):
    """
    Decode a 6 bytes into a string of the format HH:HH:HH:HH:HH:HH.

    Will raise ValueError if data is not 6 bytes

    >>> mac_decode(b"\\x01\\x02\\x03\\xfa\\xeb\\xdc") == '01:02:03:fa:eb:dc'
    True
    """
    if len(data) != 6:
        raise ValueError("SNPA data not 6 bytes ({})".format(len(data)))

    return ":".join(["%02x" % tlvrdb(x) for x in data])


def iso_encode (desc):
    """
    Encode an ISO string of the format ``[HH.]HHHH...HHHH[.HH]'' into a string of bytes.
    Brackets represent optional presence and bytes are returned in network order.

    Will raise ValueError if format of desc is wrong.

    >>> iso_encode("0102.03fa.ebdc.fa") == b'\\x01\\x02\\x03\\xfa\\xeb\\xdc\\xfa'
    True
    >>> iso_encode("af.0102.03fa.ebdc") == b'\\xaf\\x01\\x02\\x03\\xfa\\xeb\\xdc'
    True
    >>> iso_encode("0102.03fa.ebdc") == b'\\x01\\x02\\x03\\xfa\\xeb\\xdc'
    True
    """
    elts = desc.split(".")
    if not elts:
        raise ValueError("{} not in form HH or [HH.]HHHH...HHHH[.HH]".format(desc))

    if sys.version_info >= (3, 0):
        # Validate lengths of input segments and convert to integers.
        data = b""
        last = len(elts) - 1
        for i, elt in enumerate(elts):
            elen = len(elt)
            if elen == 2 and (i == 0 or i == last):
                data += chr3(int(elt, 16))
            elif elen != 4:
                raise ValueError("{} not in form HH or [HH.]HHHH...HHHH[.HH]".format(desc))
            else:
                data += bytes([int(elt[:2], 16), int(elt[2:], 16)])
    else:
        # Validate lengths of input segments and convert to integers.
        data = b""
        last = len(elts) - 1
        for i, elt in enumerate(elts):
            elen = len(elt)
            if elen == 2 and (i == 0 or i == last):
                data += chr(int(elt, 16))
            elif elen != 4:
                raise ValueError("{} not in form HH or [HH.]HHHH...HHHH[.HH]".format(desc))
            else:
                data += chr(int(elt[:2], 16)) + chr(int(elt[2:], 16))

    return data


def iso_decode (data, extratail=True):
    """
    Decode 6 bytes into a string of the format ``[HH.]HHHH.HHHH.HHHH[.HH]''.
    Brackets represent optional presence and bytes are in network order.
    If extratail is True then the odd byte is placed at end, otherwise it is
    placed at the head.

    >>> iso_decode(b"\\x01\\x02\\x03\\xFA\\xEB\\xDC\\xFA", True) == '0102.03fa.ebdc.fa'
    True
    >>> iso_decode(b"\\xAF\\x01\\x02\\x03\\xFA\\xEB\\xDC", False) == 'af.0102.03fa.ebdc'
    True
    >>> iso_decode(b"\\x01\\x02\\x03\\xFA\\xEB\\xDC") == '0102.03fa.ebdc'
    True
    """
    dlen = len(data)
    exb = (dlen % 2) == 1
    wlen = dlen // 2
    if not exb:
        fmt = "{:04x}." * wlen
        fmt = fmt[:-1]
        pfmt = "H" * wlen
    elif extratail:
        fmt = "{:04x}." * wlen + "{:02x}"
        pfmt = "H" * wlen + "B"
    else:
        fmt = "{:02x}" + ".{:04x}" * wlen
        pfmt = "B" + "H" * wlen
    return fmt.format(*struct.unpack(">" + pfmt, data))


def snpa_encode (desc):
    """
    Encode a SNPA string of the format HHHH.HHHH.HHHH into a string of bytes.
    Bytes are returned in network order.

    Will raise ValueError if format of desc is wrong.

    >>> snpa_encode("0102.03fa.ebdc") == b'\\x01\\x02\\x03\\xfa\\xeb\\xdc'
    True
    """
    data = iso_encode(desc)
    if len(data) != 6:
        raise ValueError("{} not in form HHHH.HHHH.HHHH".format(desc))
    return data


def snpa_decode (data):
    """
    Decode 6 bytes into a string of the format HHHH.HHHH.HHHH.
    Bytes are in network order.

    Will raise ValueError if data is not 6 bytes
    >>> snpa_decode(b"\\x01\\x02\\x03\\x04\\x06\\x07") == '0102.0304.0607'
    True
    """
    if len(data) != 6:
        raise ValueError("SNPA data not 6 bytes")
    return "{:04x}.{:04x}.{:04x}".format(*struct.unpack(">HHH", data))


def inc_lspid (lspid):
    """Increment an LSPID

    >>> inc_lspid(b"\\x00" * 8) == b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01'
    True
    >>> inc_lspid(b"\\x00" * 4 + b"\\xff" * 4) == b'\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00'
    True
    >>> inc_lspid(b"\\xff" * 8) == b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
    True
    """
    value = struct.unpack(">Q", lspid)[0]
    if value == 0xFFFFFFFFFFFFFFFF:
        value = 0
    else:
        value += 1
    return struct.pack(">Q", value)


ALL_L1_IS = mac_encode("01:80:C2:00:00:14")
ALL_L2_IS = mac_encode("01:80:C2:00:00:15")
ALL_LX_IS = [ ALL_L1_IS, ALL_L2_IS ]
ALL_ES = mac_encode("09:00:2B:00:00:04")
ALL_IS = mac_encode("09:00:2B:00:00:05")

CLNS_HDR_IDRP = 0
CLNS_HDR_LEN = 1
CLNS_HDR_VERSION = 2
CLNS_HDR_SYSID_LEN = 3
CLNS_HDR_PDUTYPE = 4
CLNS_HDR_VERSION2 = 5
CLNS_HDR_RESERVED = 6
CLNS_HDR_MAX_AREA = 7

CLNS_IDRP_ISIS = 0x83
CLNS_VERSION = 1
CLNS_VERSION2 = 1
CLNS_SNPA_LEN = 6
CLNS_SYSID_LEN = 6
CLNS_LANID_LEN = 7
CLNS_NODEID_LEN = 7
CLNS_LSPID_LEN = 8
CLNS_LSP_PNID_OFF = 6
CLNS_LSP_SEGMENT_OFF = 7

NLPID_IPV4 = 0xCC

PDU_TYPE_IIH_LAN_L1 = 15
PDU_TYPE_IIH_LAN_L2 = 16
PDU_TYPE_IIH_LAN_LX = [ PDU_TYPE_IIH_LAN_L1, PDU_TYPE_IIH_LAN_L2 ]
PDU_TYPE_IIH_P2P = 17
PDU_TYPE_LSP_L1 = 18
PDU_TYPE_LSP_L2 = 20
PDU_TYPE_LSP_LX = [ PDU_TYPE_LSP_L1, PDU_TYPE_LSP_L2 ]
PDU_TYPE_CSNP_L1 = 24
PDU_TYPE_CSNP_L2 = 25
PDU_TYPE_CSNP_LX = [ PDU_TYPE_CSNP_L1, PDU_TYPE_CSNP_L2 ]
PDU_TYPE_PSNP_L1 = 26
PDU_TYPE_PSNP_L2 = 27
PDU_TYPE_PSNP_LX = [ PDU_TYPE_PSNP_L1, PDU_TYPE_PSNP_L2 ]

LINDEX_L1 = 0
LINDEX_L2 = 1

CTYPE_L1 = 1
CTYPE_L2 = 2
CTYPE_L12 = 3

CLNS_MAX_AGE = 1200


def dataLinkBlocksize(unused):
    """ISO10589:2002 MTU of interface"""
    pass


def receiveLSPBufferSize ():
    """ISO10589:2002"""
    return 1492


def originatingLxLSPBufferSize (unused_lindex):
    """ISO10589:2002"""
    return receiveLSPBufferSize()


def get_pdu_class (pkt):
    etype = struct.unpack("!H", pkt[12:14])[0]
    if etype > 1500 and etype != 0x8870:
        return None
    if pkt[14:16] != "\xfe\xfe" or (pkt[16] != "\x00" and pkt[16] != "\x03"):
        return None
    pkt = pkt[17:]
    if tlvrdb(pkt[CLNS_HDR_IDRP]) != CLNS_IDRP_ISIS:
        return None
    if ((tlvrdb(pkt[CLNS_HDR_VERSION]) != CLNS_VERSION or
         tlvrdb(pkt[CLNS_HDR_VERSION2]) != CLNS_VERSION2 or
         tlvrdb(pkt[CLNS_HDR_SYSID_LEN]) not in (0, 6))):

        # XXX this represents malformed packet at this point.
        # and exception may be better here.
        return None

    pdutype = tlvrdb(pkt[CLNS_HDR_PDUTYPE]) & 0x1f
    logger.info("Got PDU type {}", pdutype)
    # XXX needs to be an actual class
    return pdutype

__author__ = 'Christian Hopps'
__date__ = 'October 28 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
