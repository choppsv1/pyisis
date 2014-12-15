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
from ctypes import BigEndianStructure, create_string_buffer
from ctypes import c_uint8, c_uint16, c_uint32, sizeof
from pyisis.lib.util import cast_as, tlvrdb
import pyisis.clns as clns
import sys

VERYVERBOSE = False


class EtherHeader (BigEndianStructure):
    _pack_ = 1
    _fields_ = [ ("ether_dst", c_uint8 * 6),
                 ("ether_src", c_uint8 * 6),
                 ("ether_type", c_uint16), ]

    def __str__ (self):
        return "Ether(dst={},src={},typelen={})".format(clns.iso_decode(self.ether_dst),
                                                        clns.iso_decode(self.ether_src),
                                                        self.ether_type)


class LLCHeader (BigEndianStructure):
    _pack_ = 1
    _fields_ = [ ("llc_dsap", c_uint8),
                 ("llc_ssap", c_uint8),
                 ("llc_control", c_uint8) ]

    def __str__ (self):
        return "LLC(dsap={:#02x},ssap={:#02x},ctrl={:#02x})".format(self.llc_dsap,
                                                                    self.llc_ssap,
                                                                    self.llc_control)


class LLCFrame (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("mac_header", "llc_header")
    _fields_ = [ ("mac_header", EtherHeader),
                 ("llc_header", LLCHeader), ]


class CLNSHeader (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("clns_idrp", c_uint8),
        ("clns_len", c_uint8),
        ("clns_version", c_uint8),
        ("clns_sysid_len", c_uint8),
        ("clns_reserved1", c_uint8, 3),
        ("clns_pdu_type", c_uint8, 5),
        ("clns_version2", c_uint8),
        ("clns_reserved2", c_uint8),
        ("clns_max_area", c_uint8), ]

    def __str__ (self):
        fmtstr = ("CLNS(idrp={:#02x},len={},v={},idlen={}," +
                  "rsv1={},pdutype={},v2={},rsv2={},maxarea={})")
        return fmtstr.format(self.clns_idrp,
                             self.clns_len,
                             self.clns_version,
                             self.clns_sysid_len,
                             self.clns_reserved1,
                             self.clns_pdu_type,
                             self.clns_version2,
                             self.clns_reserved2,
                             self.clns_max_area)


class CLNSEtherFrame (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("mac_header", "llc_header", "clns_header")
    _fields_ = [
        ("mac_header", EtherHeader),
        ("llc_header", LLCHeader),
        ("clns_header", CLNSHeader), ]


class IIHLANHeader (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("circuit_type", c_uint8),
        ("source_id", c_uint8 * clns.CLNS_SYSID_LEN),
        ("hold_time", c_uint16),
        ("pdu_len", c_uint16),
        ("reserved", c_uint8, 1),
        ("priority", c_uint8, 7),
        ("lan_id", c_uint8 * clns.CLNS_LANID_LEN), ]

    def __str__ (self):
        fmtstr = "IIHLAN(ctype={},srcid={},holdtime={},len={},rsv={},pri={},lanid={})"
        args = [self.circuit_type,
                clns.iso_decode(self.source_id),
                self.hold_time,
                self.pdu_len,
                self.reserved,
                self.priority,
                clns.iso_decode(self.lan_id)]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class IIHLANPDU (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("clns_header", "iih_header")
    _fields_ = [
        ("clns_header", CLNSHeader),
        ("iih_header", IIHLANHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [self.iih_header]
        if VERYVERBOSE:
            fmtstr += "\n  [{}]"
            args += [self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class IIHLANFrame (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("mac_header", "llc_header", "clns_header", "iih_header")
    _fields_ = [
        ("mac_header", EtherHeader),
        ("llc_header", LLCHeader),
        ("clns_header", CLNSHeader),
        ("iih_header", IIHLANHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [self.iih_header]
        if VERYVERBOSE:
            fmtstr += "\n  [{}\n   {}\n   {}]"
            args += [self.mac_header,
                     self.llc_header,
                     self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class IIHP2PHeader (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("circuit_type", c_uint8),
        ("source_id", c_uint8 * clns.CLNS_SYSID_LEN),
        ("hold_time", c_uint16),
        ("pdu_len", c_uint16),
        ("local_circuit_id", c_uint8), ]

    def __str__ (self):
        fmtstr = "IIHP2P(ctype={:#02x},srcid={},holdtime={},len={},lcircid={})"
        args = [self.circuit_type,
                clns.iso_decode(self.source_id),
                self.hold_time,
                self.pdu_len,
                self.local_circuit_id]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class IIHP2PPDU (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("clns_header", "iih_header")
    _fields_ = [
        ("clns_header", CLNSHeader),
        ("iih_header", IIHP2PHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [self.iih_header]
        if VERYVERBOSE:
            fmtstr += "\n  [{}]"
            args += [self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class IIHP2PFrame (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("llc_header", "clns_header", "iih_header")
    _fields_ = [
        ("llc_header", LLCHeader),
        ("clns_header", CLNSHeader),
        ("iih_header", IIHP2PHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [self.iih_header]
        if VERYVERBOSE:
            fmtstr += "\n  [{}\n   {}]"
            args += [self.llc_header,
                     self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class LSPHeader (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("pdu_len", c_uint16),
        ("lifetime", c_uint16),
        ("lspid", c_uint8 * clns.CLNS_LSPID_LEN),
        ("seqno", c_uint32),
        ("checksum", c_uint16),
        ("p_bit", c_uint8, 1),
        ("att_error", c_uint8, 1),
        ("att_expense", c_uint8, 1),
        ("att_delay", c_uint8, 1),
        ("att_default", c_uint8, 1),
        ("overload", c_uint8, 1),
        ("is_type", c_uint8, 2), ]

    def __str__ (self):
        fmtstr = ("LSP(len={},lifetime={},lspid={},seqno={:#010x},cksum={:#04x}," +
                  "pbit={},atterr={},attexp={},attdel={},attdef={},oload={},istype={})")
        args = [self.pdu_len,
                self.lifetime,
                clns.iso_decode(self.lspid),
                self.seqno,
                self.checksum,
                self.p_bit,
                self.att_error,
                self.att_expense,
                self.att_delay,
                self.att_default,
                self.overload,
                self.is_type]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class LSPZeroSegFrame (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("clns_header", "lsp_header")
    _fields_ = [
        ("clns_header", CLNSHeader),
        ("lsp_header", LSPHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [ self.lsp_header ]
        if VERYVERBOSE:
            fmtstr += "\n  [{}]"
            args += [self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class LSPPDU (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("clns_header", "lsp_header")
    _fields_ = [
        ("clns_header", CLNSHeader),
        ("lsp_header", LSPHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [ self.lsp_header ]
        if VERYVERBOSE:
            fmtstr += "\n  [{}]"
            args += [self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class LSPFrame (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("mac_header", "llc_header", "clns_header", "lsp_header")
    _fields_ = [
        ("mac_header", EtherHeader),
        ("llc_header", LLCHeader),
        ("clns_header", CLNSHeader),
        ("lsp_header", LSPHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [self.lsp_header]
        if VERYVERBOSE:
            fmtstr += "\n  [{}\n   {}\n   {}]"
            args += [self.mac_header,
                     self.llc_header,
                     self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class CSNPHeader (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("pdu_len", c_uint16),
        ("source_id", c_uint8 * clns.CLNS_NODEID_LEN),
        ("start_lspid", c_uint8 * clns.CLNS_LSPID_LEN),
        ("end_lspid", c_uint8 * clns.CLNS_LSPID_LEN), ]

    def __str__ (self):
        fmtstr = "CSNP(len={},srcid={},start={},end={})"
        args = [self.pdu_len,
                clns.iso_decode(self.source_id),
                clns.iso_decode(self.start_lspid),
                clns.iso_decode(self.end_lspid)]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class CSNPPDU (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("clns_header", "csnp_header")
    _fields_ = [
        ("clns_header", CLNSHeader),
        ("csnp_header", CSNPHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [self.csnp_header]
        if VERYVERBOSE:
            fmtstr += "\n  [{}]"
            args += [self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class CSNPFrame (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("mac_header", "llc_header", "clns_header", "csnp_header")
    _fields_ = [
        ("mac_header", EtherHeader),
        ("llc_header", LLCHeader),
        ("clns_header", CLNSHeader),
        ("csnp_header", CSNPHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [self.csnp_header]
        if VERYVERBOSE:
            fmtstr += "\n  [{}\n   {}\n   {}]"
            args += [self.mac_header,
                     self.llc_header,
                     self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class PSNPHeader (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("pdu_len", c_uint16),
        ("source_id", c_uint8 * clns.CLNS_NODEID_LEN), ]

    def __str__ (self):
        fmtstr = "PSNP(len={},srcid={})"
        args = [self.pdu_len,
                clns.iso_decode(self.source_id)]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class PSNPPDU (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("clns_header", "psnp_header")
    _fields_ = [
        ("clns_header", CLNSHeader),
        ("psnp_header", PSNPHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [self.psnp_header]
        if VERYVERBOSE:
            fmtstr += "\n  [{}]"
            args += [self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


class PSNPFrame (BigEndianStructure):
    _pack_ = 1
    _anonymous_ = ("mac_header", "llc_header", "clns_header", "psnp_header")
    _fields_ = [
        ("mac_header", EtherHeader),
        ("llc_header", LLCHeader),
        ("clns_header", CLNSHeader),
        ("psnp_header", PSNPHeader), ]

    def __str__ (self):
        fmtstr = "{}"
        args = [self.psnp_header]
        if VERYVERBOSE:
            fmtstr += "\n  [{}\n   {}\n   {}]"
            args += [self.mac_header,
                     self.llc_header,
                     self.clns_header]
        return fmtstr.format(*args)                         # pylint: disable=W0142


PDU_FRAME_TYPES = {
    clns.PDU_TYPE_IIH_LAN_L1: IIHLANFrame,
    clns.PDU_TYPE_IIH_LAN_L2: IIHLANFrame,
    clns.PDU_TYPE_IIH_P2P: IIHP2PFrame,
    clns.PDU_TYPE_LSP_L1: LSPFrame,
    clns.PDU_TYPE_LSP_L2: LSPFrame,
    clns.PDU_TYPE_CSNP_L1: CSNPFrame,
    clns.PDU_TYPE_CSNP_L2: CSNPFrame,
    clns.PDU_TYPE_PSNP_L1: PSNPFrame,
    clns.PDU_TYPE_PSNP_L2: PSNPFrame,
}

PDU_PDU_TYPES = {
    clns.PDU_TYPE_IIH_LAN_L1: IIHLANPDU,
    clns.PDU_TYPE_IIH_LAN_L2: IIHLANPDU,
    clns.PDU_TYPE_IIH_P2P: IIHP2PPDU,
    clns.PDU_TYPE_LSP_L1: LSPPDU,
    clns.PDU_TYPE_LSP_L2: LSPPDU,
    clns.PDU_TYPE_CSNP_L1: CSNPPDU,
    clns.PDU_TYPE_CSNP_L2: CSNPPDU,
    clns.PDU_TYPE_PSNP_L1: PSNPPDU,
    clns.PDU_TYPE_PSNP_L2: PSNPPDU,
}

PDU_FRAME_TYPE_LEVEL = {
    clns.PDU_TYPE_IIH_LAN_L1: 1,
    clns.PDU_TYPE_IIH_LAN_L2: 2,
    clns.PDU_TYPE_LSP_L1: 1,
    clns.PDU_TYPE_LSP_L2: 2,
    clns.PDU_TYPE_CSNP_L1: 1,
    clns.PDU_TYPE_CSNP_L2: 2,
    clns.PDU_TYPE_PSNP_L1: 1,
    clns.PDU_TYPE_PSNP_L2: 2,
}

PDU_FRAME_TYPE_LINDEX = {
    clns.PDU_TYPE_IIH_LAN_L1: 0,
    clns.PDU_TYPE_IIH_LAN_L2: 1,
    clns.PDU_TYPE_LSP_L1: 0,
    clns.PDU_TYPE_LSP_L2: 1,
    clns.PDU_TYPE_CSNP_L1: 0,
    clns.PDU_TYPE_CSNP_L2: 1,
    clns.PDU_TYPE_PSNP_L1: 0,
    clns.PDU_TYPE_PSNP_L2: 1,
}

OVERHEAD_LEN = sizeof(EtherHeader) + sizeof(LLCHeader)
PDU_HEADER_LEN = {
    clns.PDU_TYPE_IIH_LAN_L1: sizeof(IIHLANFrame) - OVERHEAD_LEN,
    clns.PDU_TYPE_IIH_LAN_L2: sizeof(IIHLANFrame) - OVERHEAD_LEN,
    clns.PDU_TYPE_IIH_P2P: sizeof(IIHP2PFrame) - OVERHEAD_LEN,
    clns.PDU_TYPE_LSP_L1: sizeof(LSPFrame) - OVERHEAD_LEN,
    clns.PDU_TYPE_LSP_L2: sizeof(LSPFrame) - OVERHEAD_LEN,
    clns.PDU_TYPE_CSNP_L1: sizeof(CSNPFrame) - OVERHEAD_LEN,
    clns.PDU_TYPE_CSNP_L2: sizeof(CSNPFrame) - OVERHEAD_LEN,
    clns.PDU_TYPE_PSNP_L1: sizeof(PSNPFrame) - OVERHEAD_LEN,
    clns.PDU_TYPE_PSNP_L2: sizeof(PSNPFrame) - OVERHEAD_LEN,
}


def get_frame_level (pkt):
    if not pkt:
        return 0
    offset = CLNSEtherFrame.clns_pdu_type.offset            # pylint: disable=E1101
    pdu_type = tlvrdb(memoryview(pkt)[offset])
    try:
        return PDU_FRAME_TYPE_LEVEL[pdu_type]
    except KeyError:
        return 0


def get_frame (pkt):
    if not pkt:
        return None
    frame = cast_as(pkt, CLNSEtherFrame)
    pdu_type = frame.clns_pdu_type
    try:
        return cast_as(pkt, PDU_FRAME_TYPES[pdu_type])
    except KeyError:
        return None


def get_raw_lsp_pdu (lindex):
    pdu_type = clns.PDU_TYPE_LSP_LX[lindex]
    lsp, buf, tlvview = get_pdu_buffer(clns.originatingLxLSPBufferSize(lindex), pdu_type)
    tlvview = memoryview(buf)[sizeof(lsp):]             # Get pointer to tlv space
    return lsp, buf, tlvview


def get_pdu_buffer (size, pdu_type):
    """Get a PDU buffer of the given size cast to the correct type"""
    if sys.version_info >= (3, 0):
        buf = bytearray(size)
        hdr = PDU_PDU_TYPES[pdu_type].from_buffer(buf)
    else:
        buf = create_string_buffer(size)
        hdr = cast_as(buf, PDU_PDU_TYPES[pdu_type])

    hdr.clns_idrp = clns.CLNS_IDRP_ISIS
    hdr.clns_len = PDU_HEADER_LEN[pdu_type]
    hdr.clns_version = clns.CLNS_VERSION
    hdr.clns_sysid_len = 6
    hdr.clns_reserved1 = 0
    hdr.clns_pdu_type = pdu_type
    hdr.clns_version2 = clns.CLNS_VERSION2
    hdr.clns_reserved2 = 0
    hdr.clns_max_area = 3

    tlvview = memoryview(buf)[sizeof(hdr):]

    return hdr, buf, tlvview


__author__ = 'Christian Hopps'
__date__ = 'November 7 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
