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

# from ctypes import Structure, c_uint8
from collections import defaultdict
from ctypes import BigEndianStructure
from ctypes import c_uint8, c_uint16, c_uint32, memmove, sizeof
from pyisis.bstr import memspan                             # pylint: disable=E0611
from pyisis.lib.util import buffer3, tlvrdb, tlvwrb, xrange3
import pyisis.lib.util as util
import ipaddress
import logbook
import pdb
import struct
import sys

import pyisis.clns as clns

logger = logbook.Logger(__name__)


#=====================
# TLV Parsing Objects
#=====================


def area_addr_factory (value):
    alen = ord(value[0])

    class _addr_value (BigEndianStructure):
        _pack_ = 1
        _fields_ = [ ("addr_len", c_uint8),
                     ("addr", c_uint8 * alen) ]
    return util.cast_as(value, _addr_value)


class _TLV (object):
    """Type-Length-Value object"""
    def __init__ (self, bufptr):
        blen = len(bufptr)
        if blen < 2:
            raise ValueError("Remaining TLV space {} not at least 2 bytes".format(blen))
        self.len = tlvrdb(bufptr[1])
        if self.len + 2 > blen:
            raise ValueError("Length value {} greater than remaining TLV space {}".format(
                self.len + 2, blen))
        self.type = tlvrdb(bufptr[0])

    def __str__ (self):
        return "{}({}): Len: {}".format(self.__class__.__name__, self.type, self.len)


class _ValuesTLV (_TLV):
    def __init__ (self, bufptr):
        super(_ValuesTLV, self).__init__(bufptr)
        self.values = []

    def _value_string (self):
        return ", ".join([ str(x) for x in self.values ])

    def __str__ (self):
        return "{}({}): Len: {} Values: {}".format(self.__class__.__name__,
                                                   self.type,
                                                   self.len,
                                                   self._value_string())


class TLV (_TLV):
    """Type-Length-Value object"""
    def __init__ (self, bufptr):
        super(TLV, self).__init__(bufptr)

        # Make a copy of the data as it is temporary.
        self.value = bytes(bufptr[2:2 + self.len])

    def _value_string (self):
        return " ".join(["{:02x}".format(tlvrdb(x)) for x in self.value])

    def __str__ (self):
        return "{}({}): Len: {} Value: {}".format(self.__class__.__name__,
                                                  self.type,
                                                  self.len,
                                                  self._value_string())


class _AddrsTLV (TLV):
    @classmethod
    def _coerce_value (cls, value):
        return value

    def __init__ (self, bufptr):
        super(_AddrsTLV, self).__init__(bufptr)

        self.addrs = []
        """List of addrs"""

    def _addr_strings (self):
        return [ clns.iso_decode(x) for x in self.addrs ]

    def __str__ (self):
        addrs = ", ".join(self._addr_strings())
        return "{}({}): Len: {}: Addrs: {}".format(self.__class__.__name__,
                                                   self.type,
                                                   self.len,
                                                   addrs)


class _VariableAddrsTLV (_AddrsTLV):
    def __init__ (self, bufptr):
        super(_VariableAddrsTLV, self).__init__(bufptr)

        value = self.value
        vlen = len(value)
        while vlen:
            alen = tlvrdb(value[0])
            if alen + 1 > vlen:
                raise ValueError(
                    "Length value {} greater than remaining area addr space {}".format(
                        alen + 1, vlen))
            self.addrs.append(self._coerce_value(value[1:alen + 1]))
            value = value[alen + 1:]
            vlen = len(value)


class _FixedAddrsTLV (_AddrsTLV):
    def __init__ (self, bufptr, addrlen):
        super(_FixedAddrsTLV, self).__init__(bufptr)

        value = self.value
        vlen = len(self.value)
        if vlen % addrlen:
            raise ValueError("Length of addr data {} not divisible by {}".format(
                vlen, addrlen))

        for i in xrange3(0, vlen, addrlen):
            self.addrs.append(self._coerce_value(value[i: i + addrlen]))


class _FixedValuesTLV (TLV):
    @classmethod
    def _coerce_value (cls, value):
        return value

    def __init__ (self, bufptr, valuelen, hasvflag=False):
        super(_FixedValuesTLV, self).__init__(bufptr)

        self.values = []
        """List of values"""

        value = self.value
        vlen = len(self.value)

        if not hasvflag:
            start = 0
        else:
            start = 1
            self.virtual = True if value[0] else False

        if (vlen - start) % valuelen:
            raise ValueError("Length of addr data {} not divisible by {}".format(
                vlen, valuelen))

        for i in xrange3(start, vlen, valuelen):
            self.values.append(self._coerce_value(value[i: i + valuelen]))

    def _value_strings (self):
        return [ str(x) for x in self.values ]

    def __str__ (self):
        values = ", ".join(self._value_strings())
        return "{}({}): Len: {}: Values: {}".format(self.__class__.__name__,
                                                    self.type,
                                                    self.len,
                                                    values)


class _VariableValuesTLV (TLV):
    @classmethod
    def _coerce_value (cls, value):
        return value

    def __init__ (self, bufptr, fixedlen, extralenoff):
        super(_VariableValuesTLV, self).__init__(bufptr)

        self.values = []
        self.fixedlen = fixedlen
        self.extraoff = extralenoff
        value = self.value
        vlen = len(value)
        while vlen:
            elen = tlvrdb(value[extralenoff])
            tlen = fixedlen + elen
            if tlen > vlen:
                raise ValueError(
                    "Length value {} greater than remaining area addr space {}".format(
                        tlen, vlen))
            self.values.append(self._coerce_value(value[0:tlen]))
            value = value[tlen:]
            vlen = len(value)

    def _value_strings (self):
        return [ str(x) for x in self.values ]

    def __str__ (self):
        values = ", ".join(self._value_strings())
        return "{}({}): Len: {}: Values: {}".format(self.__class__.__name__,
                                                    self.type,
                                                    self.len,
                                                    values)


class AreaAddrTLV (_VariableAddrsTLV):
    # def __eq__ (self, other):
    #     if other is None:
    #         return False
    pass


class ISNeighborsTLV (_FixedAddrsTLV):
    def __init__ (self, bufptr):
        super(ISNeighborsTLV, self).__init__(bufptr, 6)

    def _addr_strings (self):
        return [ clns.mac_decode(x) for x in self.addrs ]


# XXX what is this?
class ISVNeighborsTLV (_VariableAddrsTLV):
    def _addr_strings (self):
        return [ clns.iso_decode(x) for x in self.addrs ]


class IPV4IntfAddrsTLV (_FixedAddrsTLV):
    @classmethod
    def _coerce_value (cls, value):
        return ipaddress.ip_address(value)

    def __init__ (self, bufptr):
        super(IPV4IntfAddrsTLV, self).__init__(bufptr, 4)

    def _addr_strings (self):
        return [ str(x) for x in self.addrs ]


class IPV6IntfAddrsTLV (_FixedAddrsTLV):
    @classmethod
    def _coerce_value (cls, value):
        return ipaddress.ip_address(value)

    def __init__ (self, bufptr):
        super(IPV6IntfAddrsTLV, self).__init__(bufptr, 16)

    def _addr_strings (self):
        return [ str(x) for x in self.addrs ]


class _Metric (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("s_bit", c_uint8, 1),
        ("r_bit", c_uint8, 1),
        ("metric", c_uint8, 6), ]


class _IPV4PrefixEntry (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("default", _Metric),
        ("delay", _Metric),
        ("expense", _Metric),
        ("error", _Metric),
        ("addr", c_uint32),
        ("mask", c_uint32), ]


def extract_narrow_metrics (entry):
    external = entry.default.r_bit
    metric = entry.default.metric
    if entry.delay.s_bit:
        delay = entry.delay.metric
    else:
        delay = None
    if entry.expense.s_bit:
        expense = entry.expense.metric
    else:
        expense = None
    if entry.error.s_bit:
        error = entry.error.metric
    else:
        error = None
    return external, metric, delay, expense, error


class IPV4PrefixEntry (object):
    def __init__ (self, bufdata):
        blen = len(bufdata)
        if blen != sizeof(_IPV4PrefixEntry):
            pdb.set_trace()
            raise ValueError("IPV4PrefixEntry unexpected length {}".format(blen))
        self.entry = util.cast_as(bufdata, _IPV4PrefixEntry)
        (self.external,
         self.metric,
         self.delay,
         self.expense,
         self.error) = extract_narrow_metrics(self.entry)
        self.addr = ipaddress.ip_address(self.entry.addr)
        self.mask = ipaddress.ip_address(self.entry.mask)

    def __str__ (self):
        ie = "Ext" if self.external else "Int"
        return "Addr: {} Mask: {} {} Metric: {}".format(self.addr,
                                                        self.mask,
                                                        ie,
                                                        self.metric)


class IPV4PrefixesTLV (_FixedValuesTLV):
    @classmethod
    def _coerce_value (cls, value):
        return IPV4PrefixEntry(value)

    def __init__ (self, bufptr):
        super(IPV4PrefixesTLV, self).__init__(bufptr, sizeof(_IPV4PrefixEntry))


class _ExtIPV4Prefix (BigEndianStructure):
    _pack_ = 1
    _fields_ = [ ("metric", c_uint32),
                 ("updown", c_uint8, 1),
                 ("subtlv", c_uint8, 1),
                 ("pfxlen", c_uint8, 6), ]


def pfxlen2bytes (pfxlen):
    return (pfxlen + 7) // 8


class ExtIPV4PrefixEntry (object):
    def __init__ (self, value):
        entry = util.cast_as(value, _ExtIPV4Prefix)
        self.metric = entry.metric
        self.updown = entry.updown
        self.pfxlen = entry.pfxlen
        start = sizeof(_ExtIPV4Prefix)
        blen = pfxlen2bytes(self.pfxlen)
        aval = value[start:start + blen] + b"\x00" * (4 - blen)
        self.addr = ipaddress.ip_address(aval)

        # Sub-TLV processing.

    def __str__ (self):
        return "ExtIPV4PrefixEntry(pfx={},metric={},updown={})".format(
            self.addr, self.metric, self.updown)


class ExtIPV4PrefixesTLV (_ValuesTLV):
    def __init__ (self, bufptr):
        super(ExtIPV4PrefixesTLV, self).__init__(bufptr)
        start = 2
        end = 2 + self.len
        self.value = bufptr[start:end]
        value = self.value
        vlen = len(value)
        while vlen:
            entry = util.cast_as(value, _ExtIPV4Prefix)
            fixedlen = sizeof(_ExtIPV4Prefix) + pfxlen2bytes(entry.pfxlen)
            if not entry.subtlv:
                elen = 0
            else:
                elen = tlvrdb(value[fixedlen]) + 1
            tlen = fixedlen + elen
            if tlen > vlen:
                raise ValueError(
                    "Length value {} greater than remaining area addr space {}".format(
                        tlen, vlen))
            self.values.append(ExtIPV4PrefixEntry(value[0:tlen]))
            value = value[tlen:]
            vlen = len(value)


class _IPV6Prefix (BigEndianStructure):
    _pack_ = 1
    _fields_ = [ ("metric", c_uint32),
                 ("updown", c_uint8, 1),
                 ("external", c_uint8, 1),
                 ("subtlv", c_uint8, 1),
                 ("resv", c_uint8, 5),
                 ("pfxlen", c_uint8), ]


class IPV6PrefixEntry (object):
    def __init__ (self, value):
        entry = util.cast_as(value, _IPV6Prefix)
        self.metric = entry.metric
        self.updown = entry.updown
        self.external = entry.external
        self.pfxlen = entry.pfxlen
        blen = pfxlen2bytes(self.pfxlen)
        start = sizeof(_IPV6Prefix)
        aval = value[start:start + blen] + '\x00' * (16 - blen)
        self.addr = ipaddress.ip_address(aval)

        # Sub-TLV processing.

    def __str__ (self):
        return "IPV6PrefixEntry(pfx={},metric={},updown={},external={})".format(
            self.addr, self.metric, self.updown, self.external)


class IPV6PrefixesTLV (_ValuesTLV):
    def __init__ (self, bufptr):
        super(IPV6PrefixesTLV, self).__init__(bufptr)
        start = 2
        end = 2 + self.len
        self.value = bytes(bufptr[start:end])
        value = self.value
        vlen = len(value)
        while vlen:
            entry = util.cast_as(value, _IPV6Prefix)
            fixedlen = sizeof(_IPV6Prefix) + pfxlen2bytes(entry.pfxlen)
            if not entry.subtlv:
                elen = 0
            else:
                elen = tlvrdb(value[fixedlen]) + 1
            tlen = fixedlen + elen
            if tlen > vlen:
                raise ValueError(
                    "Length value {} greater than remaining area addr space {}".format(
                        tlen, vlen))
            self.values.append(IPV6PrefixEntry(value[0:tlen]))
            value = value[tlen:]
            vlen = len(value)


class _ISReachEntry (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("default", _Metric),
        ("delay", _Metric),
        ("expense", _Metric),
        ("error", _Metric),
        ("neighbor", c_uint8 * clns.CLNS_NODEID_LEN), ]


class ISReachEntry (object):
    def __init__ (self, bufdata):
        blen = len(bufdata)
        if blen != sizeof(_ISReachEntry):
            raise ValueError("ISReachEntry unexpected length {}".format(blen))
        self.entry = util.cast_as(bufdata, _ISReachEntry)
        (self.external,
         self.metric,
         self.delay,
         self.expense,
         self.error) = extract_narrow_metrics(self.entry)
        self.neighbor = bytearray(self.entry.neighbor)

    def __str__ (self):
        ie = "Ext" if self.external else "Int"
        return "IS Reach: {} {} Metric: {}".format(clns.iso_decode(self.neighbor),
                                                   ie,
                                                   self.metric)


class ISReachTLV (_FixedValuesTLV):
    @classmethod
    def _coerce_value (cls, value):
        return ISReachEntry(value)

    def __init__ (self, bufptr):
        super(ISReachTLV, self).__init__(bufptr, sizeof(_ISReachEntry), True)


class _ExtISReachEntry (BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("neighbor", c_uint8 * clns.CLNS_NODEID_LEN),
        ("metric", c_uint8 * 3),
        ("sublen", c_uint8),
    ]
ExtISReachEntryStruct = struct.Struct(">7s3sB")


def get_3byte_metric_str (metric):
    return struct.pack(">I", metric)[1:]


def set_3byte_metric (cobj, metric):
    memmove(cobj, get_3byte_metric_str(metric), 3)


def get_3byte_metric (marray):
    return (tlvrdb(marray[0]) << 24
            + tlvrdb(marray[1]) << 16
            + tlvrdb(marray[2]))


def tlv_append_close_done (tlvview, tlvdata):
    tlvlen = memspan(tlvview, tlvdata) - 2
    tlvview[1] = tlvwrb(tlvlen)
    tlvview = tlvview[2:2 + tlvlen]
    return tlvview


def tlv_append_close (tlvview, tlvdata):
    tlvlen = memspan(tlvview, tlvdata) - 2
    tlvview[1] = tlvwrb(tlvlen)
    tlvview = tlvview[tlvlen + 2:]
    tlvspace = len(tlvview)
    if tlvspace < 2:
        return None, None

    return tlvview, tlvview[2:2 + min(255, tlvspace - 2)]


def tlv_append_value (tlvview, tlvdata, entry):
    """Append a value to a pre-exisintg TLV if space exists"""
    elen = len(entry)
    if elen <= len(tlvdata):
        # See if we can create a new TLV.
        tlvdata[:elen] = entry
        tlvdata = tlvdata[elen:]
        return tlvview, tlvdata

    code = tlvrdb(tlvview[0])
    tlvview, tlvdata = tlv_append_close(tlvview, tlvdata)
    if tlvview and elen <= len(tlvdata):
        tlvview[0] = tlvwrb(code)
        return tlv_append_value(tlvview, tlvdata, entry)

    return None, None


class ExtISReachEntry (object):
    def __init__ (self, bufdata):
        blen = len(bufdata)
        if blen != sizeof(_ISReachEntry):
            raise ValueError("ISReachEntry unexpected length {}".format(blen))
        self.entry = util.cast_as(bufdata, _ExtISReachEntry)
        self.neighbor = bytearray(self.entry.neighbor)
        vmetric = self.entry.metric
        self.metric = (vmetric[0] << 16) + (vmetric[1] << 8) + (vmetric[2])

    def __str__ (self):
        return "IS Extended Reach: {} Metric: {}".format(clns.iso_decode(self.neighbor),
                                                         self.metric)


class ExtISReachTLV (_VariableValuesTLV):
    @classmethod
    def _coerce_value (cls, value):
        return ExtISReachEntry(value)

    def __init__ (self, bufptr):
        super(ExtISReachTLV, self).__init__(bufptr,
                                            sizeof(_ExtISReachEntry),
                                            _ExtISReachEntry.sublen.offset)  # pylint: disable=C0301,E1101


class HostnameTLV (TLV):
    def _value_string (self):
        return self.value

    def __init__ (self, bufptr):
        super(HostnameTLV, self).__init__(bufptr)
        self.hostname = str(self.value)


class _FixedValueTLV (TLV):
    @classmethod
    def _coerce_value (cls, value):
        return value

    def __init__ (self, bufptr, valuelen):
        super(_FixedValueTLV, self).__init__(bufptr)

        if len(self.value) != valuelen:
            raise ValueError("Length of data {} not {}".format(len(self.value), valuelen))
        self.value = self._coerce_value(self.value)

    def __str__ (self):
        return "{}({}): Len: {}: Value: {}".format(self.__class__.__name__,
                                                   self.type,
                                                   self.len,
                                                   str(self.value))


class RouterIDTLV (TLV):
    def _value_string (self):
        return str(self.routerid)

    def __init__ (self, bufptr):
        super(RouterIDTLV, self).__init__(bufptr)
        if len(self.value) != 4:
            raise ValueError("Length of data {} not 4".format(len(self.value)))
        self.routerid = ipaddress.ip_address(struct.unpack(">I", self.value)[0])


class NLPIDTLV (_FixedValuesTLV):
    @classmethod
    def _coerce_value (cls, value):
        return tlvrdb(value)

    def __init__ (self, bufptr):
        super(NLPIDTLV, self).__init__(bufptr, 1)


class PaddingTLV (_TLV):
    pass


class _SNPEntry (BigEndianStructure):
    _pack_ = 1
    _fields_ = [ ("lifetime", c_uint16),
                 ("lspid", c_uint8 * clns.CLNS_LSPID_LEN),
                 ("seqno", c_uint32),
                 ("checksum", c_uint16), ]
SNPEntryStruct = struct.Struct(">H8sIH")


class SNPEntry (object):
    def __init__ (self, bufdata):
        blen = len(bufdata)
        if blen != sizeof(_SNPEntry):
            raise ValueError("SNPEntry unexpected length {}".format(blen))

        entry = util.cast_as(bufdata, _SNPEntry)
        self.lifetime = entry.lifetime
        self.lspid = bytes(buffer3(entry.lspid))
        self.seqno = entry.seqno
        self.checksum = entry.checksum

    def __str__ (self):
        return "ID: {} SEQ: {:#010x} LIFE: {} CKSUM: {:#06x}".format(clns.iso_decode(self.lspid),
                                                                     self.seqno,
                                                                     self.lifetime,
                                                                     self.checksum)


class SNPEntriesTLV (_FixedValuesTLV):
    @classmethod
    def _coerce_value (cls, value):
        return SNPEntry(value)

    def __init__ (self, bufptr):
        super(SNPEntriesTLV, self).__init__(bufptr, sizeof(_SNPEntry))


class LSPBufSizeTLV (_FixedValueTLV):
    @classmethod
    def _coerce_value (cls, value):
        return int(struct.unpack(">H", value)[0])

    def __init__ (self, bufptr):
        super(LSPBufSizeTLV, self).__init__(bufptr, sizeof(c_uint16))

# ISO 10589:2002
TLV_AREA_ADDRS = 1
TLV_IS_REACH = 2
TLV_IS_NEIGHBORS = 6

# XXX Conflict!
TLV_IS_VNEIGHBORS = 7
TLV_INSTANCE_ID = 7

TLV_PADDING = 8
TLV_SNP_ENTRIES = 9
TLV_AUTH = 10
TLV_LSP_BUF_SIZE = 14

# RFC 5305
TLV_EXT_IS_REACH = 22

# RFC 1195
TLV_IPV4_IPREFIX = 128
TLV_NLPID = 129
TLV_IPV4_EPREFIX = 130
TLV_IPV4_INTF_ADDRS = 132
TLV_ROUTER_ID = 134
TLV_EXT_IPV4_PREFIX = 135
TLV_HOSTNAME = 137
TLV_IPV6_INTF_ADDRS = 232
TLV_IPV6_PREFIX = 236


TLV_TYPES = {
    TLV_AREA_ADDRS: AreaAddrTLV,
    TLV_IS_REACH: ISReachTLV,
    TLV_IS_NEIGHBORS: ISNeighborsTLV,
    TLV_IS_VNEIGHBORS: ISVNeighborsTLV,
    TLV_PADDING: PaddingTLV,
    TLV_IPV4_INTF_ADDRS: IPV4IntfAddrsTLV,
    TLV_ROUTER_ID: RouterIDTLV,
    TLV_NLPID: NLPIDTLV,
    TLV_SNP_ENTRIES: SNPEntriesTLV,
    TLV_EXT_IS_REACH: ExtISReachTLV,
    TLV_IPV4_IPREFIX: IPV4PrefixesTLV,
    TLV_IPV4_EPREFIX: IPV4PrefixesTLV,
    TLV_EXT_IPV4_PREFIX: ExtIPV4PrefixesTLV,
    TLV_HOSTNAME: HostnameTLV,
    TLV_IPV6_INTF_ADDRS: IPV6IntfAddrsTLV,
    TLV_IPV6_PREFIX: IPV6PrefixesTLV,
}


if sys.version_info >= (3, 0):
    def tlv_pad (mview, pad):
        mview[0] = TLV_PADDING
        mview[1] = pad
        return mview[2 + pad:]

    def tlv_append (mview, code, value):
        l = len(value)
        try:
            mview[0] = code
        except Exception:
            util.debug_exception()
        mview[1] = l
        try:
            mview[2:2 + l] = value
        except Exception:
            util.debug_exception()
        return mview[2 + l:]

else:
    def tlv_pad (mview, pad):
        mview[0] = tlvwrb(TLV_PADDING)
        mview[1] = tlvwrb(pad)
        return mview[2 + pad:]

    def tlv_append (mview, code, value):
        l = len(value)
        try:
            mview[0] = tlvwrb(code)
        except Exception:
            util.debug_exception()
        mview[1] = tlvwrb(l)
        mview[2:2 + l] = value
        return mview[2 + l:]


def parse_tlvs (extraptr, dbg):
    tlv_start = bytes(extraptr)                             # copy the tlvspace

    tlvs = defaultdict(list)
    v = None
    for v in tlv_object_iterator(tlv_start):
        tlvs[v.type].append(v)
        if dbg:
            logger.info("." * 5 + "{}", v)

    if v and dbg:
        logger.info("." * 5)
    return tlvs


def tlv_iterator (bufptr):
    blen = len(bufptr)
    while True:
        if blen < 2:
            raise ValueError("Remaining TLV space {} not at least 2 bytes".format(blen))

        tlv_type = tlvrdb(bufptr[0])
        tlv_len = tlvrdb(bufptr[1])
        if tlv_len + 2 > blen:
            raise ValueError("Length value {} greater than remaining TLV space {}".format(
                tlv_len + 2, blen))

        yield (tlv_type, tlv_len, bufptr[2:tlv_len])

        bufptr = bufptr[2 + tlv_len:]
        blen = len(bufptr)
        if not blen:
            return


def tlv_object_iterator (bufptr):
    blen = len(bufptr)
    while blen:
        if blen < 2:
            pdb.set_trace()
            raise ValueError("Remaining TLV space {} not at least 2 bytes".format(blen))

        tlv_type = tlvrdb(bufptr[0])
        if tlv_type in TLV_TYPES:
            tlv = TLV_TYPES[tlv_type](bufptr)
        else:
            tlv = TLV(bufptr)

        yield tlv

        bufptr = bufptr[tlv.len + 2:]
        blen = len(bufptr)


#========================
# TLV Generating Methods
#========================
# Rework this to get value length and struct objects that can pack_into to be more efficient maybe.

class NoSpaceErorr (Exception):
    pass


def tlv_close (tlvbuf, tlvdata):
    """Close a TLV, zero length data is accepted"""
    vlen = memspan(tlvbuf, tlvdata) - 2
    assert vlen >= 0
    tlvbuf[1] = tlvwrb(vlen)
    return tlvbuf[2 + vlen:]


def tlv_close_entries (tlvbuf, tlvdata):
    """Close a TLV being filled with entries, if len is zero no TLV is inserted"""
    vlen = memspan(tlvbuf, tlvdata) - 2
    if not vlen:
        return tlvbuf
    tlvbuf[1] = tlvwrb(vlen)
    return tlvbuf[2 + vlen:]


def basic_tlv_init (code, tlvbuf):
    tlvbuf[0] = tlvwrb(code)
    return tlvbuf[2:]


def _tlv_insert_init (code, tlvbuf):
    if not tlvbuf or len(tlvbuf) < 2:
        tlvbuf = None
        tlvdata = None
    else:
        tlvdata = basic_tlv_init(code, tlvbuf)
    return tlvbuf, tlvdata


def _tlv_insert_value (code, tlvbuf, tlvdata, value, new_buf_func=None, new_buf_args=None):
    vlen = len(value)
    if tlvdata and len(tlvdata) < vlen:
        tlvbuf = tlv_close_entries(tlvbuf, tlvdata)
        if len(tlvbuf) >= vlen + 2:
            tlvdata = basic_tlv_init(code, tlvbuf)

    if not tlvbuf or len(tlvbuf) < vlen + 2:
        if not new_buf_func:
            raise NoSpaceErorr()
        tlvbuf, new_buf_args = new_buf_func(tlvbuf, new_buf_args)
        if not tlvbuf:
            raise NoSpaceErorr()
        assert type(tlvbuf) == memoryview
        tlvdata = basic_tlv_init(code, tlvbuf)

    # Now insert the value.
    if vlen:
        assert len(tlvdata) >= vlen
        tlvdata[:vlen] = value
        tlvdata = tlvdata[vlen:]

    return tlvbuf, tlvdata, new_buf_args


def tlv_insert_entries (code, tlvbuf, iter_values, new_buf_func=None, new_buf_args=None):
    """Insert the TLV[s] into this TLV buffer.

    The tlvbuf should be pointing at new tlv space or None. The method
    will return a pointer to new tlvbuf space following what
    was inserted, as well as the passed in new_buf_args arg.

    new_buf_func if provided will be used to obtain new buffer space
    for insertinging new TLVs if they didn't fit in the provided tlvbuf
    or if tlvbuf was None. It should return a memoryview to the tlvbuf
    and the (possibly modified) new_buf_args value.
    """

    tlvbuf, tlvdata = _tlv_insert_init(code, tlvbuf)
    assert iter_values

    for value in iter_values():
        tlvbuf, tlvdata, new_buf_args = _tlv_insert_value(code,
                                                          tlvbuf,
                                                          tlvdata,
                                                          value,
                                                          new_buf_func,
                                                          new_buf_args)
    if tlvbuf:
        tlvbuf = tlv_close_entries(tlvbuf, tlvdata)

    return tlvbuf, new_buf_args


def tlv_insert_value (code, tlvbuf, value, new_buf_func=None, new_buf_args=None):
    if value is None:
        value = b""

    tlvbuf, tlvdata = _tlv_insert_init(code, tlvbuf)
    tlvbuf, tlvdata, new_buf_args = _tlv_insert_value(code,
                                                      tlvbuf,
                                                      tlvdata,
                                                      value,
                                                      new_buf_func,
                                                      new_buf_args)
    return tlv_close(tlvbuf, tlvdata), new_buf_args


__author__ = 'Christian Hopps'
__date__ = 'November 5 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
