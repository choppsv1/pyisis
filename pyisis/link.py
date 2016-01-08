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
from __future__ import absolute_import, division, print_function, nested_scopes

from ctypes import create_string_buffer, sizeof
from pyisis.bstr import memspan                             # pylint: disable=E0611
from pyisis.lib.util import bchr, memcpy, buffer3, stringify3, tlvwrb
import errno
import logbook
import pyisis.adjacency as adjacency
import pyisis.lib.bpf as bpf
import pyisis.clns as clns
import pyisis.lib.debug as debug
import pyisis.lsp as lsp
import pyisis.pdu as pdu
import pyisis.lib.rawsock as rawsock
import pyisis.lib.timers as timers
import pyisis.tlv as tlv
import pyisis.lib.util as util
import select
import sys
import threading
import traceback

logger = logbook.Logger(__name__)

SRM = 0
SSN = 1


class LinkDB (object):
    """A container for all the enabled links in an instance"""

    def __init__ (self, inst):
        self.inst = inst
        self.links = []
        self.linkfds = set()
        self.wlinkfds = set()
        self.linkbyfd = {}
        self.linkbyidx = {}
        self.timerheap = timers.TimerHeap("LinkDB")
        self.lock = threading.Lock()

    def __enter__ (self):
        return self.lock.__enter__()

    def __exit__ (self, *args):
        return self.lock.__exit__(*args)

    def add_link (self, ifname):
        if ifname.endswith(":p2p"):
            ifname = ifname.replace(":p2p", "")
            p2plan = True
        with self:
            index = len(self.links)
            ctype = (clns.CTYPE_L12 & self.inst.is_type)
            if p2plan:
                link = P2PLanLink(self, ifname, index, ctype)
            else:
                link = LanLink(self, ifname, index, ctype)
            fd = link.getfd()
            self.links.append(link)
            self.linkfds.add(fd)
            self.linkbyidx[index] = link
            self.linkbyfd[fd] = link

    def get_intf_ipv4_iter (self, unused_lindex):
        def intf_ipv4_iter ():
            with self:
                for link in self.links:
                    yield link.ipv4_prefix.ip.packed
        return intf_ipv4_iter

    def get_lsp_nbr_iter (self, lindex):
        def lsp_nbr_iter ():
            with self:
                for link in self.links:
                    iterator = link.get_lsp_nbr_iter(lindex, False)
                    for value in iterator():
                        yield value
        return lsp_nbr_iter

    def get_link_by_circuit_id (self, unused_lindex, circuit_id):
        return self.linkbyidx[circuit_id]

    def get_clns_buffer (self, size, pdu_type):
        """Get a PDU buffer of the given size cast to the correct type"""
        if sys.version_info >= (3, 0):
            buf = bytearray(size)
            hdr = pdu.PDU_PDU_TYPES[pdu_type].from_buffer(buf)
        else:
            buf = create_string_buffer(size)
            hdr = util.cast_as(buf, pdu.PDU_PDU_TYPES[pdu_type])
        hdr.llc_ssap = 0xfe
        hdr.llc_dsap = 0xfe
        hdr.llc_control = 0x03
        hdr.clns_idrp = clns.CLNS_IDRP_ISIS
        hdr.clns_len = pdu.PDU_HEADER_LEN[pdu_type]
        hdr.clns_version = clns.CLNS_VERSION
        hdr.clns_sysid_len = 6
        hdr.clns_reserved1 = 0
        hdr.clns_pdu_type = pdu_type
        hdr.clns_version2 = clns.CLNS_VERSION2
        hdr.clns_reserved2 = 0
        hdr.clns_max_area = 3

        tlvview = memoryview(buf)[sizeof(hdr):]

        return hdr, buf, tlvview

    def link_send_ready (self, link, nolock=False):
        if nolock:
            self.wlinkfds.add(link.getfd())
        else:
            with self:
                self.wlinkfds.add(link.getfd())

    def link_send_unready (self, link, nolock=False):
        fd = link.getfd()
        if nolock:
            if fd in self.wlinkfds:
                self.wlinkfds.remove(fd)
        else:
            with self:
                if fd in self.wlinkfds:
                    self.wlinkfds.remove(fd)

    def set_all_flag (self, flag, lspseg, butnot):
        with self:
            for link in self.links:
                if link != butnot:
                    link.set_flag_impl(flag, lspseg)
                    self.link_send_ready(link, True)

    def clear_all_flag (self, flag, lspseg, butnot):
        with self:
            for link in self.links:
                if link != butnot:
                    link.clear_flag_impl(flag, lspseg)
                    link.check_send_unready(True)

    def set_all_srm (self, lspseg, butnot=None):
        assert lspseg.lsphdr.seqno
        self.set_all_flag(SRM, lspseg, butnot)

    def clear_all_srm (self, lspseg, butnot=None):
        self.clear_all_flag(SRM, lspseg, butnot)

    def set_all_ssn (self, lspseg, butnot=None):
        self.set_all_flag(SSN, lspseg, butnot)

    def clear_all_ssn (self, lspseg, butnot=None):
        self.clear_all_flag(SSN, lspseg, butnot)

    def process_read_sockets (self, rfds):
        # XXX need locking if intf remove
        try:
            for fd in rfds:
                link = self.linkbyfd[fd]
                link.receive_packets()
        except Exception as ex:
            logger.warning("Unexpected exception in receiving packets: {}", ex)
            raise

    def process_write_sockets (self, wfds):
        # XXX need locking if intf remove
        try:
            for fd in wfds:
                link = self.linkbyfd[fd]
                link.send_packets()
        except Exception as ex:
            logger.warning("Unexpected exception in sending packets: {}", ex)
            raise

    def process_packets (self):
        # XXX to avoid the race of link going away, we want to process packets
        # in the same thread that we would remove links in.
        while True:
            with self:
                rfds = list(self.linkfds)
                wfds = list(self.wlinkfds)
            try:
                rfds, wfds, unused = select.select(rfds, wfds, [])
            except select.error as error:
                if error.args[0] != errno.EINTR:
                    raise
            else:
                if rfds:
                    self.process_read_sockets(rfds)
                if wfds:
                    self.process_write_sockets(wfds)


class Link (object):
    """Generic Link object"""

    receive_pdu_method = {}

    def __init__ (self, linkdb, ifname, index, circtype):
        self.linkdb = linkdb                                # Backlink
        self.index = index                                  # Index in linkdb for circuit-id
        self.ifname = ifname
        self.circtype = circtype
        self.last_frame = None

        self.enabled_lindex = []
        """A list of enabled levels by lindex"""

        if circtype & 1:
            self.enabled_lindex.append(0)
        if circtype & 2:
            self.enabled_lindex.append(1)

        #---------------------------------
        # Get raw interface and addresses
        #---------------------------------

        if sys.platform == "darwin":
            self.rawintf = bpf.BPFInterface(ifname)
        else:
            self.rawintf = rawsock.RawInterface(ifname)
            if circtype == clns.CTYPE_L12 or circtype == clns.CTYPE_L1:
                self.rawintf.add_drop_group(True, clns.ALL_L1_IS)
            if circtype == clns.CTYPE_L12 or circtype == clns.CTYPE_L2:
                self.rawintf.add_drop_group(True, clns.ALL_L2_IS)
        self.rawintf.set_filter(bpf.iso_filter)
        self.mac_addr, self.ipv4_prefix = self.rawintf.get_if_addrs()

        #--------------------------------
        # SRM and SSN flags for flooding
        #--------------------------------

        # Flags SRM = 0, SSN = 1
        # Index by lindex, then by flag.
        # Lock by lindex.
        self.flags = [ [ set(), set() ],
                       [ set(), set() ] ]
        self.flag_locks = [ threading.Lock(), threading.Lock() ]

    def is_lindex_enabled (self, lindex):
        # is (lindex in self.enabled_lindex) faster?
        return (self.circtype & (1 << lindex)) != 0

    def is_p2p (self):
        return False

    def getfd (self):
        return self.rawintf

    def fileno (self):
        return self.rawintf.fileno()

    def iih_expire (self, lindex):
        pass

    def get_lindex_metric (self, unused_lindex):
        return 10

    def schedule_send (self, nolock=False):
        # logger.info("Going SEND READY on {}", self)
        self.linkdb.link_send_ready(self, nolock)

    def check_send_unready (self, nolock=False):
        # logger.info("CHECK SEND UNREADY on {}", self)

        # This is a bit ridiculous
        with self.flag_locks[0]:
            with self.flag_locks[1]:
                if ( not self.flags[0][SRM] and not self.flags[0][SSN] and
                     not self.flags[1][SRM] and not self.flags[1][SSN] ):
                    # logger.info("GOING UNREADY on {}", self)
                    self.linkdb.link_send_unready(self, nolock)

    def set_flag_impl (self, flag, lspseg):
        lindex = lspseg.lindex
        with self.flag_locks[lindex]:
            self.flags[lindex][flag].add(lspseg)
        if debug.FLAGDBG:
            fdesc = [ "SRM", "SSN" ]
            logger.info("Set {} on {} for {}", fdesc[flag], self, lspseg)

    def clear_flag_impl (self, flag, lspseg, nolock=False):
        lindex = lspseg.lindex
        if nolock:
            withobj = util.NoLock()
        else:
            withobj = self.flag_locks[lindex]
        with withobj:
            try:
                self.flags[lindex][flag].remove(lspseg)
            except KeyError:
                return
        if debug.FLAGDBG:
            fdesc = [ "SRM", "SSN" ]
            logger.info("Clear {} on {} for {}", fdesc[flag], self, lspseg)

    def set_flag (self, flag, lspseg):
        self.set_flag_impl(flag, lspseg)
        self.schedule_send()

    def clear_flag (self, flag, lspseg):
        self.clear_flag_impl(flag, lspseg)
        self.check_send_unready()

    def set_srm_flag (self, lspseg):
        assert lspseg.lsphdr.seqno
        self.set_flag(SRM, lspseg)

    def clear_srm_flag (self, lspseg):
        self.clear_flag(SRM, lspseg)

    def set_ssn_flag (self, lspseg):
        self.set_flag(SSN, lspseg)

    def clear_ssn_flag (self, lspseg):
        self.clear_flag(SSN, lspseg)

    def check_pdu (self, hdr, unused_pdubuf, unused_tlvs):
        # If this wasn't sent to proper mcast addr drop it.
        dst = stringify3(hdr.ether_dst)
        if dst not in clns.ALL_LX_IS:
            if debug.is_dbg(hdr):
                logger.warning("Dropping dst is not AllLxIS")
                import pdb
                pdb.set_trace()
            return False

        # If this is our PDU drop it.
        src = stringify3(hdr.ether_src)
        if src == self.mac_addr:
            if debug.is_dbg(hdr):
                logger.warning("Dropping as src is us")
            return False

        # ISO10589 8.4.2.x (XXX lookup)
        # ISO10589: 7.3.15.1: 4
        if hdr.clns_sysid_len and hdr.clns_sysid_len != 6:
            logger.info("TRAP iDFieldLengthMismtach: {}: {} dropping",
                        self, hdr.clns_sysid_len)
            return False

        # ISO10589 8.4.2.2.b (do before area compare)
        # ISO10589 7.3.15.1: 5)
        if hdr.clns_max_area and hdr.clns_max_area != 3:
            logger.info("TRAP maximumAreaAddressesMismatch: {}: {} dropping",
                        self, hdr.clns_max_area)
            return False

        # XXX check authentication password
        return True

    def receive_packets (self):
        pkt = self.rawintf.recv_pkt()
        if pkt:
            self.receive_packet(pkt)

    def receive_packet (self, pkt):
        frame = pdu.get_frame(pkt)
        self.last_frame = frame
        if not frame:
            util.debug_after(1)
        if debug.is_dbg(frame):
            level = pdu.get_frame_level(pkt)
            if level:
                logger.info("Received: L{} {}", level, frame)
            else:
                logger.info("Received: {}", frame)

        #---------------------------------------
        # Verify we are enabled for this level.
        #---------------------------------------

        pdu_type = frame.clns_pdu_type
        if pdu_type in pdu.PDU_FRAME_TYPE_LINDEX:
            lindex = pdu.PDU_FRAME_TYPE_LINDEX[pdu_type]
            if lindex not in self.enabled_lindex:
                return

        if pdu_type not in self.receive_pdu_method:
            logger.warning("Unknown PDU type {}", pdu_type)
            return

        #--------------------------------------------
        # Validate Ethernet Payload and Frame Length
        #--------------------------------------------

        # XXX this is for ethernet only adjust when we get p2p
        # Validate ethernet length field
        payload_len = frame.ether_type
        if payload_len < 46:
            logger.warning("Recived short ethernet frame length {}", payload_len)

        if payload_len + 14 > len(pkt):
            logger.warning("Recived ethernet frame with incorrect length: {} > {}",
                           payload_len,
                           len(pkt) - 14)
        if frame.pdu_len + sizeof(pdu.LLCHeader) > payload_len:
            logger.warning("Recived pkt smaller ({}) than pdu_len ({})",
                           payload_len,
                           frame.pdu_len)

        # Strip off any extra left from padded ethernet frame
        payload_len = frame.pdu_len + sizeof(pdu.LLCHeader)

        #-----------------------------------
        # Get CLNS buffer and TLV space ptr
        #-----------------------------------

        clnsoff = sizeof(pdu.LLCHeader)
        payload = buffer3(pkt, sizeof(pdu.EtherHeader))
        pdubuf = buffer3(payload, clnsoff, payload_len - clnsoff)
        tlvptr = pdubuf[frame.clns_len:]

        #----------------
        # Parse the TLVs
        #----------------

        try:
            tlvs = tlv.parse_tlvs(tlvptr, debug.is_dbg(frame))
        except Exception as ex:
            traceback.print_exc()
            logger.error("Unexpected exception on {} while parsing TLVs in PDU {}: {}",
                         self, frame, ex)
            return

        #-----------------------------------------
        # Dispatch the PDU to the correct handler
        #-----------------------------------------

        try:
            pdu_method = self.receive_pdu_method[pdu_type]
            pdu_method(self, pkt, pdubuf, frame, tlvs)
        except Exception as ex:
            traceback.print_exc()
            logger.error("Unexpected exception on {} handling PDU {}: {}",
                         self, frame, ex)
            return


class _LanLink (Link):                                       # pylint: disable=R0904
    """LAN Link Object"""

    def __init__ (self, linkdb, ifname, index, circtype, p2p=False):
        super(_LanLink, self).__init__(linkdb, ifname, index, circtype)

        self.is_p2p_link = p2p

        # index + 1 to avoid 0 which we use for all p2p links.
        self.local_circuit_id = index + 1
        self.sysid = linkdb.inst.sysid
        logger.debug("Creating {}", self)

        # XXX unhardcode timer interval
        self.std_isis_hello_timer = 10
        self.std_isis_dis_hello_timer = self.std_isis_hello_timer // 3
        self.std_isis_hello_multipier = 3
        self.mtu = 1514

    def get_pdu_mtu (self):
        return self.mtu - sizeof(pdu.LLCFrame)

    def get_lsp_nbr_iter (self, lindex, for_dis):
        def _lsp_nbr_dis_iter ():
            dis = self.get_dis(lindex)
            metric = self.get_lindex_metric(lindex)
            if dis and dis.lanid:
                value = tlv.ExtISReachEntryStruct.pack(dis.lanid,
                                                       tlv.get_3byte_metric_str(metric),
                                                       0)
                yield value

        def _lsp_nbr_adj_iter ():
            # Always include us.
            sysid = self.linkdb.inst.sysid
            yield tlv.ExtISReachEntryStruct.pack(sysid + bchr(0),
                                                 tlv.get_3byte_metric_str(0),
                                                 0)

            # And any UP adjacencies
            adjdb = self.lxlink[lindex].adjdb
            with adjdb:
                for adj in adjdb.adjlist:
                    if adj.state == adj.ADJ_STATE_UP:
                        value = tlv.ExtISReachEntryStruct.pack(adj.sysid + bchr(0),
                                                               tlv.get_3byte_metric_str(0),
                                                               0)
                        yield value

        if for_dis:
            return _lsp_nbr_adj_iter
        else:
            return _lsp_nbr_dis_iter

    def get_llc_frame (self, lindex=None):
        size = sizeof(pdu.LLCFrame)
        if sys.version_info >= (3, 0):
            buf = bytearray(size)
            hdr = pdu.LLCFrame.from_buffer(buf)             # pylint: disable=E1101
        else:
            buf = create_string_buffer(size)
            hdr = util.cast_as(buf, pdu.LLCFrame)
        memcpy(hdr.ether_src, self.mac_addr)
        if lindex is None:
            memcpy(hdr.ether_dst, clns.ALL_IS)
        else:
            memcpy(hdr.ether_dst, clns.ALL_LX_IS[lindex])
        hdr.llc_ssap = 0xfe
        hdr.llc_dsap = 0xfe
        hdr.llc_control = 0x03
        return hdr

    def get_iih_buffer (self, lindex):
        maxsize = max(self.get_pdu_mtu(), clns.originatingLxLSPBufferSize(lindex))

        pdu_type = clns.PDU_TYPE_IIH_LAN_LX[lindex]
        iih, buf, tlvview = pdu.get_pdu_buffer(maxsize, pdu_type)

        iih.circuit_type = self.circtype
        memcpy(iih.source_id, self.linkdb.inst.sysid)
        lxlink = self.lxlink[lindex]
        iih.hold_time = lxlink.hello_interval * lxlink.hello_multiplier
        iih.priority = lxlink.priority
        iih.reserved = 0
        memcpy(iih.lan_id, lxlink.lanid)

        # Get pointer to tlv space
        return iih, buf, tlvview

    def get_p2p_iih_buffer (self):
        maxsize = self.get_pdu_mtu()
        for lindex in [0, 1]:
            if self.is_lindex_enabled(lindex):
                maxsize = max(maxsize, clns.originatingLxLSPBufferSize(lindex))

        pdu_type = clns.PDU_TYPE_IIH_P2P
        iih, buf, tlvview = pdu.get_pdu_buffer(maxsize, pdu_type)

        # Add in ether header
        iih.clns_len += sizeof(pdu.EtherHeader)

        iih.circuit_type = self.circtype
        memcpy(iih.source_id, self.linkdb.inst.sysid)
        lxlink = self.p2plxlink
        iih.hold_time = lxlink.hello_interval * lxlink.hello_multiplier
        iih.reserved = 0
        iih.local_circuit_id = 0

        # Get pointer to tlv space
        return iih, buf, tlvview

    def get_csnp_buffer (self, lindex):
        pdu_type = clns.PDU_TYPE_CSNP_LX[lindex]
        csnp, buf, tlvview = pdu.get_pdu_buffer(self.get_pdu_mtu(), pdu_type)

        memcpy(csnp.source_id, self.linkdb.inst.sysid + bchr(0))
        tlvview = memoryview(buf)[sizeof(csnp):]             # Get pointer to tlv space
        return csnp, buf, tlvview

    def get_psnp_buffer (self, lindex):
        pdu_type = clns.PDU_TYPE_PSNP_LX[lindex]
        psnp, buf, tlvview = pdu.get_pdu_buffer(self.get_pdu_mtu(), pdu_type)

        memcpy(psnp.source_id, self.linkdb.inst.sysid + bchr(0))
        tlvview = memoryview(buf)[sizeof(psnp):]             # Get pointer to tlv space
        return psnp, buf, tlvview

    def __str__ (self):
        return "LanLink({})".format(self.ifname)

    def get_dis (self, lindex):
        lxlink = self.lxlink[lindex]
        if not lxlink:
            return None
        return lxlink.dis

    def is_dis (self, lindex):
        lxlink = self.lxlink[lindex]
        if not lxlink:
            return False
        return lxlink.dis == lxlink

    def receive_iih (self, unused_pkt, pdubuf, iih, tlvs):
        inst = self.linkdb.inst

        #------------------
        # ISO10589 8.4.2.1
        #------------------

        if not self.check_pdu(iih, pdubuf, tlvs):
            return

        #-----------------------------
        # Process the TLVs and packet
        #-----------------------------

        lindex = pdu.PDU_FRAME_TYPE_LINDEX[iih.clns_pdu_type]
        if lindex == 0:
            # Reject if we receive 0 or more than 1 AreaAddrTLV
            atlv = tlvs[tlv.TLV_AREA_ADDRS]
            if len(atlv) != 1:
                logger.info("TRAP areaMismatch: Incorrect area TLV count: {}", len(atlv))
                return False
            atlv = atlv[0]
            for addr in atlv.addrs:
                if addr == inst.areaid:
                    break
            else:
                logger.info("TRAP areaMismatch: {}: {}", atlv, clns.iso_decode(inst.areaid))
                return False

        # All checks have passed simply process the hello.
        lxlink = self.lxlink[lindex]
        if lxlink.adjdb.update_adjacency(iih, tlvs):
            lxlink.dis_election_info_changed()

    def dis_election_info_changed(self, lindex):
        """This method is called by AdjDB if DIS election information has changed"""
        lxlink = self.lxlink[lindex]
        if lxlink:
            lxlink.dis_election_info_changed()

    def check_update_pdu (self, hdr, pdubuf, tlvs):
        inst = self.linkdb.inst
        lindex = pdu.PDU_FRAME_TYPE_LINDEX[hdr.clns_pdu_type]
        uproc = inst.update[lindex]
        if not uproc:
            # If we don't support this level drop it.
            return False
        adjdb = self.lxlink[lindex].adjdb

        #------------------------------------
        # ISO10589: 7.3.15.{1,2}: 4, 5, 7, 8
        #------------------------------------
        if not self.check_pdu(hdr, pdubuf, tlvs):
            return False

        #------------------------------
        # ISO10589: 7.3.15.{1,2}: 2, 3
        #------------------------------
        if not uproc:
            if debug.is_dbg(hdr):
                logger.warning("Not is-type enabled at this level")
            return False
        if not self.is_lindex_enabled(lindex):
            if debug.is_dbg(hdr):
                logger.warning("Not circuit-type enabled at this level")
            return False

        #---------------------------
        # ISO10589: 7.3.15.{1,2}: 6
        #---------------------------
        snpa = stringify3(hdr.ether_src)
        if not adjdb.has_up_adjacency(snpa):
            if debug.is_dbg(hdr):
                logger.warning("Dropping no adjacency with {}", clns.iso_decode(snpa))
            return False

        return True

    def receive_lsp (self, pkt, pdubuf, lsphdr, tlvs):
        inst = self.linkdb.inst
        try:
            lindex = pdu.PDU_FRAME_TYPE_LINDEX[lsphdr.clns_pdu_type]
        except KeyError:
            util.debug_after(1)
        uproc = inst.update[lindex]

        #----------------------------------------
        # ISO10589: 7.3.15.1: 2, 3, 4, 5, 6 7, 8
        #----------------------------------------
        if not self.check_update_pdu(lsphdr, pdubuf, tlvs):
            return

        uproc.receive_lsp(self, pkt, pdubuf, lsphdr, tlvs)

    def receive_snp (self, unused_pkt, pdubuf, snphdr, tlvs):
        inst = self.linkdb.inst
        lindex = pdu.PDU_FRAME_TYPE_LINDEX[snphdr.clns_pdu_type]
        uproc = inst.update[lindex]

        #----------------------------------------
        # ISO10589: 7.3.15.2: 2, 3, 4, 5, 6 7, 8
        #----------------------------------------
        if not self.check_update_pdu(snphdr, pdubuf, tlvs):
            return

        uproc.receive_snp(self, snphdr, tlvs)

    def send_pdu (self, pduframe, pdubuf, extra):
        pdulen = sizeof(pduframe) + extra
        # Ethernet requires payload length of 46 bytes.
        pktlen = pdulen + sizeof(pdu.LLCHeader)
        if pktlen >= 46:
            extra = 0
        else:
            extra = 46 - pktlen
            pktlen = 46

        if self.is_p2p_link:
            llcframe = self.get_llc_frame()
        else:
            lindex = pdu.PDU_FRAME_TYPE_LINDEX[pduframe.clns_pdu_type]
            llcframe = self.get_llc_frame(lindex)
        llcframe.ether_type = pktlen
        pduframe.pdu_len = pdulen
        vec = [llcframe, pdubuf[:pdulen]]
        if extra:
            vec.append(b"\x00" * extra)
        count = self.rawintf.writev(vec)
        if debug.is_dbg(pduframe):
            logger.info("{} wrote: {} bytes".format(self, count))

    def fill_snp_packet (self, ssnflags, tlvview):
        """Fill an SNP packet with SNP entries"""
        snpstruct = tlv.SNPEntryStruct
        sz = snpstruct.size

        availb = len(tlvview) - 2
        avail = availb // sz
        while avail > 0 and ssnflags:
            tavailb = min(255, availb)
            tlvview[0] = tlvwrb(tlv.TLV_SNP_ENTRIES)
            tlvp = tlvview[2:2 + tavailb]
            origtlvp = tlvp
            while len(tlvp) >= sz and ssnflags:
                # XXX don't we need to lock the DB here while we look at this data?
                lspseg = ssnflags.pop()
                lsphdr = lspseg.lsphdr
                self.clear_flag_impl(SSN, lspseg)

                tlvp[0:sz] = snpstruct.pack(lsphdr.lifetime,
                                            stringify3(lsphdr.lspid),
                                            lsphdr.seqno,
                                            lsphdr.checksum)
                tlvp = tlvp[sz:]
            tlen = len(origtlvp) - len(tlvp)
            tlvview[1] = tlvwrb(tlen)

            tlvview = tlvview[tlen + 2:]
            availb = len(tlvview) - 2
            avail = availb // sz
        return ssnflags, tlvview

    def send_packets_psnp (self, lindex):
        # Get the set of SSN flags and clear
        with self.flag_locks[lindex]:
            ssnflags = list(self.flags[lindex][SSN])
            self.flags[lindex][SSN] = set()

        if not ssnflags:
            return

        if debug.is_dbg_type(clns.PDU_TYPE_PSNP_LX[lindex]):
            logger.debug("START PSNP")

        psnp, pdubuf, orig_tlvview = self.get_psnp_buffer(lindex)

        # snpstruct = tlv.SNPEntryStruct
        # sz = snpstruct.size
        #
        # # Determine the total number of entries that fit in a PSNP
        # tlv_space = len(orig_tlvview)
        # full_entry_count = 255 // sz
        # full_tlv_count = tlv_space // 257
        # short_entry_count = ((tlv_space % 257) - 2) // sz
        # psnp_tlv_count = full_tlv_count + (1 if short_entry_count else 0)
        # psnp_entry_count = full_tlv_count * full_entry_count + short_entry_count
        #
        # # Determine the number of PSNP we need
        # count = len(ssnflags)
        # pktcount = count // psnp_entry_count
        # if count % psnp_entry_count:
        #     pktcount += 1
        # for pi in xrange(0, pktcount):
        #     ...

        while ssnflags:
            ssnflags, tlvview = self.fill_snp_packet(ssnflags, orig_tlvview)
            extra = len(orig_tlvview) - len(tlvview)
            if debug.is_dbg(psnp):
                logger.info("Sending 1 PSNP packet")
            self.send_pdu(psnp, pdubuf, extra)

        if debug.is_dbg(psnp):
            logger.debug("DONE SENDING PSNP")

    def send_packets_lindex (self, lindex):
        # if ( debug.is_dbg_type(clns.PDU_TYPE_PSNP_LX[lindex]) or
        #      debug.is_dbg_type(clns.PDU_TYPE_LSP_LX[lindex])):
        #     logger.info("Send Packets Lindex: {} {}", self, lindex)

        #-----------
        # Flood LSP
        #-----------

        # XXX we really want to send no more than 10 at a time, and then wait.
        # XXX implement with sending timers eventually.
        with self.flag_locks[lindex]:
            lsplist = list(self.flags[lindex][SRM])

        # if debug.is_dbg_type(clns.PDU_TYPE_LSP_LX[lindex]):
        #     logger.info("  LSP {} ", lsplist)
        for lspseg in lsplist:
            # if debug.is_dbg_type(clns.PDU_TYPE_LSP_LX[lindex]):
            #     logger.info("Sending 1 LSP {} on {}", lspseg, self)
            lspseg.update_lifetime()
            self.send_lsp(lspseg)
            # if debug.is_dbg_type(clns.PDU_TYPE_LSP_LX[lindex]):
            #     logger.info("Sent 1 LSP {} on {}", lspseg, self)
            with self.flag_locks[lindex]:
                self.flags[lspseg.lindex][SRM].remove(lspseg)
                self.clear_flag_impl(SRM, lspseg, nolock=True)

        # if debug.is_dbg_type(clns.PDU_TYPE_LSP_LX[lindex]):
        #     logger.info("DONE SENDING LSP")

        #-----------
        # Send PSNP
        #-----------
        self.send_packets_psnp(lindex)

        self.check_send_unready()

    def send_packets (self):
        """Socket is ready to write so send some packets"""
        for lindex in self.enabled_lindex:
            self.send_packets_lindex(lindex)

    def send_lsp(self, lspseg):
        llcframe = self.get_llc_frame(lspseg.lindex)
        payload_len = len(lspseg.pdubuf) + sizeof(pdu.LLCHeader)
        if payload_len >= 46:
            extra = None
        else:
            extra = 46 - payload_len
            # extra = b"\xFF" * extra -- 0xff easier to see the pad in dumps.
            extra = b"\x00" * extra
            payload_len = 46
        llcframe.ether_type = payload_len
        if extra:
            self.rawintf.writev([llcframe, lspseg.pdubuf, extra])
        else:
            self.rawintf.writev([llcframe, lspseg.pdubuf])


class P2PLanLink (_LanLink):
    def __init__ (self, linkdb, ifname, index, circtype):
        super(P2PLanLink, self).__init__(linkdb, ifname, index, circtype, True)

        self.lxlink = [ None, None ]
        self.p2plxlink = LxP2PLanLink(self)

    def receive_iih (self, unused_pkt, pdubuf, iih, tlvs):
        inst = self.linkdb.inst

        #------------------
        # ISO10589 8.4.2.1
        #------------------

        if not self.check_pdu(iih, pdubuf, tlvs):
            return

        #-----------------------------
        # Process the TLVs and packet
        #-----------------------------

        lindex = pdu.PDU_FRAME_TYPE_LINDEX[iih.clns_pdu_type]
        if lindex == 0:
            # Reject if we receive 0 or more than 1 AreaAddrTLV
            atlv = tlvs[tlv.TLV_AREA_ADDRS]
            if len(atlv) != 1:
                logger.info("TRAP areaMismatch: Incorrect area TLV count: {}", len(atlv))
                return False
            atlv = atlv[0]
            for addr in atlv.addrs:
                if addr == inst.areaid:
                    break
            else:
                logger.info("TRAP areaMismatch: {}: {}", atlv, clns.iso_decode(inst.areaid))
                return False

        # All checks have passed simply process the hello.
        lxlink = self.lxlink[lindex]
        if lxlink.adjdb.update_adjacency(iih, tlvs):
            lxlink.dis_election_info_changed()


class LanLink (_LanLink):
    def __init__ (self, linkdb, ifname, index, circtype):
        super(LanLink, self).__init__(linkdb, ifname, index, circtype, False)

        self.lxlink = [ None, None ]
        for lindex in self.enabled_lindex:
            self.lxlink[lindex] = LxLanLink(self, lindex)


LanLink.receive_pdu_method = {
    clns.PDU_TYPE_IIH_LAN_L1: LanLink.receive_iih,
    clns.PDU_TYPE_IIH_LAN_L2: LanLink.receive_iih,
    # XXXp2p different rx routine?
    clns.PDU_TYPE_IIH_P2P: P2PLanLink.receive_iih,
    clns.PDU_TYPE_LSP_L1: LanLink.receive_lsp,
    clns.PDU_TYPE_LSP_L2: LanLink.receive_lsp,
    clns.PDU_TYPE_CSNP_L1: LanLink.receive_snp,
    clns.PDU_TYPE_CSNP_L2: LanLink.receive_snp,
    clns.PDU_TYPE_PSNP_L1: LanLink.receive_snp,
    clns.PDU_TYPE_PSNP_L2: LanLink.receive_snp,
}


class LxP2PLanLink (object):
    """Level "Specific" P2P LAN Link Object"""
    def __init__ (self, link):
        self.dis = None

        # Possibly create 2 AdjLinkDBs
        for lindex in [ 0, 1 ]:
            if link.is_lindex_enabled(lindex):
                self.adjdb = adjacency.AdjLinkDB(link, lindex)

        self.link = link
        self.sysid = link.sysid
        self.hello_interval = link.std_isis_hello_timer
        self.hello_multiplier = link.std_isis_hello_multipier

        #-------------
        # Hello Timer
        #-------------
        self.iih_timer = timers.Timer(link.linkdb.timerheap,
                                      .25,
                                      self.p2p_iih_expire)
        # XXX self.iih_timer.start(self.hello_interval)
        self.iih_timer.start(1)

        # #------------
        # # CSNP timer
        # #------------
        # self.csnp_timer = timers.Timer(link.linkdb.timerheap,
        #                                0,
        #                                self.csnp_expire)

    def __str__ (self):
        sstr = "L"
        if self.link.is_lindex_enabled(0):
            sstr += "1"
        if self.link.is_lindex_enabled(1):
            sstr += "2"
        return "LxP2PLanLink({}: {})".format(sstr, self.link.ifname)

    def p2p_iih_expire (self):
        # XXX only removed stuff from iih_expire so refactor
        iih, pdubuf, tlvview = self.link.get_p2p_iih_buffer()
        tlvspace = len(tlvview)

        # Add Area Addresses
        areaid = self.link.linkdb.inst.areaid
        areaval = bchr(len(areaid)) + areaid
        tlvview = tlv.tlv_append(tlvview, tlv.TLV_AREA_ADDRS, areaval)

        # # Add IS Neighbors
        tlvview, unused = tlv.tlv_insert_entries(tlv.TLV_IS_NEIGHBORS,
                                                 tlvview,
                                                 self.adjdb.neighbor_iih_tlv_iter)

        # Add NLPID
        tlvview = tlv.tlv_append(tlvview, tlv.TLV_NLPID, bchr(clns.NLPID_IPV4))

        # Add IPv4 Interface Address
        tlvview = tlv.tlv_append(tlvview,
                                 tlv.TLV_IPV4_INTF_ADDRS,
                                 self.link.ipv4_prefix.ip.packed)

        # Add Padding
        while len(tlvview) >= 2:
            padlen = min(255, len(tlvview) - 2)
            tlvview = tlv.tlv_pad(tlvview, padlen)

        # TLV space is original space minus what we have leftover.
        extra = tlvspace - len(tlvview)
        self.link.send_pdu(iih, pdubuf, extra)
        self.iih_timer.start(self.hello_interval)


class LxLanLink (object):
    """Level Specific LAN Link Object"""
    def __init__ (self, link, lindex):
        self.dis = None
        self.adjdb = adjacency.AdjLinkDB(link, lindex)
        self.lindex = lindex
        self.link = link
        self.priority = self.link.linkdb.inst.priority
        self.sysid = link.sysid
        # XXX maybe 0?
        self.lanid = link.linkdb.inst.sysid + bchr(link.local_circuit_id)
        self.hello_interval = link.std_isis_hello_timer
        self.hello_multiplier = link.std_isis_hello_multipier
        self.pn_lsp = None

        #-------------
        # Hello Timer
        #-------------
        self.iih_timer = timers.Timer(link.linkdb.timerheap,
                                      .25,
                                      self.iih_expire)
        # XXX self.iih_timer.start(self.hello_interval)
        self.iih_timer.start(1)

        #--------------------
        # DIS election timer
        #--------------------
        self.dis_timer = timers.Timer(link.linkdb.timerheap,
                                      0,
                                      self.dis_elect_expire)
        self.dis_timer.start(4) # XXX self.hello_interval * 2)

        #------------
        # CSNP timer
        #------------
        self.csnp_timer = timers.Timer(link.linkdb.timerheap,
                                       0,
                                       self.csnp_expire)

    def __str__ (self):
        return "LxLanLink(L{}: {})".format(self.lindex + 1, self.link.ifname)

    def dis_find_best (self):

        #-----------------
        # ISO10589: 8.4.5
        #-----------------

        elect = self            # duck typing: only looks at priority and sysid
        count = 0
        for adj in self.adjdb.adjlist:
            if adj.state != adj.ADJ_STATE_UP:
                continue
            count += 1
            if adj.priority > elect.priority:
                elect = adj
            elif adj.priority == elect.priority:
                if adj.sysid > elect.sysid:
                    elect = adj
        if count == 0:
            # No up adjacencies
            elect = None
        return elect

    def dis_self_elect (self, old_dis):
        # We are becoming DIS
        logger.info("TRAP lANLevelXDesignatedIntermediateSystemChange: Old: {} New: {}",
                    old_dis, self)

        # Generate
        assert self.pn_lsp is None
        self.pn_lsp = lsp.OwnLSP(self.link.linkdb.inst, self.lindex, self.link)
        self.pn_lsp.sched_gen(5) # XXX 0

        # Start sending CSNP
        self.csnp_timer.start(0)

    def dis_self_resign (self, elect):
        # We are no longer DIS
        logger.info("TRAP lANLevelXDesignatedIntermediateSystemChange: Old: {} New: {}",
                    self, elect)

        # Stop sending CSNP
        self.csnp_timer.stop()

        # Purge
        assert self.pn_lsp is not None
        self.pn_lsp.purge()
        self.pn_lsp = None

    def dis_elect (self):
        if self.dis_timer.scheduled():
            return

        inst = self.link.linkdb.inst
        uproc = inst.update[self.lindex]

        old_dis = self.dis
        with self.adjdb:
            elect = self.dis_find_best()
            if elect == old_dis:
                return
            if old_dis == self:
                self.dis_self_resign(elect)

            logger.info("DIS Change: Old: {} New: {}", old_dis, elect)

            self.dis = elect
            if elect is None:
                # No DIS no PN LSP, set LAN ID to us.
                # Purge if we didn't just do it above the TRAP.
                self.lanid = inst.sysid + bchr(self.link.local_circuit_id)
            else:
                self.lanid = self.dis.lanid
                if elect == self:
                    self.dis_self_elect(old_dis)

                # What happens when the neighbor is reporting *us* in it's LANID?
                # If we don't think we are DIS we won't generate a PNLSP so no
                # linkage will exist.

            uproc.dis_change(self.link, self.lindex, self.dis)

    def dis_elect_expire (self):
        logger.debug("{}: Running DIS election", self)
        self.dis_elect()

    def dis_election_info_changed(self):
        if self.dis_timer.scheduled():
            return

        # Schedule the timer to fire "immediately". This moves us from (possibly)
        # the packet receive thread to the timer thread.
        self.dis_timer.start(.001)

    def iih_expire (self):
        iih, pdubuf, tlvview = self.link.get_iih_buffer(self.lindex)
        # XXX test.
        if self.dis == self:
            self.priority = 10
        tlvspace = len(tlvview)

        # Add Area Addresses
        areaid = self.link.linkdb.inst.areaid
        areaval = bchr(len(areaid)) + areaid
        tlvview = tlv.tlv_append(tlvview, tlv.TLV_AREA_ADDRS, areaval)

        # # Add IS Neighbors
        tlvview, unused = tlv.tlv_insert_entries(tlv.TLV_IS_NEIGHBORS,
                                                 tlvview,
                                                 self.adjdb.neighbor_iih_tlv_iter)

        # Add NLPID
        tlvview = tlv.tlv_append(tlvview, tlv.TLV_NLPID, bchr(clns.NLPID_IPV4))

        # Add IPv4 Interface Address
        tlvview = tlv.tlv_append(tlvview,
                                 tlv.TLV_IPV4_INTF_ADDRS,
                                 self.link.ipv4_prefix.ip.packed)

        # Add Padding
        while len(tlvview) >= 2:
            padlen = min(255, len(tlvview) - 2)
            tlvview = tlv.tlv_pad(tlvview, padlen)

        # TLV space is original space minus what we have leftover.
        extra = tlvspace - len(tlvview)
        self.link.send_pdu(iih, pdubuf, extra)
        self.iih_timer.start(self.hello_interval)

        # XXX test.
        if self.dis == self:
            self.dis_election_info_changed()

    #------
    # CSNP
    #------

    def get_last_snpentry_lspid (self, tlvstart, tlvspace):
        tlvspace -= tlv.SNPEntryStruct.size
        tlvspace += tlv._SNPEntry.lspid.offset              # pylint: disable=E1101,W0212
        return tlvstart[tlvspace:tlvspace + clns.CLNS_LSPID_LEN]

    def close_and_send_csnp (self, csnp, buf, tlvview, final):
        tlvstart = memoryview(buf)[sizeof(csnp):]           # Get pointer to tlv start space
        tlvspace = memspan(tlvstart, tlvview)

        if final:
            util.memcpy(csnp.end_lspid, b"\xff" * 8)
        else:
            util.memcpy(csnp.end_lspid,
                        self.get_last_snpentry_lspid(tlvstart,
                                                     tlvspace))

        self.link.send_pdu(csnp, buf, tlvspace)

    def get_new_csnp_buf (self, tlvview, buflist):
        if not buflist:
            buflist = []
            startid = b"\x00" * 8
        else:
            csnp, buf, unused = buflist[-1]
            self.close_and_send_csnp(csnp, buf, tlvview, False)
            startid = clns.inc_lspid(stringify3(csnp.end_lspid))

        csnp, pdubuf, tlvview = self.link.get_csnp_buffer(self.lindex)
        memcpy(csnp.start_lspid, startid)

        buflist.append((csnp, pdubuf, tlvview))
        return tlvview, buflist

    def csnp_expire (self):
        # Reschedule in 10 seconds

        self.csnp_timer.start(10)
        uproc = self.link.linkdb.inst.update[self.lindex]
        tlvview, buflist = tlv.tlv_insert_entries(tlv.TLV_SNP_ENTRIES,
                                                  None,
                                                  uproc.csnp_iter,
                                                  self.get_new_csnp_buf,
                                                  None)
        csnp, buf, unused = buflist[-1]
        self.close_and_send_csnp(csnp, buf, tlvview, True)

__author__ = 'Christian Hopps'
__date__ = 'November 1 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
