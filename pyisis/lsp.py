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
from ctypes import sizeof
from pyisis.bstr import bchr, memspan                       # pylint: disable=E0611
from pyisis.lib.util import stringify3, tlvrdb, xrange3

import logbook
import pyisis.clns as clns
import pyisis.lib.debug as debug
import pyisis.pdu as pdu
import pyisis.lib.timers as timers
import pyisis.tlv as tlv
import pyisis.lib.util as util

logger = logbook.Logger(__name__)

ZERO_MAX_AGE = 60
MAX_AGE = 1200


def get_lsp_number (lsphdr):
    return int(lsphdr.lspid[clns.CLNS_LSP_SEGMENT_OFF])


def lsp_id_str (lsp):
    return clns.iso_decode(lsp.lspid)


class LSPSegment (object):
    def __init__ (self, inst, lindex, pdubuf, tlvs):
        self.inst = inst
        self.uproc = inst.update[lindex]
        self.lindex = lindex
        self.pdubuf = bytearray(pdubuf)
        self.lsphdr = util.cast_as(self.pdubuf, pdu.LSPPDU)
        self.tlvview = memoryview(self.pdubuf)[self.lsphdr.clns_len:]
        self.tlvs = tlvs
        self.is_lsp_ack = False                             # Used to indicate only an ack skeleton

        self.purge_lock = util.QueryLock()

        self.hold_timer = timers.Timer(self.uproc.timerheap, 0, self.expire)

        self.zero_lifetime = None
        self.lifetime = util.Lifetime(self.lsphdr.lifetime)
        # Should we add a second here so we always expire after?
        self.hold_timer.start(self.lifetime.timeleft())

        if not self.is_ours():
            self.refresh_timer = None
        else:
            timeleft = (self.lifetime.timeleft() * 3) / 4
            if timeleft:
                self.refresh_timer = timers.Timer(self.uproc.timerheap, 0, self.refresh)
                self.refresh_timer.start(timeleft)

        logger.info("Adding LSP to DB: {}", self)

    def __str__ (self):
        lsphdr = self.lsphdr
        return "LSP(id:{} seqno:{:#010x} lifetime:{} cksum:{:#06x})".format(
            clns.iso_decode(lsphdr.lspid),
            lsphdr.seqno,
            lsphdr.lifetime,
            lsphdr.checksum)

    def get_lspid (self):
        return stringify3(self.lsphdr.lspid)

    def update (self, pdubuf, tlvs):
        """Update the segment based on received packet"""
        with self.purge_lock:
            self.pdubuf = bytearray(pdubuf)
            self.lsphdr = util.cast_as(self.pdubuf, pdu.LSPPDU)
            self.tlvs = tlvs

            # This LSP is being purged.
            if self.lsphdr.lifetime == 0:
                # We're updating so need to set a new zero age lifetime.
                self.hold_timer.stop()
                if self.zero_lifetime is None:
                    self.zero_lifetime = util.Lifetime(ZERO_MAX_AGE)
                elif self.zero_lifetime.timeleft() < ZERO_MAX_AGE:
                    # This is due to a seqno update.
                    self.zero_lifetime.reset(ZERO_MAX_AGE)
                self.hold_timer.start(self.zero_lifetime.timeleft())
                logger.info("Updated zero-lifetime LSP to {}", self)
                return

            # Reset the hold timer
            self.zero_lifetime = None
            self.lifetime.reset(self.lsphdr.lifetime)
            self.hold_timer.start(self.lifetime.timeleft())

            if self.is_ours():
                assert self.refresh_timer
                timeleft = (self.lifetime.timeleft() * 3) / 4
                assert timeleft
                self.refresh_timer.stop()
                self.refresh_timer.start(timeleft)

        logger.info("Updated LSP to {}", self)

    def refresh (self):
        logger.info("Refresh timer fires for own LSP {}", self)
        assert self.lifetime and self.lifetime.timeleft()
        assert self.lsphdr.lifetime

        # Force a regeneration.
        self.uproc.update_own_lsp(self.pdubuf, self.tlvs, self.lsphdr.seqno)

    def _purge_expired (self, zero_age=ZERO_MAX_AGE):
        """Purge the LSP, purge lock must already be held and timer should be unset"""
        assert self.purge_lock.held()

        #-----------------------------
        # ISO10589: 7.3.16.4: a, b, c
        #-----------------------------

        # a)
        self.inst.linkdb.set_all_srm(self)

        # b) Retain only LSP header. XXX we need more space for auth and purge tlv
        self.pdubuf = self.pdubuf[:sizeof(pdu.LSPPDU)]
        frame = util.cast_as(self.pdubuf, pdu.LSPPDU)

        frame.checksum = 0
        frame.pdu_len = len(self.pdubuf)

        # c) Retain for ZERO_MAX_AGE
        self.zero_lifetime = util.Lifetime(zero_age)
        assert not self.hold_timer.scheduled()
        self.hold_timer.start(self.zero_lifetime.timeleft())

        # Add in purge TLVs

        logger.info("Adding LSP to DB: {}", self)

    def get_segment_number (self):
        return get_lsp_number(self.lsphdr)

    def is_ours (self):
        srcid = stringify3(self.lsphdr.lspid[:clns.CLNS_SYSID_LEN])
        ours = srcid == self.inst.sysid
        return ours

    def force_purge_ours (self):
        with self.purge_lock:
            logger.info("Forcing purge of Our LSP {}", self.lindex + 1, self)
            assert self.is_ours()
            # See if it's already done
            if self.lsphdr.lifetime == 0:
                assert self.zero_lifetime is not None
                return
            frame = util.cast_as(self.pdubuf, pdu.LSPPDU)
            frame.lifetime = 0
            self.hold_timer.stop()
            self.refresh_timer.stop()
            # Since we are "originating" this I suppose we use MAX_AGE
            self._purge_expired(MAX_AGE)

    def update_lifetime (self):
        """Update the lifetime field in the LSP header, may initiate purge"""
        with self.purge_lock:
            # If the lifetime is already zero nothing to update.
            if self.lsphdr.lifetime == 0:
                assert self.zero_lifetime is not None
                return

            timeleft = self.lifetime.timeleft()
            self.lsphdr.lifetime = timeleft
            if not timeleft:
                # We have expired, stop the normal timer, and purge
                self.hold_timer.stop()
                self._purge_expired()

    def expire (self):
        with self.purge_lock:
            # Check to see if we have already purged.
            if self.zero_lifetime is not None:
                # Zero age timer has expired, remove the LSP segment
                assert self.lsphdr.lifetime == 0
                self.zero_lifetime = None
                logger.info("XXXXXX Removing zero lifetime LSP {}", self)
                self.uproc.remove_lsp(self)
                # We're gone.
                return

            if self.lsphdr.seqno == 0:
                util.debug_after(1)

            # Lifetime timer has expired, set lifetime to 0 and purge.
            frame = util.cast_as(self.pdubuf, pdu.LSPPDU)
            frame.lifetime = 0
            self._purge_expired()


class OwnLSP (object):
    """Locally originated LSP"""
    def __init__ (self, inst, lindex, link=None):
        self.inst = inst
        self.lindex = lindex
        self.link = link
        self.gen_lock = util.QueryLock()
        self.gen_timer = timers.Timer(inst.timerheap, 0, self.gen_expire)
        self.segments = {}

        self.tlv_producers = {}
        self.seg_zero_tlv_producers = {}

        if link:
            self.nodeid = inst.sysid + bchr(link.local_circuit_id)
        else:
            self.nodeid = inst.sysid + bchr(0)

    def sched_gen (self, delay):
        with self.gen_lock:
            if self.gen_timer.scheduled():
                return
            self.gen_timer.start(delay)

    def gen_expire (self):
        with self.gen_lock:
            self.regenerate()

    def get_segment (self, index):
        if index in self.segments:
            return self.segments[index]
        return None

    def purge (self):
        # Purge this is only called for PN-LSPs
        assert self.is_pnlsp()

        # Purge any newly unsupported.
        for i in xrange3(0, 256):
            if i in self.segments:
                lspseg = self.segments[i]
                if not lspseg.lifetime or lspseg.lifetime.timeleft() != 0:
                    lspseg.force_purge_ours()
                del self.segments[i]

    def is_pnlsp (self):
        return self.link is not None

    def get_value_view (self, tlvview, space):
        if not tlvview:
            return None
        if len(tlvview) < space:
            return None
        return tlvview

    def get_tlv_start (self, lsp, buf):
        return memoryview(buf)[sizeof(lsp):]            # Get pointer to tlv start space

    def update_lsp_db (self, lsp, buf, tlvview):
        # Complete the LSP and update the DB.
        tlvstart = self.get_tlv_start(lsp, buf)
        tlvspace = memspan(tlvstart, tlvview)
        lsp.pdu_len = sizeof(lsp) + tlvspace
        pdubuf = memoryview(buf)
        pdubuf = pdubuf[:lsp.pdu_len]

        # XXX cast_as doesn't like bytearray or a memoryview of it, copy into string
        # pdubuf = stringify3(pdubuf)

        # Re-get the start using new sized buffer.
        tlvstart = self.get_tlv_start(lsp, pdubuf)
        tlvs = tlv.parse_tlvs(tlvstart, debug.is_dbg(lsp))

        uproc = self.inst.update[self.lindex]
        uproc.update_own_lsp(pdubuf, tlvs)

        segment = get_lsp_number(lsp)
        self.segments[segment] = uproc.get_lsp_segment(stringify3(lsp.lspid))

    def close_lsp (self, lsp, buf, tlvview):
        segnum = get_lsp_number(lsp)
        tlvstart = self.get_tlv_start(lsp, buf)

        # We only introduce empty LSPs for segment 0
        if memspan(tlvstart, tlvview) > 0 or segnum == 0:
            self.update_lsp_db(lsp, buf, tlvview)
            segnum += 1

        # Purge any newly unsupported.
        for i in xrange3(segnum, 256):
            if i in self.segments:
                lspseg = self.segments[i]
                if lspseg.lifetime:
                    lspseg.force_purge_ours()
                del self.segments[i]

    def get_new_buf (self, tlvview, buflist):
        if not buflist:
            buflist = []
            segment = 0
        else:
            lsp, buf, unused = buflist[-1]
            self.update_lsp_db(lsp, buf, tlvview)
            segment = tlvrdb(lsp.lsphdr.lspid[clns.CLNS_LSP_SEGMENT_OFF]) + 1
            if segment == 256:
                raise tlv.NoSpaceErorr()

        oldseg = self.get_segment(segment)
        if oldseg:
            seqno = oldseg.lsphdr.seqno
        else:
            seqno = 0

        lsp, buf, tlvview = pdu.get_raw_lsp_pdu(self.lindex)
        lsp.pdu_len = 0
        lsp.lifetime = 60 # XXX MAX_AGE
        util.memcpy(lsp.lspid, self.nodeid + bchr(segment))
        lsp.seqno = seqno                            # init with old seqno
        lsp.checksum = 0
        lsp.p_bit = 0
        lsp.att_error = 0
        lsp.att_expense = 0
        lsp.att_delay = 0
        lsp.att_default = 1
        lsp.overload = self.inst.overload
        lsp.is_type = self.inst.is_type
        tlvview = memoryview(buf)[sizeof(lsp):]
        buflist.append((lsp, buf, tlvview))
        return tlvview, buflist

    def regen_nonpn_lsp (self):
        lindex = self.lindex
        logger.info("L{} Non-PN LSP Generation starts", lindex + 1)
        cputimer = util.CPUTimer()

        linkdb = self.inst.linkdb
        buflist = []
        tlvview = None

        # Authentication
        # XXX

        # Area addresses - Level 2 only
        if lindex == 1:
            areaid = self.inst.areaid
            areaval = bchr(len(areaid)) + areaid
            tlvview, buflist = tlv.tlv_insert_value(tlv.TLV_AREA_ADDRS,
                                                    tlvview,
                                                    areaval,
                                                    self.get_new_buf,
                                                    buflist)
        # Hostname
        tlvview, buflist = tlv.tlv_insert_value(tlv.TLV_HOSTNAME,
                                                tlvview,
                                                self.inst.hostname,
                                                self.get_new_buf,
                                                buflist)

        # Add NLPID
        tlvview, buflist = tlv.tlv_insert_value(tlv.TLV_NLPID,
                                                tlvview,
                                                bchr(clns.NLPID_IPV4),
                                                self.get_new_buf,
                                                buflist)

        # Add IPv4 Interface Addresses
        tlvview, buflist = tlv.tlv_insert_entries(tlv.TLV_IPV4_INTF_ADDRS,
                                                  tlvview,
                                                  linkdb.get_intf_ipv4_iter(lindex),
                                                  self.get_new_buf,
                                                  buflist)

        # IS Reach - Don't use this.

        # Ext IS Reach
        tlvview, buflist = tlv.tlv_insert_entries(tlv.TLV_EXT_IS_REACH,
                                                  tlvview,
                                                  linkdb.get_lsp_nbr_iter(lindex),
                                                  self.get_new_buf,
                                                  buflist)

        # Prefix Addresses
        # lsp, buf, tlvview, tlvdata = self.get_tlvview(lsp, buf, tlvview,
        #                                               tlv.TLV_EXT_IS_REACH,
        #                                               len(entry))

        # Close the LSP updating final segment if non-empty or 0
        lsp, buf, unused = buflist[-1]
        self.close_lsp(lsp, buf, tlvview)

        logger.info("L{} Non-PN LSP Generation {} completes using {}",
                    lindex + 1,
                    lsp_id_str(lsp),
                    cputimer)

    def regen_pn_lsp (self):
        lindex = self.lindex
        logger.info("L{} PN LSP Generation starts", lindex + 1)
        cputimer = util.CPUTimer()

        buflist = []
        tlvview = None

        logger.info("L{} PN LSP Generation starts for {}", lindex + 1, self.link)

        tlvview, buflist = tlv.tlv_insert_entries(tlv.TLV_EXT_IS_REACH,
                                                  tlvview,
                                                  self.link.get_lsp_nbr_iter(lindex, True),
                                                  self.get_new_buf,
                                                  buflist)

        lsp, buf, unused = buflist[-1]
        self.close_lsp(lsp, buf, tlvview)

        logger.info("L{} PN LSP Generation {} completes using {}",
                    lindex + 1,
                    lsp_id_str(lsp),
                    cputimer)

    def regenerate (self):                                  # pylint: disable=R0914
        if not self.link:
            self.regen_nonpn_lsp()
        else:
            self.regen_pn_lsp()

__author__ = 'Christian Hopps'
__date__ = 'November 2 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
