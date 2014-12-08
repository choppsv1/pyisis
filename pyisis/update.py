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
# from pyisis.lib.util import buffer3
from pyisis.lib.util import debug_exception

from ctypes import sizeof
import logbook
import threading
# import rbtree
import pyisis.clns as clns
# import pyisis.lib.debug as debug
import pyisis.lsp as lsp
import pyisis.pdu as pdu
import pyisis.lib.timers as timers
import pyisis.tlv as tlv
import pyisis.lib.util as util
from pyisis.lib.util import stringify3, tlvrdb
from pyisis.lib.cksum import iso_cksum

logger = logbook.Logger(__name__)

OLDER = -1
SAME = 0
NEWER = 1


class UpdateProcess (object):
    def __init__ (self, inst, lindex):
        self.inst = inst
        self.lindex = lindex
        self.timerheap = timers.TimerHeap("Level-{} UpdateProcess".format(lindex + 1))

        self.dblock = threading.Lock()
        self.dbhash = {}
        # self.dbtree = rbtree.rbtree()

        self.our_lsp = lsp.OwnLSP(inst, lindex)
        self.our_lsp.sched_gen(2)

    def __str__ (self):
        return "UpdateProcess(L{})".format(self.lindex + 1)

    def cmp_lsp(self, alsp, blsp):                          # pylint: disable=R0911
        try:
            if alsp and not blsp:
                return NEWER
            elif not alsp and blsp:
                return OLDER
            elif not alsp and not blsp:
                return SAME
            elif alsp.seqno > blsp.seqno:
                return NEWER
            elif alsp.seqno < blsp.seqno:
                return OLDER
            elif alsp.lifetime == 0 and blsp.lifetime:
                return NEWER
            elif blsp.lifetime == 0 and alsp.lifetime:
                return OLDER
            return SAME
        except Exception:
            debug_exception()

    def lsp_confusion (self, link, frame, dblsp, pdubuf, tlvs):
        """7.3.162."""
        # XXX
        pass

    def receive_other_zero_lifetime (self, link, frame, dblsp, pdubuf, tlvs):
        """Enter with db locked"""
        #--------------------
        # ISO10589: 7.3.16.4
        #--------------------

        # a) not in DB.
        if not dblsp:
            # XXX send ack on link do not retain
            return

        dbhdr = dblsp.lsphdr
        # result = self.cmp_lsp(frame, dbhdr)

        # b)
        # 1) newer
        if frame.seqno > dbhdr.seqno or (frame.seqno == dbhdr.seqno and dbhdr.lifetime):
            dblsp.update(pdubuf, tlvs)

            linkdb = link.linkdb
            linkdb.set_all_srm(dblsp, link)
            link.clear_srm_flag(dblsp)
            if link.is_p2p():
                link.set_ssn_flag(dblsp)
            linkdb.clear_all_ssn(dblsp, link)

        # 2) same
        elif frame.seqno == dbhdr.seqno and dbhdr.lifetime == 0:
            link.clear_srm_flag(dblsp)
            if link.is_p2p():
                link.set_ssn_flag(dblsp)
        # 3) older
        else:
            link.set_srm_flag(dblsp)
            link.clear_ssn_flag(dblsp)

    def get_lsp_segment (self, lspid):
        with self.dblock:
            try:
                return self.dbhash[lspid]
            except KeyError:
                return None

    def update_own_lsp (self, pdubuf, tlvs, oldseqno=None):
        with self.dblock:
            return self._update_own_lsp(pdubuf, tlvs, oldseqno)

    def remove_lsp (self, lspseg):
        lspid = lspseg.get_lspid()
        with self.dblock:
            if lspid in self.dbhash:
                del self.dbhash[lspid]

    def csnp_iter (self):
        with self.dblock:
            keys = sorted(self.dbhash.keys())
            for key in keys:
                lspseg = self.dbhash[key]
                hdr = lspseg.lsphdr
                lifetime = lspseg.lifetime.timeleft()
                yield tlv.SNPEntryStruct.pack(lifetime,
                                              stringify3(hdr.lspid),
                                              hdr.seqno,
                                              hdr.checksum)

    def _update_own_lsp (self, pdubuf, tlvs, oldseq=None):
        # Increment the seqno, set new lifetime, calc checksum and flood.
        frame = util.cast_as(pdubuf, pdu.LSPPDU)
        lspid = stringify3(frame.lspid)
        ckoff = pdu.LSPPDU.lspid.offset                     # pylint: disable=E1101

        # If we aren't forcing an update and the LSP contents are the same we are done.
        try:
            dblsp = self.dbhash[lspid]
        except KeyError:
            dblsp = None
        force = oldseq is not None
        if not force and dblsp and pdubuf[ckoff:] == dblsp.pdubuf[ckoff:]:
            return

        if not force:
            frame.seqno += 1
        elif dblsp and dblsp.lsphdr.lifetime != 0 and frame.lifetime == 0:
            # Don't update the seqno as zero lifetime is enough to catch-up
            pass
        else:
            frame.seqno = oldseq + 1

        assert frame.seqno                                  # XXX deal with rollover
        frame.checksum = 0
        # XXX what if we are purging our own?
        if not force or frame.lifetime != 0:
            frame.lifetime = 30 # lsp.MAX_AGE
        frame.checksum = iso_cksum(pdubuf[ckoff:], 12)

        if dblsp:
            fstr = "force " if force else ""
            logger.info("{}: {}updating own LSP segment: {} from: {}", self, fstr, dblsp, frame)
            dblsp.update(pdubuf, tlvs)
        else:
            if frame.lifetime == 0:
                # 17.3.16.4: a
                # XXX send ack on link do not retain
                logger.info("{}: (XXX not impl.) acking own LSP segment: from: {}", self, frame)
                return
            logger.info("{}: adding own LSP segment: from: {}", self, frame)
            dblsp = lsp.LSPSegment(self.inst, self.lindex, pdubuf, tlvs)
            self.dbhash[lspid] = dblsp
        self.inst.linkdb.set_all_srm(dblsp)

    def receive_lsp (self, link, unused_pkt, pdubuf, frame, tlvs):        # pylint: disable=R0912,R0914,R0915
        if len(pdubuf) > clns.receiveLSPBufferSize():
            # ISO 7.3.14.2 - Treat as invalid checksum
            logger.info("TRAP corruptedLSPReceived: {} dropping", link)
            return

        lspbuf = pdubuf[sizeof(pdu.CLNSHeader):]
        if frame.lifetime:
            cksum = iso_cksum(lspbuf[4:])
            if cksum:
                import pdb
                pdb.set_trace()
                logger.info("TRAP corruptedLSPReceived: {} got 0x{:04X} expect 0x{:04X} dropping",
                            link, cksum, frame.checksum)
                return

        #------------------------------------------------------------
        # ISO10589: 7.3.15.1 "Action on receipt of a link state PDU"
        #------------------------------------------------------------

        # 1-8 done in receive by the link code

        # 9)
        if tlv.TLV_LSP_BUF_SIZE in tlvs:
            value = tlvs[tlv.TLV_LSP_BUF_SIZE].value
            if value != clns.originatingLxLSPBufferSize(self.lindex):
                logger.info("TRAP: originatingLSPBufferSizeMismatch: {}", value)

        lspid = stringify3(frame.lspid)
        with self.dblock:
            if lspid in self.dbhash:
                dblsp = self.dbhash[lspid]
            else:
                dblsp = None

            # Is this our LSP?
            ours = (lspid[:clns.CLNS_SYSID_LEN] == self.inst.sysid)

            # b) If the LSP has zero Remaining Lifetime, perform the actions described in
            #    7.3.16.4. -- for LSPs not ours this is the same as normal handling
            #    except that we do not add a missing LSP segment, instead we acknowledge
            #    receipt only.

            if dblsp:
                result = self.cmp_lsp(frame, dblsp.lsphdr)
            else:
                result = NEWER

            linkdb = link.linkdb
            if ours:
                pnid = tlvrdb(lspid[7])
                if not pnid:
                    pnlink = None
                    unsupported = False                     # Always support our non-pn LSP
                else:
                    pnlink = linkdb.get_link_by_circuit_id(self.lindex, pnid)
                    unsupported = not dblsp or not pnlink.is_dis()

                # c) Ours, but we don't support, and not expired, perform 7.3.16.4 purge.
                #    If ours not supported and expired we will simply be ACKing the receipt
                #    below under e1.
                if unsupported and frame.lsphdr.lifetime:
                    if dblsp:
                        assert result == NEWER
                        assert dblsp.lsphdr.lifetime == 0
                    else:
                        dblsp = lsp.LSPSegment(self.inst, self.lindex, pdubuf, tlvs)
                        self.dbhash[lspid] = dblsp
                        dblsp.force_purge_ours()
                        return

                # d) Ours, supported and wire is newer, need to increment our copy per 7.3.16.1
                if not unsupported and result == NEWER:
                    # If this is supported we better have a non-expired LSP in the DB.
                    assert dblsp
                    assert dblsp.lifetime
                    self._update_own_lsp(dblsp.pdubuf, dblsp.tlvs, frame.seqno)
                    return

            # [ also: ISO 10589 17.3.16.4: a, b ]
            # e1) Newer - update db, flood and acknowledge
            #     [ also: ISO 10589 17.3.16.4: b.1 ]
            if result == NEWER:
                if dblsp:
                    logger.info("Updating LSP from {}", link)
                    dblsp.update(pdubuf, tlvs)
                else:
                    logger.info("Added LSP from {}", link)
                    if frame.lifetime == 0:
                        # 17.3.16.4: a
                        # XXX send ack on link do not retain
                        return
                    dblsp = lsp.LSPSegment(self.inst, self.lindex, pdubuf, tlvs)
                    self.dbhash[lspid] = dblsp

                linkdb.set_all_srm(dblsp, link)
                link.clear_srm_flag(dblsp)
                if link.is_p2p():
                    link.set_ssn_flag(dblsp)
                linkdb.clear_all_ssn(dblsp, link)

            # e2) Same - Stop sending and Acknowledge
            #     [ also: ISO 10589 17.3.16.4: b.2 ]
            elif result == SAME:
                link.clear_srm_flag(dblsp)
                if link.is_p2p():
                    link.set_ssn_flag(dblsp)

            # e3) Older - Send and don't acknowledge
            #     [ also: ISO 10589 17.3.16.4: b.3 ]
            else:
                link.set_srm_flag(dblsp)
                link.clear_ssn_flag(dblsp)

    def receive_snp (self, link, snphdr, tlvs):             # pylint: disable=R0912,R0914,R0915
        is_csnp = (snphdr.clns_pdu_type in clns.PDU_TYPE_CSNP_LX)
        if is_csnp:
            mentioned = set()
            # util.debug_after(5)
        with self.dblock:
            #-----------------------
            # ISO10589: 7.3.15.2: b
            #-----------------------
            for snpval in tlvs[tlv.TLV_SNP_ENTRIES]:
                for snp in snpval.values:
                    if is_csnp:
                        mentioned.add(snp.lspid)
                    lspid = snp.lspid
                    if lspid in self.dbhash:
                        lspseg = self.dbhash[lspid]
                        lsphdr = lspseg.lsphdr
                    else:
                        lspseg = None
                        lsphdr = None

                    # Check if this is our LSP, if so regenerate our LSP, right?
                    # We don't do anything with this apparently.
                    # ours = (lspid[:clns.CLNS_HDR_SYSID_LEN] == self.inst.sysid)

                    # 7.3.15.2: b1
                    result = self.cmp_lsp(snp, lsphdr)
                    if result == SAME:
                        # 7.3.15.2: b2 ack received, stop sending on p2p
                        if link.is_p2p():
                            link.clear_srm_flag(lspseg)
                    elif result == OLDER:
                        # 7.3.15.2: b3 flood newer from our DB
                        link.clear_ssn_flag(lspseg)
                        link.set_srm_flag(lspseg)
                    else:
                        assert result == NEWER
                        if lspseg:
                            # 7.3.15.2: b4 Request newer
                            link.set_ssn_flag(lspseg)
                            if link.is_p2p():
                                link.clear_srm_flag(lspseg)
                        else:
                            # 7.3.15.2: b5 Add zero seqno segment for missing
                            if snp.seqno and snp.lifetime and snp.checksum:
                                lsphdr = pdu.LSPZeroSegFrame()
                                util.memcpy(lsphdr.lspid, snp.lspid)
                                lsphdr.seqno = 0
                                lsphdr.checksum = snp.checksum
                                lsphdr.lifetime = snp.lifetime
                                lspseg = lsp.LSPSegment(self.inst,
                                                        self.lindex,
                                                        lsphdr,
                                                        # buffer3(lsphdr),
                                                        None)
                                self.dbhash[lspid] = lspseg
                                link.set_ssn_flag(lspseg)

            #----------------------------------------------------
            # ISO10589: 7.3.15.2: c Flood neighbors missing LSPs
            #----------------------------------------------------
            if is_csnp:
                lspidlist = sorted(self.dbhash.keys())
                startid = stringify3(snphdr.start_lspid)
                endid = stringify3(snphdr.end_lspid)
                for lspid in lspidlist:
                    if lspid < startid:
                        continue
                    if lspid > endid:
                        break
                    if lspid not in mentioned:
                        lspseg = self.dbhash[lspid]
                        try:
                            if lspseg.lsphdr.seqno and lspseg.lsphdr.lifetime:
                                link.set_srm_flag(lspseg)
                        except Exception:
                            debug_exception()

    def dis_change (self, link, lindex, dis):
        # We need to update our LSP to point at the new DIS (or None)
        logger.info("{}: DIS CHANGE: {}: {}: {}", self, link, lindex, dis)
        self.our_lsp.sched_gen(0.1)


__author__ = 'Christian Hopps'
__date__ = 'November 2 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
