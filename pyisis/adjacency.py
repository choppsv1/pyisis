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
from pyisis.lib.util import stringify3

import logbook
import threading
import pyisis.clns as clns
import pyisis.lib.timers as timers
import pyisis.tlv as tlv

logger = logbook.Logger(__name__)


class AdjLinkDB (object):
    def __init__ (self, link, lindex):
        self.bysnpa = {}
        self.adjlist = []
        self.link = link
        self.lindex = lindex
        self.rlock = threading.RLock()
        self.timerheap = timers.TimerHeap("Level-{} AdjDB".format(lindex + 1))

    def __enter__ (self):
        return self.rlock.__enter__()

    def __exit__ (self, *args):
        return self.rlock.__exit__(*args)

    def get_neighbors_value (self):
        # XXX this won't work if too many neighbors
        vlist = []
        with self.rlock:
            for adj in self.adjlist:
                if adj.state == adj.ADJ_STATE_DOWN:
                    continue
                vlist.append(adj.snpa)
        return b"".join(vlist)

    def neighbor_iih_tlv_iter (self):
        with self.rlock:
            for adj in self.adjlist:
                if adj.state != Adjacency.ADJ_STATE_DOWN:
                    yield adj.snpa

    def has_up_adjacency (self, snpa):
        # Need to handle p2p link here.
        with self.rlock:
            return (snpa in self.bysnpa and
                    self.bysnpa[snpa].state == Adjacency.ADJ_STATE_UP)

    def up_iter (self):
        with self:
            for adj in self.adjlist:
                if adj.state == adj.ADJ_STATE_UP:
                    yield adj

    def update_adjacency (self, iih, tlvs):
        with self.rlock:
            snpa = stringify3(iih.ether_src)
            source_id = stringify3(iih.source_id)
            # snpa = bytes(buffer(iih.ether_src)
            # source_id = bytes(buffer(iih.source_id)
            try:
                adj = self.bysnpa[snpa]
            except KeyError:
                adj = Adjacency(self, snpa, source_id, iih, tlvs)
                self.bysnpa[snpa] = adj
                self.adjlist.append(adj)

                # If our new adjacency is UP then we want to run dis election.
                if adj.state == adj.ADJ_STATE_UP:
                    return True
            else:
                # If the system ID changed ignore the iih.
                if adj.sysid != source_id:
                    return False
                return adj.update(iih, tlvs)

    def expire_adjacency (self, adj):
        dis_election_change = False
        with self.rlock:
            # If this adjacency was UP then we need to rerun the DIS election.
            if adj.state == adj.ADJ_STATE_UP:
                dis_election_change = True

            adj.hold_timer.stop()
            self.adjlist.remove(adj)
            del self.bysnpa[adj.snpa]

        if dis_election_change:
            logger.info("TRAP: adjacencyStateChange: Down: {}: Hold time expired", adj)
            self.link.dis_election_info_changed(self.lindex)


class Adjacency (object):
    ADJ_STATE_DOWN = 0
    ADJ_STATE_INITIAL = 1
    ADJ_STATE_UP = 2

    def __init__ (self, adjdb, snpa, source_id, iih, tlvs):
        # Invariants
        self.adjdb = adjdb
        self.lindex = adjdb.lindex
        self.link = adjdb.link
        self.snpa = snpa
        self.sysid = source_id

        try:
            # Only LAN IIH frames have this
            self.lanid = stringify3(iih.lan_id)
        except AttributeError:
            self.lanid = None
            self.nodeid = None

        self.hold_timer = timers.Timer(adjdb.timerheap, 0, self.expire)

        self.areas = []
        self.hold_time = None
        self.priority = None
        self.state = self.ADJ_STATE_DOWN
        self.update(iih, tlvs)

    def update (self, iih, tlvs):
        dis_info_changed = False
        self.hold_time = iih.hold_time

        if self.priority != iih.priority:
            self.priority = iih.priority
            dis_info_changed = False

        # Area TLV for Level-1 IIH acceptance has guaranteed
        # that we have only 1 area TLV and a match somewhere.
        if self.lindex == 0:
            self.areas = tlvs[tlv.TLV_AREA_ADDRS][0]

        old_state = self.state
        self.state = self.ADJ_STATE_INITIAL
        for ntlv in tlvs[tlv.TLV_IS_NEIGHBORS]:
            for nbr in ntlv.addrs:
                if nbr == self.link.mac_addr:
                    self.state = self.ADJ_STATE_UP
                    break
            else:
                continue
            # We broke out of the inner loop we are done
            break

        self.hold_timer.start(self.hold_time)

        if self.state != old_state:
            if self.state == self.ADJ_STATE_UP:
                dis_info_changed = True
                logger.info("TRAP: adjacencyStateChange: Up: {}", self)
            elif old_state == self.ADJ_STATE_UP:
                dis_info_changed = True
                logger.info("TRAP: adjacencyStateChange: Down: {}", self)
        return dis_info_changed

    def expire (self):
        self.adjdb.expire_adjacency(self)

    def __str__ (self):
        return "Adjacency(snpa:{}, link:{})".format(clns.snpa_decode(self.snpa), self.link)


class LanAdjacency (object):
    def __init__ (self, iih):
        pass

__author__ = 'Christian Hopps'
__date__ = 'November 1 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
