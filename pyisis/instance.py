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
import pyisis.clns as clns
import pyisis.update as update
import pyisis.link as link
import pyisis.lib.timers as timers
import socket


class Instance (object):
    def __init__ (self, is_type, areaid, sysid, priority):
        self.is_type = is_type
        self.areaid = areaid
        self.sysid = sysid
        self.overload = False
        self.linkdb = link.LinkDB(self)
        self.priority = priority
        self.update = [ None, None ]
        self.timerheap = timers.TimerHeap("Instance")
        if self.is_type & clns.CTYPE_L1:
            self.update[0] = update.UpdateProcess(self, 0)
        if self.is_type & clns.CTYPE_L2:
            self.update[1] = update.UpdateProcess(self, 1)
        self.hostname = socket.gethostname().split('.')[0]
        self.hostname = self.hostname.encode('ascii')


__author__ = 'Christian Hopps'
__date__ = 'November 1 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
