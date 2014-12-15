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
