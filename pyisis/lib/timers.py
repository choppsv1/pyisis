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
import heapq
import logbook
import random
import pdb
import time
import threading
import functools
try:
    from pyisis.lib.util import debug_exception
    from pyisis.lib.threads import Timer as ThreadTimer
except ImportError:

    def debug_exception ():
        pdb.set_trace()

logger = logbook.Logger(__name__)


@functools.total_ordering
class Timer (object):
    def __init__ (self, heap, jitter, action, *args, **kwargs):
        self.jitter = jitter
        self.action = action
        self.args = args
        self.kwargs = kwargs
        self.expire = None
        self.timerheap = heap

    def run (self):
        try:
            self.action(*self.args, **self.kwargs)
        except Exception as ex:
            logger.error("Uncaught exception within timer action: {}", ex)
            debug_exception()
            raise

    def __hash__ (self):
        return id(self)

    def __cmp__ (self, other):
        if other is None:
            return -1
        return self.expire - other.expire

    def __lt__ (self, other):
        if other is None:
            return -1
        return self.expire < other.expire

    def __eq__ (self, other):
        return id(self) == id(other)

    def __ne__ (self, other):
        return id(self) != id(other)

    def scheduled (self):
        return self.expire is not None

    def start (self, expire):
        self.stop()

        self.expire = time.time()
        if self.jitter:
            self.expire += expire * (1 - random.random() * self.jitter)
        else:
            self.expire += expire

        self.timerheap.add(self)

    def stop (self):
        self.timerheap.remove(self)
        self.expire = None

functools.cmp_to_key(Timer.__cmp__)


class TimerHeap (object):
    def __init__ (self, desc):
        self.desc = desc
        self.timers = {}
        self.heap = []
        self.lock = threading.Lock()
        self.rtimer = None
        self.expiring = False

    def add (self, timer):
        """Add a timer to the heap"""
        with self.lock:
            if self.heap:
                top = self.heap[0]
            else:
                top = None
            if timer in self.timers:
                self._remove(timer)

            self.timers[timer] = timer
            heapq.heappush(self.heap, timer)

            # Check to see if we need to reschedule our main timer.
            # Only do this if we aren't expiring in the other thread.
            if self.heap[0] != top and not self.expiring:
                if self.rtimer:
                    self.rtimer.cancel()
                    # self.rtimer.join()
                    self.rtimer = None

            # If we are expiring timers right now then that will reschedule
            # as appropriate otherwise let's start a timer if we don't have
            # one
            if self.rtimer is None and not self.expiring:
                top = self.heap[0]
                ival = top.expire - time.time()
                if ival < 0:
                    ival = 0
                self.rtimer = ThreadTimer(self.desc, ival, self.expire)
                self.rtimer.start()

    def expire (self):
        try:
            # Set expiring variable and forget old timer.
            with self.lock:
                self.expiring = True
                self.rtimer = None

            while True:
                with self.lock:
                    if not self.heap:
                        return

                    top = self.heap[0]
                    ctime = time.time()
                    if top.expire > ctime:
                        return

                    # remove the timer
                    expired = heapq.heappop(self.heap)
                    del self.timers[expired]

                # Run the expired timer outside of the lock.
                expired.expire = None
                expired.run()
        except Exception as ex:
            logger.error("Unexpected Exception: {}", ex)
            debug_exception()
        finally:
            # This is never set while expiring is True
            assert self.rtimer is None

            with self.lock:
                # Now grab the next timer and set our real-time timer and unset expiring
                if self.heap:
                    top = self.heap[0]
                    ival = top.expire - time.time()
                    if ival < 0:
                        ival = 0
                    self.rtimer = ThreadTimer(self.desc, ival, self.expire)
                    self.rtimer.start()
                self.expiring = False

    def _remove (self, timer):
        """Remove timer from heap lock and presence are assumed"""
        assert timer.timerheap == self
        del self.timers[timer]
        if timer not in self.heap:
            pdb.set_trace()
        self.heap.remove(timer)
        heapq.heapify(self.heap)

    def remove (self, timer):
        """Remove a timer from the heap"""
        with self.lock:
            # This is somewhat expensive as we have to heapify.
            if timer in self.timers:
                self._remove(timer)


__author__ = 'Christian Hopps'
__date__ = 'November 1 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
