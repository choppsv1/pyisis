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

from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
import pyisis.lib.timers as timers
import time

from pyisis.lib.util import xrange3


def test_simple_timers ():
    done = [ x for x in xrange3(0, 10) ]

    def expire ():
        done.pop()

    print("Create Heap")
    heap = timers.TimerHeap("Timer Heap")

    print("Create Timer")

    for x in xrange3(0, 10):
        timers.Timer(heap, .25, expire).start((x + 1) / 100)

    while done:
        time.sleep(.01)
    print("Expired all")


def test_stop_timer ():
    def expire_assert ():
        assert False

    print("Create Heap")
    heap = timers.TimerHeap("TimerHeap")

    print("Create Timer")
    timer = timers.Timer(heap, .25, expire_assert)
    timer.start(2)
    timer.stop()


def test_restart_timer ():
    done = [1]

    def expire ():
        done.pop()

    print("Create Heap")
    heap = timers.TimerHeap("TimerHeap")

    print("Create Timer")
    timer = timers.Timer(heap, .25, expire)
    timer.start(2)
    timer.start(1)

__author__ = 'Christian Hopps'
__date__ = 'November 1 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
