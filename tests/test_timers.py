#
# November 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.
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
