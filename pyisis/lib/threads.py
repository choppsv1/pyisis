#
# November 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.
from __future__ import absolute_import, division, nested_scopes, print_function, unicode_literals
import sys
import threading

if sys.version_info >= (3, 0):
    from threading import Timer as ThreadTimer
    from _thread import get_ident
else:
    from threading import _Timer as ThreadTimer
    from thread import get_ident

thread_mapping = { get_ident(): threading.current_thread() }


class Timer (ThreadTimer):
    def __init__(self, name, interval, function, args=None):
        super(Timer, self).__init__(interval, function, args)
        self.basename = "TimerThread({})".format(name)
        self.name = "Init-" + self.basename
        self.daemon = True

    def run (self):
        thread_id = get_ident()
        thread_mapping[thread_id] = self

        self.name = "Running-" + self.basename
        rv = super(Timer, self).run()
        self.name = "Ran-" + self.basename
        return rv

    def __str__ (self):
        return self.name


class PersistentTimer (ThreadTimer):
    def __init__(self, name, function, args=None):
        # XXX this isn't actually functional
        super(PersistentTimer, self).__init__(0, function, args)
        self.basename = "TimerThread({})".format(name)
        self.name = "Init-" + self.basename
        self.daemon = True

        self.lock = threading.Lock()
        self.start_event = threading.Event()
        self.expire_event = threading.Event()
        self.seqno = 0

        self.interval = None

    def wait_for_start (self):
        self.start_event.wait()
        with self.lock:
            assert self.interval is not None

    def start_timer (self, interval):
        with self.lock:
            self.interval = interval
            self.start_event.set()

    def cancel_timer (self):
        with self.lock:
            self.interval = None

    def wait_for_expire (self):
        self.expire_event.wait()
        with self.lock:
            if self.interval is None:
                return

    def run (self):
        thread_id = get_ident()
        thread_mapping[thread_id] = self

        self.name = "Running-" + self.basename
        rv = super(Timer, self).run()
        self.name = "Ran-" + self.basename
        return rv

    def __str__ (self):
        return self.name

__author__ = 'Christian Hopps'
__date__ = 'November 8 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
