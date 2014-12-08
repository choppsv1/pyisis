#
# November 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.
from __future__ import absolute_import, division, nested_scopes, print_function, unicode_literals

from ctypes import addressof, cast, memmove, sizeof, string_at, POINTER
import pdb
import sys
import time
import threading
import traceback


def as_string (cobj):
    return string_at(addressof(cobj), sizeof(cobj))


def cast_as (bufptr, ctype):
    return cast(bufptr, POINTER(ctype)).contents


def copy_as (s, ctype):
    cobj = ctype()
    try:
        if sys.version_info >= (3, 0):
            s = bytes(s[:sizeof(cobj)])
        else:
            s = str(s[:sizeof(cobj)])
        memmove(addressof(cobj), s, sizeof(cobj))
    except Exception:
        debug_exception()
    return cobj


def copy_cobj (s, ctype):
    cobj = ctype()
    try:
        memmove(addressof(cobj), addressof(s), sizeof(cobj))
    except Exception:
        debug_exception()
    return cobj


# def _copy_as (bufptr, buftype):
#     # This seems convoluted
#     sz = sizeof(buftype)
#     bufcopy = buffer(bufptr)[:sz]
#     val = cast(str(bufcopy), POINTER(buftype)).contents
#     pdb.set_trace()
#     return val


def memcpy (dst, src):
    try:
        if sizeof(dst) != len(src):
            debug_after(1)
        assert sizeof(dst) == len(src)
        if sys.version_info >= (3, 0):
            memmove(dst, bytes(src), len(src))
        else:
            memmove(dst, src, len(src))
    except Exception:
        debug_exception()

from pyisis.bstr import bchr                                # pylint: disable=E0611

if sys.version_info >= (3, 0):
    # Python 3.4
    stringify3 = bytes
    xrange3 = range

    chr3 = bchr

    def _chr3 (val):
        # Convert an integer into a byte string
        return bytes((val,))

    def buffer3 (val, off=None, sz=None):
        rv = memoryview(val)
        if off is not None:
            if sz is not None:
                return rv[off:off + sz]
            else:
                return rv[off:]
        else:
            return rv

    def tlvrdb (val):
        # In python3 byte strings return integers when indexed
        return val

    tlvwrb = tlvrdb

    monotonic = time.monotonic                              # pylint: disable=E1101

else:
    import pyisis.lib.compat3 as compat3
    # Python 2.7
    # chr3 = chr
    chr3 = bchr
    tlvrdb = ord
    tlvwrb = bchr
    xrange3 = xrange                                        # pylint: disable=E0602

    def buffer3 (val, off=None, l=None):
        if off is not None:
            if l is not None:
                return buffer(val, off, l)                  # pylint: disable=E0602
            else:
                return buffer(val, off)                     # pylint: disable=E0602
        else:
            return buffer(val)                              # pylint: disable=E0602

    def stringify3 (b):
        return str(buffer(b))                               # pylint: disable=E0602

    monotonic = compat3.monotonic_time


def debug_exception ():
    if debug_exception.entered:
        return
    debug_exception.entered = True
    traceback.print_exc()
    pdb.set_trace()
debug_exception.entered = False


class CPUTimer (object):
    def __init__ (self):
        if sys.version_info >= (3, 0):
            self.start = time.process_time()                # pylint: disable=E1101
        else:
            self.start = time.clock()

    def elapsed (self):
        if sys.version_info >= (3, 0):
            return time.process_time() - self.start         # pylint: disable=E1101
        else:
            return time.clock() - self.start

    def __str__ (self):
        return "{:f} cpu seconds".format(self.elapsed())


class Lifetime (object):
    """A way to track the lifetime left of an object"""
    def __init__ (self, lifetime):
        self.lifetime = float(lifetime)
        self.timestamp = monotonic()

    def reset (self, lifetime):
        self.lifetime = float(lifetime)
        self.timestamp = monotonic()

    def expire_at (self):
        return self.timestamp + self.lifetime

    def timeleft (self):
        elapsed = monotonic() - self.timestamp
        left = self.lifetime - elapsed
        if left <= 0:
            return 0
        # We actually don't want to do this as other timer functions may be int seconds based.
        # elif left < 1:
        #     return 1
        else:
            return int(left)


class QueryLock (object):
    """A threading Lock that is queriable"""
    def __init__ (self):
        self.lock = threading.Lock()
        self.holding_thread = None

    def __enter__ (self):
        return self.acquire()

    def __exit__ (self, *args):
        return self.release()

    def held (self):
        """Return True if the current thread holds the lock"""
        return self.holding_thread == threading.current_thread()

    def acquire (self, blocking=True):
        self.lock.acquire(blocking)
        self.holding_thread = threading.current_thread()

    def release (self):
        assert self.held
        self.holding_thread = None
        self.lock.release()


def debug_after (count=1):
    debug_after.entered += 1
    if debug_after.entered != count:
        return
    debug_after.entered = 0
    pdb.set_trace()
debug_after.entered = 0


class NoLock (object):
    def __enter__ (self):
        return

    def __exit__ (self, *args):
        return


__author__ = 'Christian Hopps'
__date__ = 'November 2 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
