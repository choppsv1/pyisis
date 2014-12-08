"""
Stack tracer for multi-threaded applications.


Usage:

import stacktracer
stacktracer.start_trace("trace.html",interval=5,auto=True) # Set auto flag to always update file!
....
stacktracer.stop_trace()
"""
from __future__ import absolute_import, division, nested_scopes, print_function # , unicode_literals

import sys
import traceback
from pygments import highlight
from pygments.lexers.python import PythonLexer
from pygments.formatters.html import HtmlFormatter
from pyisis.lib.threads import thread_mapping

# Taken from http://bzimmer.ziclix.com/2008/12/17/python-thread-dumps/


def stacktraces():
    code = []
    for threadId, stack in sys._current_frames().items():  # pylint: disable=W0212
        try:
            name = thread_mapping[threadId].name
        except KeyError:
            name = "ThreadID: {}".format(threadId)
        code.append("\n# " + name)
        for filename, lineno, name, line in traceback.extract_stack(stack):
            code.append('File: "%s", line %d, in %s' % (filename, lineno, name))
            if line:
                code.append("  %s" % (line.strip()))

    return highlight("\n".join(code), PythonLexer(), HtmlFormatter(
        full=False,
        # style="native",
        noclasses=True,
    ))


# This part was made by nagylzs
import os
import time
import threading


class TraceDumper(threading.Thread):
    """Dump stack traces into a given file periodically."""
    def __init__(self, fpath, interval, auto):
        """
        @param fpath: File path to output HTML (stack trace file)
        @param auto: Set flag (True) to update trace continuously.
            Clear flag (False) to update only if file not exists.
            (Then delete the file to force update.)
        @param interval: In seconds: how often to update the trace file.
        """
        assert(interval > 0.1)
        self.auto = auto
        self.interval = interval
        self.fpath = os.path.abspath(fpath)
        self.stop_requested = threading.Event()
        threading.Thread.__init__(self)
        self.name = "TraceDumper"

    def run(self):
        thread_mapping[threading.current_thread().ident] = threading.current_thread()
        while not self.stop_requested.isSet():
            time.sleep(self.interval)
            if self.auto or not os.path.isfile(self.fpath):
                self.stacktraces()

    def stop(self):
        self.stop_requested.set()
        self.join()
        try:
            if os.path.isfile(self.fpath):
                os.unlink(self.fpath)
        except Exception:
            pass

    def stacktraces(self):
        fout = open(self.fpath, "wb+")  # pylint: disable=W0141  # pylint: disable=W1501
        try:
            output = stacktraces()
            fout.write(bytes(output, 'ascii'))
        finally:
            fout.close()


_tracer = None


def trace_start(fpath, interval=5, auto=True):
    """Start tracing into the given file."""
    global _tracer                                          # pylint: disable=W0603
    if _tracer is None:
        _tracer = TraceDumper(fpath, interval, auto)
        _tracer.setDaemon(True)
        _tracer.start()
    else:
        raise Exception("Already tracing to {}".format(_tracer.fpath))


def trace_stop():
    """Stop tracing."""
    global _tracer                                          # pylint: disable=W0603
    if _tracer is None:
        raise Exception("Not tracing, cannot stop.")
    else:
        _tracer.stop()
        _tracer = None
