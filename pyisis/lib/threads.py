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
    def __init__(self, name, interval, function, *args, **kwargs):
        super(Timer, self).__init__(interval, function, args, kwargs)
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


__author__ = 'Christian Hopps'
__date__ = 'November 8 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
