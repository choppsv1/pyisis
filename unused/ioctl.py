#
# Copyright (c) 2014 by Christian E. Hopps.
# All Rights Reserved.
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
#

IOCPARM_MASK = 0x1fff
IOC_VOID = 0x20000000
IOC_IN = 0x80000000
IOC_OUT = 0x40000000


def _IOC(inout, group, num, length):
    return (inout | ((length & IOCPARM_MASK) << 16) | (ord(group) << 8) | (num))


def _IO(g, n):
    return _IOC(IOC_VOID, g, n, 0)


def _IOR(g, n, t):
    return _IOC(IOC_OUT, g, n, t)


def _IOW(g, n, t):
    return _IOC(IOC_IN, g, n, t)


def _IOWR(g, n, t):
    return _IOC(IOC_IN | IOC_OUT, g, n, t)

__author__ = 'Christian Hopps'
__date__ = 'October 30 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
