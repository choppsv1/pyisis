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
from setuptools import setup, Extension
import sys

if sys.version_info >= (3, 0):
    bstr = Extension('pyisis.bstr', sources=['src/bstr.c'])
    extra = {
        'ext_modules': [bstr],
        'entry_points': { "console_scripts": [ "pyisis = pyisis.main:main", ] },
    }
else:
    bstr = Extension('pyisis.bstr', sources=['src/bstr.c'])
    extra = {
        'ext_modules': [bstr],
        'entry_points': { "console_scripts": [ "pyisis = pyisis.main:main", ] },
    }

setup (name='pyisis',                                       # pylint: disable=W0142
       version='1.0',
       description='IS-IS [partial ISO10589:2002]',
       author='Christian E. Hopps',
       author_email='chopps@gmail.com',
       packages=['pyisis'],
       **extra)
