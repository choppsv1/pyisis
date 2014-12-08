#
# November 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.
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
