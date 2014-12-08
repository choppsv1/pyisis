#
# November 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.
#
import sys

collect_ignore = [ "setup.py", "build" ]


def pytest_configure():
    sys._called_from_test = True  # pylint: disable=W0212


def pytest_unconfigure():
    if hasattr(sys, "_called_from_test"):
        del sys._called_from_test
