#
# October 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.
#
from __future__ import absolute_import, division, nested_scopes, print_function, unicode_literals
import argparse
from pyisis.instance import Instance
import pyisis.clns as clns
import pyisis.lib.threads as threads
import logbook
import pdb
import signal
import sys
# bytearray, from_buffer, from_buffer_copy

# logging.basicConfig(level=logging.DEBUG)
logger = logbook.Logger(__name__)

import pyisis.lib.stacktracer as stacktracer
# Set auto flag to always update file!
stacktracer.trace_start("trace.html", interval=5, auto=True)


# Hanlde ^\ to break into pdb
def sigquit_handler (signum, unused_frame):
    if signum == signal.SIGQUIT:
        pdb.set_trace()
# signal.signal(signal.SIGQUIT, sigquit_handler)

debug_inst = None
"""A singl global (bad) used to track an instance"""


def main ():
    global debug_inst                    # pylint: disable=W0603

    # Only run this is we are invoked as the program, otherwise trips up unit tests
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--areaid', default='00', help='The Area id')
    parser.add_argument('-p', '--priority', type=int, default=64, help='Priority to run links at')
    parser.add_argument('-s', '--sysid', help='The system id')
    parser.add_argument('--is-type', default='l1', choices=["l1", "l2", "l12"],
                        help='the is-type [l1, l2, l12]')
    parser.add_argument('interfaces',
                        metavar='INTF',
                        nargs='+',
                        help='Interfaces to run on')

    if hasattr(sys, "_called_from_test"):
        args = parser.parse_args([])
        return

    #---------------------
    # Parse the arguments
    #---------------------

    args = parser.parse_args()

    if args.is_type == "l1":
        is_type = clns.CTYPE_L1
    elif args.is_type == "l2":
        is_type = clns.CTYPE_L2
    elif args.is_type == "l12":
        is_type = clns.CTYPE_L12

    sysid = clns.iso_encode(args.sysid)
    if len(sysid) != 6:
        print("SysID must be 6 bytes")
        sys.exit(1)

    inst = Instance(is_type, clns.iso_encode(args.areaid), sysid, args.priority)
    debug_inst = inst
    for ifname in args.interfaces:
        inst.linkdb.add_link(ifname)

    try:
        while True:
            inst.linkdb.process_packets()
    except Exception as ex:
        logger.error("UNEXPECTED EXCEPTION: {}", ex)
    except:
        logger.error("UNEXPECTED EXCEPTION")

if __name__ == "__main__":
    main()

__author__ = 'Christian Hopps'
__date__ = 'October 24 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
