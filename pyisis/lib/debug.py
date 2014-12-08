#
# November 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.
from __future__ import absolute_import, division, nested_scopes, print_function, unicode_literals
import pyisis.clns as clns

FLAGDBG = False
PKTDBG = True
PKTDBGTYPE = {
    # clns.PDU_TYPE_IIH_LAN_L1: True,
    clns.PDU_TYPE_CSNP_L1: True,
    # clns.PDU_TYPE_CSNP_L2: True,
    clns.PDU_TYPE_PSNP_L1: True,
    # clns.PDU_TYPE_PSNP_L2: True,
    # clns.PDU_TYPE_LSP_L1: True,
    # clns.PDU_TYPE_LSP_L2: True,
}


def is_dbg (frame):
    return PKTDBG and (not frame or frame.clns_pdu_type in PKTDBGTYPE)


def is_dbg_type (pdu_type):
    return PKTDBG and pdu_type in PKTDBGTYPE


__author__ = 'Christian Hopps'
__date__ = 'November 2 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
