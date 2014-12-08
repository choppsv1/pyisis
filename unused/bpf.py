#
# October 30 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.

# BIOCGBLEN = _IOR('B', 102, sizeof(c_uint))
# BIOCSBLEN = _IOWR('B', 102, sizeof(c_uint))
# # BIOCSETF = _IOW('B', 103, struct bpf_program)
# BIOCFLUSH = _IO('B', 104)
# BIOCPROMISC = _IO('B', 105)
# BIOCGDLT = _IOR('B', 106, sizeof(c_uint))
# BIOCGETIF = _IOR('B', 107, 16) # struct ifreq)
# BIOCSETIF = _IOW('B', 108, 16) # struct ifreq)
# # BIOCSRTIMEOUT = _IOW('B', 109, struct timeval)
# # BIOCGRTIMEOUT = _IOR('B', 110, struct timeval)
# BIOCGSTATS = _IOR('B', 111, struct bpf_stat)
# BIOCIMMEDIATE = _IOW('B', 112, sizeof(c_uint))
# # BIOCVERSION = _IOR('B', 113, struct bpf_version)
# BIOCGRSIG = _IOR('B', 114, sizeof(c_uint))
# BIOCSRSIG = _IOW('B', 115, sizeof(c_uint))
# BIOCGHDRCMPLT = _IOR('B', 116, sizeof(c_uint))
# BIOCSHDRCMPLT = _IOW('B', 117, sizeof(c_uint))
# BIOCGSEESENT = _IOR('B', 118, sizeof(c_uint))
# BIOCSSEESENT = _IOW('B', 119, sizeof(c_uint))
# BIOCSDLT = _IOW('B', 120, sizeof(c_uint))
# # BIOCGDLTLIST = _IOWR('B', 121, struct bpf_dltlist)
# # BIOCSETFNR = _IOW('B', 126, struct bpf_program)

BIOCGBLEN = 0x40044266
BIOCSBLEN = 0xc0044266
BIOCSETF = 0x80104267
BIOCFLUSH = 0x20004268
BIOCPROMISC = 0x20004269
BIOCGDLT = 0x4004426a
BIOCGETIF = 0x4020426b
BIOCSETIF = 0x8020426c
BIOCSRTIMEOUT = 0x8010426d
BIOCGRTIMEOUT = 0x4010426e
BIOCGSTATS = 0x4008426f
BIOCIMMEDIATE = 0x80044270
BIOCVERSION = 0x40044271
BIOCGRSIG = 0x40044272
BIOCSRSIG = 0x80044273
BIOCGHDRCMPLT = 0x40044274
BIOCSHDRCMPLT = 0x80044275
BIOCGSEESENT = 0x40044276
BIOCSSEESENT = 0x80044277
BIOCSDLT = 0x80044278
BIOCGDLTLIST = 0xc00c4279
BIOCSETFNR = 0x8010427e

__author__ = 'Christian Hopps'
__date__ = 'October 30 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
