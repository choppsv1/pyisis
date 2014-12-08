#
# Adapted from C in RFC 1008: 7.2.1
#
# This adaptation is placed in the public domain.
#
from __future__ import absolute_import, division, nested_scopes, print_function, unicode_literals
try:
    # Deal with python2 and python3
    xrange                                                  # pylint: disable=E0602
except NameError:
    # Python3
    xrange3 = range

    def ord3 (val):
        return val
else:
    # Python2
    xrange3 = xrange                                        # pylint: disable=E0602

    def ord3 (val):
        return ord(val)


MODX = 4102


def iso_cksum (mess, ckoff=None):
    # RFC1008 calls this k and points to the 2nd byte (calling it the first)
    # so ckoff = k -1, our ckoff points at the actual first byte of the chksum
    # or None if not required.

    p3 = len(mess)

    # We can't modify the data so we look for it later while iterating
    # if k > 0:
    #     mess[k - 1] = 0
    #     mess[k] = 0
    c0 = 0
    c1 = 0
    p1 = 0

    # Outer sum accumulation loop
    while p1 < p3:
        p2 = p1 + MODX
        if p2 > p3:
            p2 = p3

        # Inner sum accumulation loop
        for p in xrange3(p1, p2):
            # if these are the cksum bytes skip addition (treat as zero)
            if not ckoff or (p != ckoff and p != (ckoff + 1)):
                c0 = c0 + ord3(mess[p])
            c1 = c1 + c0

        # Adjust accumulated sums to mod 255
        c0 = c0 % 255
        c1 = c1 % 255
        p1 = p2

    # concatenate c1 and c0
    ip = ((c1 & 0xFF) << 8) + (c0 & 0xFF)
    if ckoff is None:
        return ip

    # iq = ((mlen - k) * c0 - c1) % 255
    iq = ((p3 - (ckoff + 1)) * c0 - c1) % 255
    if iq <= 0:
        iq = iq + 255
    # mess[ckoff] = chr(iq)     # Can't modify data

    ir = (510 - c0 - iq)
    if ir > 255:
        ir = ir - 255
    # mess[ckoff + 1] = chr(ir)         # Can't modify data

    # Return in host order
    return ((iq & 0xFF) << 8) | (ir & 0xFF)


__author__ = 'Christian Hopps'
__date__ = 'November 2 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
