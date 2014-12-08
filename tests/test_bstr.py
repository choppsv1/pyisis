#
# November 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2014 by Christian E. Hopps.
# All rights reserved.
#
# REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
# CONSENT OF THE AUTHOR.


from pyisis.bstr import bchr, memspan, writev, IOV_MAX               # pylint: disable=W0611


def test_writev ():
    v = [ ("{} ".format(x)).encode('ascii') for x in range(0, 10) ]
    #v = [ x.encode('ascii') for x in v ]

    l = 0
    for x in v:
        l += len(x)

    with open("/tmp/foo", "wb") as fo:
        rv = writev(fo, v)
    assert rv == l

    tcontent = b"".join(v)
    with open("/tmp/foo", "rb") as fo:
        content = fo.read()
    assert content == tcontent


def test_writev_error ():
    v = [ ("{} ".format(x)).encode('ascii') for x in range(0, IOV_MAX + 1) ]

    # Verify IOV_MAX works
    l = 0
    for x in v[:-1]:
        l += len(x)
    with open("/tmp/foo", "wb") as fo:
        rv = writev(fo, v[:-1])
    assert rv == l

    # Verify IOV_MAX + 1 fails
    try:
        with open("/tmp/foo", "wb") as fo:
            writev(fo, v)
    except IndexError as error:
        print(error)
    else:
        assert False


def test_memspan ():
    """
    >>> a = bytearray(b'12345')
    >>> am = memoryview(a)
    >>> bm = am[2:]
    >>> memspan(a, bm)
    2
    >>> memspan(bm, a)
    -2
    >>> memspan(am, bm)
    2
    >>> memspan(bm, am)
    -2
    >>> memspan(bm, bytearray(b'another'))
    Traceback (most recent call last):
       ...
    ValueError: One argument not contained by the other
    >>> memspan(bytearray(b'another'), am)
    Traceback (most recent call last):
       ...
    ValueError: One argument not contained by the other
    """

__author__ = 'Christian Hopps'
__date__ = 'November 2 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
