# $Id: pim.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Protocol Independent Multicast."""
from __future__ import absolute_import

from . import dpkt


class PIM(dpkt.Packet):
    """Protocol Independent Multicast.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of PIM.
        TODO.
    """

    __hdr__ = (
        ('_v_type', 'B', 0x20),
        ('rsvd', 'B', 0),
        ('sum', 'H', 0)
    )

    @property
    def v(self):
        return self._v_type >> 4

    @v.setter
    def v(self, v):
        self._v_type = (v << 4) | (self._v_type & 0xf)

    @property
    def type(self):
        return self._v_type & 0xf

    @type.setter
    def type(self, type):
        self._v_type = (self._v_type & 0xf0) | type

    def __bytes__(self):
        if not self.sum:
            self.sum = dpkt.in_cksum(dpkt.Packet.__bytes__(self))
        return dpkt.Packet.__bytes__(self)


def test_pim():
    from binascii import unhexlify
    buf = unhexlify(
        '20'            # _v_type
        '00'            # rsvd
        'df93'          # sum

        '000100020069'  # data
    )
    pimdata = PIM(buf)
    assert bytes(pimdata) == buf
    # force checksum recalculation
    pimdata = PIM(buf)
    pimdata.sum = 0
    assert pimdata.sum == 0
    assert bytes(pimdata) == buf

    assert pimdata.v == 2
    assert pimdata.type == 0

    # test setters
    buf_modified = unhexlify(
        '31'            # _v_type
        '00'            # rsvd
        'df93'          # sum

        '000100020069'  # data
    )
    pimdata.v = 3
    pimdata.type = 1
    assert bytes(pimdata) == buf_modified
