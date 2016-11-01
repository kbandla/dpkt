# $Id: pim.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Protocol Independent Multicast."""

from . import dpkt
from .decorators import deprecated


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

    # Deprecated methods, will be removed in the future
    # =================================================
    @deprecated('v')
    def _get_v(self): return self.v

    @deprecated('v')
    def _set_v(self, v): self.v = v

    @deprecated('type')
    def _get_type(self): return self.type

    @deprecated('type')
    def _set_type(self, type): self.type = type
    # =================================================

    def __str__(self):
        if not self.sum:
            self.sum = dpkt.in_cksum(dpkt.Packet.__str__(self))
        return dpkt.Packet.__str__(self)
