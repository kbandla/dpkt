# $Id: igmp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Internet Group Management Protocol."""

from . import dpkt


class IGMP(dpkt.Packet):
    """Internet Group Management Protocol.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of IGMP.
        TODO.
    """
    
    __hdr__ = (
        ('type', 'B', 0),
        ('maxresp', 'B', 0),
        ('sum', 'H', 0),
        ('group', 'I', 0)
    )

    def __str__(self):
        return str(self.__bytes__())
    
    def __bytes__(self):
        if not self.sum:
            self.sum = dpkt.in_cksum(dpkt.Packet.__bytes__(self))
        return dpkt.Packet.__bytes__(self)
