# $Id: igmp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Internet Group Management Protocol."""

import dpkt


class IGMP(dpkt.Packet):
    __hdr__ = (
        ('type', 'B', 0),
        ('maxresp', 'B', 0),
        ('sum', 'H', 0),
        ('group', '4s', '\x00' * 4)
    )

    def __str__(self):
        if not self.sum:
            self.sum = dpkt.in_cksum(dpkt.Packet.__str__(self))
        return dpkt.Packet.__str__(self)
