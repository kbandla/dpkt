"""Extreme Discovery Protocol."""
from __future__ import absolute_import 

import dpkt
import sys

class EDP(dpkt.Packet):
    __hdr__ = (
        ('version', 'B', 1),
        ('reserved', 'B', 0),
        ('hlen', 'H', 0),
        ('sum', 'H', 0),
        ('seq', 'H', 0),
        ('mid', 'H', 0),
        ('mac', '6s', '')
        )
    
    def __str__(self):
        if not self.sum:
            self.sum = dpkt.in_cksum(dpkt.Packet.__str__(self))
        return dpkt.Packet.__str__(self)

