# $Id: sll.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Linux libpcap "cooked" capture encapsulation."""

from . import arp
from . import dpkt
from . import ethernet


class SLL(dpkt.Packet):
    """Linux libpcap "cooked" capture encapsulation.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of SLL.
        TODO.
    """
    
    __hdr__ = (
        ('type', 'H', 0),  # 0: to us, 1: bcast, 2: mcast, 3: other, 4: from us
        ('hrd', 'H', arp.ARP_HRD_ETH),
        ('hlen', 'H', 6),  # hardware address length
        ('hdr', '8s', ''),  # first 8 bytes of link-layer header
        ('ethtype', 'H', ethernet.ETH_TYPE_IP),
    )
    _typesw = ethernet.Ethernet._typesw

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        try:
            self.data = self._typesw[self.ethtype](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            pass
