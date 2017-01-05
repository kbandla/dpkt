# $Id: yahoo.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Yahoo Messenger."""
from __future__ import absolute_import

from . import dpkt


class YHOO(dpkt.Packet):
    """Yahoo Messenger.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of Yahoo Messenger.
        TODO.
    """
    
    __hdr__ = [
        ('version', '8s', ' ' * 8),
        ('length', 'I', 0),
        ('service', 'I', 0),
        ('connid', 'I', 0),
        ('magic', 'I', 0),
        ('unknown', 'I', 0),
        ('type', 'I', 0),
        ('nick1', '36s', ' ' * 36),
        ('nick2', '36s', ' ' * 36)
    ]
    __byte_order__ = '<'


class YMSG(dpkt.Packet):
    __hdr__ = [
        ('version', '8s', ' ' * 8),
        ('length', 'H', 0),
        ('type', 'H', 0),
        ('unknown1', 'I', 0),
        ('unknown2', 'I', 0)
    ]
