# $Id: esp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Encapsulated Security Protocol."""

import dpkt


class ESP(dpkt.Packet):
    """Encapsulated Security Protocol.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of ESP.
        TODO.
    """
    
    __hdr__ = (
        ('spi', 'I', 0),
        ('seq', 'I', 0)
    )
