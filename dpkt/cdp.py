# $Id: cdp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Cisco Discovery Protocol."""
from __future__ import absolute_import

import struct

from . import dpkt

CDP_DEVID = 1  # string
CDP_ADDRESS = 2
CDP_PORTID = 3  # string
CDP_CAPABILITIES = 4  # 32-bit bitmask
CDP_VERSION = 5  # string
CDP_PLATFORM = 6  # string
CDP_IPPREFIX = 7

CDP_VTP_MGMT_DOMAIN = 9  # string
CDP_NATIVE_VLAN = 10  # 16-bit integer
CDP_DUPLEX = 11  # 8-bit boolean
CDP_TRUST_BITMAP = 18  # 8-bit bitmask0x13
CDP_UNTRUST_COS = 19  # 8-bit port
CDP_SYSTEM_NAME = 20  # string
CDP_SYSTEM_OID = 21  # 10-byte binary string
CDP_MGMT_ADDRESS = 22  # 32-bit number of addrs, Addresses
CDP_LOCATION = 23  # string


class CDP(dpkt.Packet):
    """Cisco Discovery Protocol.

    See more about the BGP on \
    https://en.wikipedia.org/wiki/Cisco_Discovery_Protocol

    Attributes:
        __hdr__: Header fields of CDP.
        #TODO
    """

    __hdr__ = (
        ('version', 'B', 2),
        ('ttl', 'B', 180),
        ('sum', 'H', 0)
    )

    #keep here the TLV classes whose header is different from the generic TLV header (example : TLV_Addresses)
    tlv_types = {CDP_ADDRESS: 'TLV_Addresses'}

    class TLV(dpkt.Packet):
        '''When constructing the packet, len is not mandatory : if not provided, then self.data must be this exact TLV payload'''

        __hdr__ = (
            ('type', 'H', 0),
            ('len', 'H', 0)
        )

        def data_len(self):
            if self.len:
                return self.len - self.__hdr_len__
            return len(self.data)

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            self.data = self.data[:self.data_len()]

        def __len__(self):
            return self.__hdr_len__ + len(self.data)

        def __bytes__(self):
            if hasattr(self,'len') and not self.len:
                self.len = len(self)
            return self.pack_hdr() + bytes(self.data)


    class Address(TLV):
        # XXX - only handle NLPID/IP for now
        __hdr__ = (
            ('ptype', 'B', 1),  # protocol type (NLPID)
            ('plen', 'B', 1),  # protocol length
            ('p', 'B', 0xcc),  # IP
            ('alen', 'H', 4)  # address length
        )
        def data_len(self):
            return self.alen


    class TLV_Addresses(TLV):
        __hdr__ = (
            ('type', 'H', CDP_ADDRESS),
            ('len', 'H', 0),    #17),
            ('Addresses', 'L', 1),
        )


    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        buf = self.data
        l = []
        while buf:
            #find the right TLV according to Type value
            tlv_find_type = self.TLV(buf).type
            #if this TLV is not in tlv_types, use the default TLV class
            tlv = getattr(self, self.tlv_types.get(tlv_find_type, 'TLV'))(buf)
            l.append(bytes(tlv))
            buf = buf[len(tlv):]
        self.data = b''.join(l)

    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.data))

    def __bytes__(self):
        data = bytes(self.data)
        if not self.sum:
            self.sum = dpkt.in_cksum(self.pack_hdr() + data)
        return self.pack_hdr() + data


def test_cdp():
    import socket

    ss = (b'\x02\xb4\xdf\x93\x00\x01\x00\x09\x63\x69\x73\x63\x6f\x00\x02\x00\x11\x00\x00\x00\x01\x01\x01\xcc\x00\x04\xc0\xa8\x01\x67')
    rr1 = CDP(ss)
    assert bytes(rr1) == ss    

    # construction
    ss = (b'\x02\xb4\xdf\x93\x00\x01\x00\x09\x63\x69\x73\x63\x6f\x00\x02\x00\x11\x00\x00\x00\x01\x01\x01\xcc\x00\x04\xc0\xa8\x01\x67')
    p1 = CDP.TLV_Addresses(data=CDP.Address(data=socket.inet_aton('192.168.1.103')))
    p2 = CDP.TLV(type=CDP_DEVID, data=b'cisco')
    data = p2.pack() + p1.pack()
    rr2 = CDP(data=data)
    assert bytes(rr2) == ss    



if __name__ == '__main__':
    test_cdp()
    print('Tests Successful...')



