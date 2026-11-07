# $Id: mrt.py 29 2007-01-26 02:29:07Z jon.oberheide $
# -*- coding: utf-8 -*-
"""Multi-threaded Routing Toolkit."""
from __future__ import absolute_import

import struct

from . import dpkt
from . import bgp

# Multi-threaded Routing Toolkit
# http://www.ietf.org/internet-drafts/draft-ietf-grow-mrt-03.txt

# MRT Types
NULL = 0
START = 1
DIE = 2
I_AM_DEAD = 3
PEER_DOWN = 4
BGP = 5  # Deprecated by BGP4MP
RIP = 6
IDRP = 7
RIPNG = 8
BGP4PLUS = 9  # Deprecated by BGP4MP
BGP4PLUS_01 = 10  # Deprecated by BGP4MP
OSPF = 11
TABLE_DUMP = 12
BGP4MP = 16
BGP4MP_ET = 17
ISIS = 32
ISIS_ET = 33
OSPF_ET = 64

# BGP4MP Subtypes
BGP4MP_STATE_CHANGE = 0
BGP4MP_MESSAGE = 1
BGP4MP_ENTRY = 2
BGP4MP_SNAPSHOT = 3
BGP4MP_MESSAGE_32BIT_AS = 4

# Address Family Types
AFI_IPv4 = 1
AFI_IPv6 = 2


class MRTHeader(dpkt.Packet):
    __hdr__ = (
        ('ts', 'I', 0),
        ('type', 'H', 0),
        ('subtype', 'H', 0),
        ('len', 'I', 0)
    )


class TableDump(dpkt.Packet):
    __hdr__ = (
        ('view', 'H', 0),
        ('seq', 'H', 0),
        ('prefix', 'I', 0),
        ('prefix_len', 'B', 0),
        ('status', 'B', 1),
        ('originated_ts', 'I', 0),
        ('peer_ip', 'I', 0),
        ('peer_as', 'H', 0),
        ('attr_len', 'H', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        plen = self.attr_len
        l_ = []
        while plen > 0:
            attr = bgp.BGP.Update.Attribute(self.data)
            self.data = self.data[len(attr):]
            plen -= len(attr)
            l_.append(attr)
        self.attributes = l_


class BGP4MPMessage(dpkt.Packet):
    """BGP message with IPv4 integer or IPv6 packed-byte address fields."""

    __hdr__ = (
        ('src_as', 'H', 0),
        ('dst_as', 'H', 0),
        ('intf', 'H', 0),
        ('family', 'H', AFI_IPv4),
        ('src_ip', 'I', 0),
        ('dst_ip', 'I', 0)
    )

    def __init__(self, *args, **kwargs):
        dpkt.Packet.__init__(self, *args, **kwargs)
        if not args and self.family == AFI_IPv6:
            for field in ('src_ip', 'dst_ip'):
                if field not in kwargs:
                    setattr(self, field, b'\x00' * 16)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.family == AFI_IPv6:
            offset = self.__hdr_len__ - 8
            if len(buf) < offset + 32:
                raise dpkt.NeedData('short IPv6 BGP4MP address fields')
            self.src_ip, self.dst_ip = struct.unpack('>16s16s', buf[offset:offset + 32])
            self.data = buf[offset + 32:]

    def __len__(self):
        return dpkt.Packet.__len__(self) + (24 if self.family == AFI_IPv6 else 0)

    def pack_hdr(self):
        if self.family != AFI_IPv6:
            return dpkt.Packet.pack_hdr(self)
        try:
            return struct.pack(self.__hdr_fmt__[:-2] + '16s16s',
                               self.src_as, self.dst_as, self.intf, self.family,
                               self.src_ip, self.dst_ip)
        except struct.error as e:
            raise dpkt.PackError(str(e))


class BGP4MPMessage_32(BGP4MPMessage):
    __hdr__ = (
        ('src_as', 'I', 0),
        ('dst_as', 'I', 0),
        ('intf', 'H', 0),
        ('family', 'H', AFI_IPv4),
        ('src_ip', 'I', 0),
        ('dst_ip', 'I', 0)
    )


def test_tabledump():
    from binascii import unhexlify
    buf_tabledump = unhexlify(
        '0001'           # view
        '0002'           # seq
        '00000003'       # prefix
        '04'             # prefix_len
        '05'             # status
        '00000006'       # originated_ts
        '00000007'       # peer_ip
        '0008'           # peer_as

        '0002'           # attr_len
    )
    buf_attrs = unhexlify(
        '01'  # flags
        '01'  # type (ORIGIN)

        '01'  # length
        '02'  # Origin.type (INCOMPLETE)
    )
    buf = buf_tabledump + buf_attrs
    table_dump = TableDump(buf)
    assert table_dump.view == 1
    assert table_dump.seq == 2
    assert table_dump.prefix == 3
    assert table_dump.prefix_len == 4
    assert table_dump.status == 5
    assert table_dump.originated_ts == 6
    assert table_dump.peer_ip == 7
    assert table_dump.peer_as == 8
    assert table_dump.attr_len == 2

    assert len(table_dump.attributes) == 1
    attr = table_dump.attributes[0]
    assert isinstance(attr, bgp.BGP.Update.Attribute)
    assert isinstance(attr.data, bgp.BGP.Update.Attribute.Origin)


def _check_bgp4mp_ipv6(cls, subtype, as_format, src_as, dst_as):
    import socket
    import struct

    src_ip = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
    dst_ip = socket.inet_pton(socket.AF_INET6, '2001:db8:1::2')
    # A BGP keepalive follows both complete addresses (RFC 6396 section 4.4).
    payload = b'\xff' * 16 + b'\x00\x13\x04'
    message = struct.pack('>' + as_format + 'HH', src_as, dst_as, 3, AFI_IPv6) + src_ip + dst_ip + payload
    wire = bytes(MRTHeader(ts=1700000000, type=BGP4MP, subtype=subtype, len=len(message), data=message))
    header = MRTHeader(wire)
    packet = cls(header.data)
    assert packet.src_as == src_as
    assert packet.dst_as == dst_as
    assert packet.intf == 3
    assert packet.family == AFI_IPv6
    assert packet.src_ip == src_ip
    assert packet.dst_ip == dst_ip
    assert packet.data == payload
    assert bgp.BGP(packet.data).type == bgp.KEEPALIVE
    assert len(packet) == header.len == len(message)
    assert bytes(packet) == message
    assert bytes(cls(src_as=src_as, dst_as=dst_as, intf=3, family=AFI_IPv6,
                     src_ip=src_ip, dst_ip=dst_ip, data=payload)) == message
    packet.src_ip = socket.inet_pton(socket.AF_INET6, '2001:db8::3')
    assert cls(bytes(packet)).src_ip == packet.src_ip


def test_bgp4mp_ipv6_message():
    _check_bgp4mp_ipv6(BGP4MPMessage, BGP4MP_MESSAGE, 'HH', 64512, 64513)


def test_bgp4mp_ipv6_message_32():
    _check_bgp4mp_ipv6(BGP4MPMessage_32, BGP4MP_MESSAGE_32BIT_AS, 'II', 65536, 4294967295)


def test_bgp4mp_ipv4_preserved():
    import struct

    payload = b'\xff' * 16 + b'\x00\x13\x04'
    for cls, as_format in ((BGP4MPMessage, 'HH'), (BGP4MPMessage_32, 'II')):
        wire = struct.pack('>' + as_format + 'HHII', 64512, 64513, 3, AFI_IPv4, 0xc0000201, 0xc6336402) + payload
        packet = cls(wire)
        assert packet.src_ip == 0xc0000201
        assert packet.dst_ip == 0xc6336402
        assert packet.data == payload
        assert len(packet) == len(wire)
        assert bytes(packet) == wire
        assert bgp.BGP(packet.data).type == bgp.KEEPALIVE
        assert bytes(cls(src_as=64512, dst_as=64513, intf=3, family=AFI_IPv4,
                         src_ip=0xc0000201, dst_ip=0xc6336402, data=payload)) == wire


def test_bgp4mp_ipv6_short_addresses():
    import struct
    import pytest

    for cls, as_format in ((BGP4MPMessage, 'HH'), (BGP4MPMessage_32, 'II')):
        prefix = struct.pack('>' + as_format + 'HH', 64512, 64513, 3, AFI_IPv6)
        for address_bytes in range(32):
            with pytest.raises(dpkt.NeedData):
                cls(prefix + b'\x00' * address_bytes)


def test_bgp4mp_ipv6_defaults():
    for cls in (BGP4MPMessage, BGP4MPMessage_32):
        packet = cls(family=AFI_IPv6)
        assert packet.src_ip == packet.dst_ip == b'\x00' * 16
        wire = bytes(packet)
        assert len(packet) == len(wire)
        assert cls(wire).src_ip == packet.src_ip
        assert cls(wire).dst_ip == packet.dst_ip
        assert cls(wire).data == b''
