# $Id: ntp.py 48 2008-05-27 17:31:15Z yardley $
# -*- coding: utf-8 -*-
"""Network Time Protocol."""
from __future__ import print_function

from . import dpkt

# NTP v4

# Leap Indicator (LI) Codes
NO_WARNING = 0
LAST_MINUTE_61_SECONDS = 1
LAST_MINUTE_59_SECONDS = 2
ALARM_CONDITION = 3

# Mode Codes
RESERVED = 0
SYMMETRIC_ACTIVE = 1
SYMMETRIC_PASSIVE = 2
CLIENT = 3
SERVER = 4
BROADCAST = 5
CONTROL_MESSAGE = 6
PRIVATE = 7


class NTP(dpkt.Packet):
    """Network Time Protocol.

    The Network Time Protocol (NTP) is a networking protocol for clock synchronization between computer systems over
    packet-switched, variable-latency data networks. In operation since before 1985, NTP is one of the oldest Internet
    protocols in current use. NTP was designed by David L. Mills of the University of Delaware.

    Attributes:
        __hdr__: Header fields of NTP.
        TODO.
    """

    __hdr__ = (
        ('flags', 'B', 0),
        ('stratum', 'B', 0),
        ('interval', 'B', 0),
        ('precision', 'B', 0),
        ('delay', 'I', 0),
        ('dispersion', 'I', 0),
        ('id', '4s', b''),
        ('update_time', '8s', b''),
        ('originate_time', '8s', b''),
        ('receive_time', '8s', b''),
        ('transmit_time', '8s', b'')
    )
    __bit_fields__ = {
        'flags': (
            ('li', 2),    # leap indicator, 2 hi bits
            ('v', 3),     # version, 3 bits
            ('mode', 3),  # mode, 3 lo bits
        )
    }


__s = (b'\x24\x02\x04\xef\x00\x00\x00\x84\x00\x00\x33\x27\xc1\x02\x04\x02\xc8\x90\xec\x11\x22\xae'
       b'\x07\xe5\xc8\x90\xf9\xd9\xc0\x7e\x8c\xcd\xc8\x90\xf9\xd9\xda\xc5\xb0\x78\xc8\x90\xf9\xd9\xda\xc6\x8a\x93')


def test_ntp_pack():
    n = NTP(__s)
    assert (__s == bytes(n))


def test_ntp_unpack():
    n = NTP(__s)
    assert (n.li == NO_WARNING)
    assert (n.v == 4)
    assert (n.mode == SERVER)
    assert (n.stratum == 2)
    assert (n.id == b'\xc1\x02\x04\x02')
    # test get/set functions
    n.li = ALARM_CONDITION
    n.v = 3
    n.mode = CLIENT
    assert (n.li == ALARM_CONDITION)
    assert (n.v == 3)
    assert (n.mode == CLIENT)


def test_ntp_default_request():
    request = NTP(v=4, mode=CLIENT)
    wire = bytes(request)
    assert wire == b'\x23' + b'\x00' * 47
    parsed = NTP(wire)
    assert parsed.v == 4
    assert parsed.mode == CLIENT
    assert parsed.id == b'\x00' * 4
    for field in ('update_time', 'originate_time', 'receive_time', 'transmit_time'):
        assert getattr(parsed, field) == b'\x00' * 8
    assert bytes(parsed) == wire


def test_ntp_request_in_udp_capture():
    from io import BytesIO
    from . import ip, pcap, udp

    timestamp = b'\xed\x12\x34\x56\x78\x9a\xbc\xde'
    request = NTP(v=4, mode=CLIENT, transmit_time=timestamp)
    datagram = udp.UDP(sport=49152, dport=123, data=request)
    datagram.ulen = len(datagram)
    packet = ip.IP(src=b'\x7f\x00\x00\x01', dst=b'\x7f\x00\x00\x01',
                   p=ip.IP_PROTO_UDP, data=datagram)
    packet.len = len(packet)
    capture = BytesIO()
    writer = pcap.Writer(capture, linktype=pcap.DLT_RAW)
    writer.writepkt(bytes(packet), ts=1)
    capture.seek(0)
    _, captured = next(iter(pcap.Reader(capture)))
    received = ip.IP(captured)
    assert received.udp.dport == 123
    assert received.udp.ulen == 56
    assert received.udp.data == b'\x23' + b'\x00' * 39 + timestamp
    parsed = NTP(received.udp.data)
    assert parsed.transmit_time == timestamp
    assert parsed.mode == CLIENT
