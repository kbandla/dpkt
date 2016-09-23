# -*- coding: utf-8 -*-
"""Hypertext Transfer Protocol Version 2."""

import dpkt
import struct
import binascii


HTTP2_PREFACE = '\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a'

# Frame types
HTTP2_FRAME_DATA = 0
HTTP2_FRAME_HEADERS = 1
HTTP2_FRAME_PRIORITY = 2
HTTP2_FRAME_RST_STREAM = 3
HTTP2_FRAME_SETTINGS = 4
HTTP2_FRAME_PUSH_PROMISE = 5
HTTP2_FRAME_PING = 6
HTTP2_FRAME_GOAWAY = 7
HTTP2_FRAME_WINDOW_UPDATE = 8
HTTP2_FRAME_CONTINUATION = 9

# Flags
HTTP2_FLAG_END_STREAM = 0x01 # for DATA and HEADERS frames
HTTP2_FLAG_ACK = 0x01 # for SETTINGS and PING frames
HTTP2_FLAG_END_HEADERS = 0x04
HTTP2_FLAG_PADDED = 0x08
HTTP2_FLAG_PRIORITY = 0x20

# Settings
HTTP2_SETTINGS_HEADER_TABLE_SIZE = 0x1
HTTP2_SETTINGS_ENABLE_PUSH = 0x2
HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
HTTP2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4
HTTP2_SETTINGS_MAX_FRAME_SIZE = 0x5
HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

# Error codes
HTTP2_NO_ERROR = 0x0
HTTP2_PROTOCOL_ERROR = 0x1
HTTP2_INTERNAL_ERROR = 0x2
HTTP2_FLOW_CONTROL_ERROR = 0x3
HTTP2_SETTINGS_TIMEOUT = 0x4
HTTP2_STREAM_CLOSED = 0x5
HTTP2_FRAME_SIZE_ERROR = 0x6
HTTP2_REFUSED_STREAM = 0x7
HTTP2_CANCEL = 0x8
HTTP2_COMPRESSION_ERROR = 0x9
HTTP2_CONNECT_ERROR = 0xa
HTTP2_ENHANCE_YOUR_CALM = 0xb
HTTP2_INADEQUATE_SECURITY = 0xc
HTTP2_HTTP_1_1_REQUIRED = 0xd


class HTTP2Exception(Exception):
    pass


class Preface(dpkt.Packet):
    __hdr__ = (
        ('preface', '24s', HTTP2_PREFACE),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.preface != HTTP2_PREFACE:
            raise HTTP2Exception("Invalid HTTP/2 preface")
        self.data = ''


class Frame(dpkt.Packet):

    """
    An HTTP/2 frame as defined in RFC 7540
    """

    # struct.unpack can't handle the 3-byte int, so we parse it as bytes
    # (and store it as bytes so dpkt doesn't get confused), and turn it into
    # an int in a user-facing property
    __hdr__ = (
        ('length_bytes', '3s', 0),
        ('type', 'B', 0),
        ('flags', 'B', 0),
        ('stream_id', 'I', 0),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        # only take the right number of bytes
        self.data = self.data[:self.length]
        if len(self.data) != self.length:
            raise dpkt.NeedData

    @property
    def length(self):
        return struct.unpack('!I', '\x00' + self.length_bytes)[0]


def frame_multi_factory(buf, preface=False):
    """
    Attempt to parse one or more Frame's out of buf

    Args:
      buf: string containing HTTP/2 frames. May have an incomplete frame at the
        end.
      preface: expect an HTTP/2 preface at the beginning of the buffer.

    Returns:
      [Frame]
      int, total bytes consumed, != len(buf) if an incomplete frame was left at
        the end.
    """
    i = 0
    n = len(buf)
    frames = []

    if preface:
        try:
            p = Preface(buf)
            i += len(p)
        except dpkt.NeedData:
            return [], 0

    while i < n:
        try:
            frame = Frame(buf[i:])
            frames.append(frame)
            i += len(frame)
        except dpkt.NeedData:
            break
    return frames, i


_hexdecode = binascii.a2b_hex

class TestFrame(object):

    """Some data found in real traffic"""

    @classmethod
    def setup_class(cls):
        # Settings ack frame
        cls.frame_ack = Frame(_hexdecode('000000040100000000'))
        # First TLS AppData record sent by Firefox (decrypted)
        record = _hexdecode('505249202a20485454502f322e300d0a'
                            '0d0a534d0d0a0d0a00000c0400000000'
                            '00000400020000000500004000000004'
                            '08000000000000bf0001000005020000'
                            '00000300000000c80000050200000000'
                            '05000000006400000502000000000700'
                            '00000000000005020000000009000000'
                            '070000000502000000000b0000000300')
        cls.frames, cls.i = frame_multi_factory(record, preface=True)

    def test_ack(self):
        assert (self.frame_ack.length == 0)
        assert (self.frame_ack.type == HTTP2_FRAME_SETTINGS)
        assert (self.frame_ack.flags == HTTP2_FLAG_ACK)
        assert (self.frame_ack.stream_id == 0)

    def test_mutli(self):
        assert (self.i == 128)
        assert (len(self.frames) == 7)

        assert (self.frames[0].length == 12)
        assert (self.frames[1].length == 4)
        assert (self.frames[2].length == 5)
        assert (self.frames[3].length == 5)
        assert (self.frames[4].length == 5)
        assert (self.frames[5].length == 5)
        assert (self.frames[6].length == 5)

        assert (self.frames[0].type == HTTP2_FRAME_SETTINGS)
        assert (self.frames[1].type == HTTP2_FRAME_WINDOW_UPDATE)
        assert (self.frames[2].type == HTTP2_FRAME_PRIORITY)
        assert (self.frames[3].type == HTTP2_FRAME_PRIORITY)
        assert (self.frames[4].type == HTTP2_FRAME_PRIORITY)
        assert (self.frames[5].type == HTTP2_FRAME_PRIORITY)
        assert (self.frames[6].type == HTTP2_FRAME_PRIORITY)

        assert (self.frames[0].flags == 0)
        assert (self.frames[1].flags == 0)
        assert (self.frames[2].flags == 0)
        assert (self.frames[3].flags == 0)
        assert (self.frames[4].flags == 0)
        assert (self.frames[5].flags == 0)
        assert (self.frames[6].flags == 0)

        assert (self.frames[0].stream_id == 0)
        assert (self.frames[1].stream_id == 0)
        assert (self.frames[2].stream_id == 3)
        assert (self.frames[3].stream_id == 5)
        assert (self.frames[4].stream_id == 7)
        assert (self.frames[5].stream_id == 9)
        assert (self.frames[6].stream_id == 11)

    def test_exceptions(self):
        import pytest
        # Preface
        pytest.raises(dpkt.NeedData, Preface, _hexdecode('505249202a20485454502f322e300d0a'))
        pytest.raises(dpkt.NeedData, Preface, _hexdecode('00' * 23))
        pytest.raises(HTTP2Exception, Preface, _hexdecode('00' * 24))

        frames, i = frame_multi_factory(_hexdecode('505249202a20485454502f322e300d0a'), preface=True)
        assert (len(frames) == 0)
        assert (i == 0)

        # Frame
        pytest.raises(dpkt.NeedData, Frame, _hexdecode('000001' # length
                                                       '0000' # type, flags
                                                       '00000000')) # stream id

        # Only preface was parsed
        frames, i = frame_multi_factory(_hexdecode('505249202a20485454502f322e300d0a'
                                                   '0d0a534d0d0a0d0a00000c0400000000'), preface=True)
        assert (len(frames) == 0)
        assert (i == 24)

