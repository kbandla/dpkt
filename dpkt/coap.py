# -*- coding: utf-8 -*-
"""Constrained Application Protocol (CoAP)."""
from __future__ import print_function
from __future__ import absolute_import

import struct
from . import dpkt
from .compat import compat_ord

# CoAP Message Types (RFC 7252)
COAP_CON = 0  # Confirmable
COAP_NON = 1  # Non-confirmable
COAP_ACK = 2  # Acknowledgement
COAP_RST = 3  # Reset

# CoAP Codes (RFC 7252)
# Requests
COAP_GET = 1
COAP_POST = 2
COAP_PUT = 3
COAP_DELETE = 4

# Responses
COAP_CREATED = 65      # 2.01
COAP_DELETED = 66      # 2.02
COAP_VALID = 67        # 2.03
COAP_CHANGED = 68      # 2.04
COAP_CONTENT = 69      # 2.05
COAP_BAD_REQUEST = 128 # 4.00
COAP_UNAUTHORIZED = 129 # 4.01
COAP_BAD_OPTION = 130   # 4.02
COAP_FORBIDDEN = 131    # 4.03
COAP_NOT_FOUND = 132    # 4.04
COAP_METHOD_NOT_ALLOWED = 133 # 4.05
COAP_NOT_ACCEPTABLE = 134     # 4.06
COAP_PRECONDITION_FAILED = 140 # 4.12
COAP_REQUEST_ENTITY_TOO_LARGE = 141 # 4.13
COAP_UNSUPPORTED_CONTENT_FORMAT = 143 # 4.15
COAP_INTERNAL_SERVER_ERROR = 160 # 5.00
COAP_NOT_IMPLEMENTED = 161      # 5.01
COAP_BAD_GATEWAY = 162          # 5.02
COAP_SERVICE_UNAVAILABLE = 163  # 5.03
COAP_GATEWAY_TIMEOUT = 164      # 5.04
COAP_PROXYING_NOT_SUPPORTED = 165 # 5.05

# CoAP Option Numbers (RFC 7252)
COAP_OPT_IF_MATCH = 1
COAP_OPT_URI_HOST = 3
COAP_OPT_ETAG = 4
COAP_OPT_IF_NONE_MATCH = 5
COAP_OPT_OBSERVE = 6
COAP_OPT_URI_PORT = 7
COAP_OPT_LOCATION_PATH = 8
COAP_OPT_URI_PATH = 11
COAP_OPT_CONTENT_FORMAT = 12
COAP_OPT_MAX_AGE = 14
COAP_OPT_URI_QUERY = 15
COAP_OPT_ACCEPT = 17
COAP_OPT_LOCATION_QUERY = 20
COAP_OPT_BLOCK2 = 23
COAP_OPT_BLOCK1 = 27
COAP_OPT_SIZE2 = 28
COAP_OPT_PROXY_URI = 35
COAP_OPT_PROXY_SCHEME = 39
COAP_OPT_SIZE1 = 60

# CoAP Content Formats (RFC 7252 and OMA LWM2M)
COAP_FORMAT_TEXT = 0
COAP_FORMAT_LINK = 40
COAP_FORMAT_OCTET = 42
COAP_FORMAT_EXI = 47
COAP_FORMAT_XML = 48
COAP_FORMAT_JSON = 50
COAP_FORMAT_CBOR = 60
COAP_FORMAT_LWM2M_TLV = 11542
COAP_FORMAT_LWM2M_JSON = 11543
COAP_FORMAT_SENML_JSON = 110
COAP_FORMAT_SENML_CBOR = 112


class CoAP(dpkt.Packet):
    """Constrained Application Protocol.

    The Constrained Application Protocol (CoAP) is a specialized web transfer protocol
    for use with constrained nodes and constrained networks in the Internet of Things.
    The protocol is designed for machine-to-machine (M2M) applications such as smart
    energy and building automation.

    RFC 7252

    Attributes:
        v (int): Version (2 bits). Default is 1.
        t (int): Type (2 bits). 0=CON, 1=NON, 2=ACK, 3=RST.
        tkl (int): Token Length (4 bits). 0-8 bytes.
        code (int): Code (8 bits). Request or Response code.
        id (int): Message ID (16 bits).
        token (bytes): Token (0-8 bytes).
        opts (list): List of (opt_num, value) tuples.
    """

    __hdr__ = (
        ('_v_t_tkl', 'B', 0x40),  # Ver (2), T (2), TKL (4). Default Ver=1
        ('code', 'B', 0),
        ('id', 'H', 0),
    )
    __bit_fields__ = {
        '_v_t_tkl': (
            ('v', 2),
            ('t', 2),
            ('tkl', 4),
        )
    }

    def __init__(self, *args, **kwargs):
        self.token = b''
        self.opts = []
        super(CoAP, self).__init__(*args, **kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        # Token
        if self.tkl > 8:
            raise dpkt.UnpackError('invalid token length: %d' % self.tkl)
        if len(buf) < self.__hdr_len__ + self.tkl:
            raise dpkt.NeedData('short token')
        self.token = buf[self.__hdr_len__:self.__hdr_len__ + self.tkl]
        off = self.__hdr_len__ + self.tkl

        # Options
        self.opts = []
        last_opt_num = 0
        while off < len(buf):
            if compat_ord(buf[off]) == 0xFF:
                if off + 1 == len(buf):
                    raise dpkt.UnpackError('payload marker with no payload')
                off += 1
                break

            # Read Option header
            delta_len = compat_ord(buf[off])
            off += 1
            delta = (delta_len & 0xF0) >> 4
            length = delta_len & 0x0F

            if delta == 13:
                if off >= len(buf):
                    raise dpkt.NeedData('short option delta (1 byte)')
                delta = compat_ord(buf[off]) + 13
                off += 1
            elif delta == 14:
                if off + 2 > len(buf):
                    raise dpkt.NeedData('short option delta (2 bytes)')
                delta = struct.unpack('>H', buf[off:off + 2])[0] + 269
                off += 2
            elif delta == 15:
                raise dpkt.UnpackError('invalid option delta: 15')

            if length == 13:
                if off >= len(buf):
                    raise dpkt.NeedData('short option length (1 byte)')
                length = compat_ord(buf[off]) + 13
                off += 1
            elif length == 14:
                if off + 2 > len(buf):
                    raise dpkt.NeedData('short option length (2 bytes)')
                length = struct.unpack('>H', buf[off:off + 2])[0] + 269
                off += 2
            elif length == 15:
                raise dpkt.UnpackError('invalid option length: 15')

            if off + length > len(buf):
                raise dpkt.NeedData('short option value')

            opt_num = last_opt_num + delta
            value = buf[off:off + length]
            off += length

            self.opts.append((opt_num, value))
            last_opt_num = opt_num

        self.data = buf[off:]

    def _pack_opt(self, opt_num, value, last_opt_num):
        delta = opt_num - last_opt_num
        length = len(value)

        res = b''

        # Option Delta
        if delta < 13:
            d_val = delta
        elif delta < 269:
            d_val = 13
        else:
            d_val = 14

        # Option Length
        if length < 13:
            l_val = length
        elif length < 269:
            l_val = 13
        else:
            l_val = 14

        res += struct.pack('B', (d_val << 4) | l_val)

        if d_val == 13:
            res += struct.pack('B', delta - 13)
        elif d_val == 14:
            res += struct.pack('>H', delta - 269)

        if l_val == 13:
            res += struct.pack('B', length - 13)
        elif l_val == 14:
            res += struct.pack('>H', length - 269)

        res += value
        return res

    def __len__(self):
        opts_len = 0
        last_opt_num = 0
        for opt_num, value in sorted(self.opts):
            opts_len += len(self._pack_opt(opt_num, value, last_opt_num))
            last_opt_num = opt_num

        return self.__hdr_len__ + len(self.token) + opts_len + (1 if self.data else 0) + len(self.data)

    def __bytes__(self):
        # Update TKL based on token length
        self.tkl = len(self.token)

        res = self.pack_hdr()
        res += self.token

        last_opt_num = 0
        for opt_num, value in sorted(self.opts):
            res += self._pack_opt(opt_num, value, last_opt_num)
            last_opt_num = opt_num

        if self.data:
            res += b'\xff'
            res += bytes(self.data)

        return res

    @property
    def code_class(self):
        return self.code >> 5

    @property
    def code_detail(self):
        return self.code & 0x1F


def test_coap():
    from binascii import unhexlify
    # Example from RFC 7252: GET /test (CON, MID=0x7d34)
    # 0x40 (Ver=1, T=CON, TKL=0)
    # 0x01 (Code=GET)
    # 0x7d34 (MID)
    # 0xb4 (Delta=11 (Uri-Path), Length=4)
    # 0x74657374 ("test")
    buf = unhexlify('40017d34b474657374')
    c = CoAP(buf)
    assert c.v == 1
    assert c.t == COAP_CON
    assert c.tkl == 0
    assert c.code == COAP_GET
    assert c.id == 0x7d34
    assert len(c.opts) == 1
    assert c.opts[0] == (COAP_OPT_URI_PATH, b'test')
    assert bytes(c) == buf

    # Example with token and payload
    # 0x42 (Ver=1, T=CON, TKL=2)
    # 0x01 (Code=GET)
    # 0x1234 (MID)
    # 0xabcd (Token)
    # 0xff (Payload Marker)
    # 0x68656c6c6f ("hello")
    buf2 = unhexlify('42011234abcdff68656c6c6f')
    c2 = CoAP(buf2)
    assert c2.tkl == 2
    assert c2.token == b'\xab\xcd'
    assert c2.data == b'hello'
    assert bytes(c2) == buf2

    # Example with multiple options
    c3 = CoAP(t=COAP_NON, code=COAP_POST, id=0xabcd)
    c3.opts = [(COAP_OPT_URI_HOST, b'example.com'), (COAP_OPT_URI_PATH, b'test')]
    c3.data = b'payload'
    buf3 = bytes(c3)
    c3_parsed = CoAP(buf3)
    assert c3_parsed.t == COAP_NON
    assert c3_parsed.code == COAP_POST
    assert c3_parsed.id == 0xabcd
    assert len(c3_parsed.opts) == 2
    assert c3_parsed.opts[0] == (COAP_OPT_URI_HOST, b'example.com')
    assert c3_parsed.opts[1] == (COAP_OPT_URI_PATH, b'test')
    assert c3_parsed.data == b'payload'

    # Test payload marker with no payload (RFC 7252 Section 3)
    buf4 = unhexlify('40017d34ff')
    try:
        CoAP(buf4)
        assert False, "Should have raised UnpackError"
    except dpkt.UnpackError as e:
        assert str(e) == 'payload marker with no payload'


if __name__ == '__main__':
    test_coap()
    print('Tests passed.')
