# $Id: radius.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Remote Authentication Dial-In User Service."""

from __future__ import absolute_import

import struct

from . import dpkt


# http://www.untruth.org/~josh/security/radius/radius-auth.html
# RFC 2865


# RADIUS Codes
RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCT_REQUEST = 4
RADIUS_ACCT_RESPONSE = 5
RADIUS_ACCT_STATUS = 6
RADIUS_ACCESS_CHALLENGE = 11

# Attribute Types
RADIUS_USER_NAME = 1
RADIUS_USER_PASSWORD = 2
RADIUS_CHAP_PASSWORD = 3
RADIUS_NAS_IP_ADDR = 4
RADIUS_NAS_PORT = 5
RADIUS_SERVICE_TYPE = 6
RADIUS_FRAMED_PROTOCOL = 7
RADIUS_FRAMED_IP_ADDR = 8
RADIUS_FRAMED_IP_NETMASK = 9
RADIUS_FRAMED_ROUTING = 10
RADIUS_FILTER_ID = 11
RADIUS_FRAMED_MTU = 12
RADIUS_FRAMED_COMPRESSION = 13
RADIUS_LOGIN_IP_HOST = 14
RADIUS_LOGIN_SERVICE = 15
RADIUS_LOGIN_TCP_PORT = 16
# unassigned
RADIUS_REPLY_MESSAGE = 18
RADIUS_CALLBACK_NUMBER = 19
RADIUS_CALLBACK_ID = 20
# unassigned
RADIUS_FRAMED_ROUTE = 22
RADIUS_FRAMED_IPX_NETWORK = 23
RADIUS_STATE = 24
RADIUS_CLASS = 25
RADIUS_VENDOR_SPECIFIC = 26
RADIUS_SESSION_TIMEOUT = 27
RADIUS_IDLE_TIMEOUT = 28
RADIUS_TERMINATION_ACTION = 29
RADIUS_CALLED_STATION_ID = 30
RADIUS_CALLING_STATION_ID = 31
RADIUS_NAS_ID = 32
RADIUS_PROXY_STATE = 33
RADIUS_LOGIN_LAT_SERVICE = 34
RADIUS_LOGIN_LAT_NODE = 35
RADIUS_LOGIN_LAT_GROUP = 36
RADIUS_FRAMED_ATALK_LINK = 37
RADIUS_FRAMED_ATALK_NETWORK = 38
RADIUS_FRAMED_ATALK_ZONE = 39
# 40-59 reserved for accounting
RADIUS_CHAP_CHALLENGE = 60
RADIUS_NAS_PORT_TYPE = 61
RADIUS_PORT_LIMIT = 62
RADIUS_LOGIN_LAT_PORT = 63


class RADIUS(dpkt.Packet):
    """Remote Authentication Dial-In User Service (RADIUS).
    This class is responsible for unpacking/packing header with
    the multiple AVPs above.

    Attributes:
        __hdr__: Header fields of RADIUS.
                  - code: Code field
                  - id  : Identifier field
                  - len : Length field
                  - auth: Authenticator field
    """
    __hdr__ = (
        ('code', 'B', RADIUS_ACCESS_REQUEST),
        ('id', 'B', 0),
        ('len', 'H', 4),
        ('auth', '16s', b'')
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        l = []
        while self.data:
            avp = AVP(self.data)
            l.append(avp)
            self.data = self.data[len(avp):]
        self.data = self.avps = l

    def pack_hdr(self):
        l = [bytes(d) for d in self.data]
        self.data = self.avps = b''.join(l)
        self.len = self.__hdr_len__ + len(bytes(self.data))

        return dpkt.Packet.pack_hdr(self)


class AVP(dpkt.Packet):
    """RADIUS AVP.
    This class is responsible for distinguishing general AVPs
    and Vendor-Specific AVPs, and unpacking/packing them.

    Attributes:
        __hdr__: Header fields of RADIUS.
                  - type: Type field
                  - len : Length field
        vendor : Vendor-Id field
                 This field exists only when type is Vendor-Specific(26).
        vsa    : Vendor-Specific AVP part on a AVP.
                 This value is always the same as data.
    """
    __hdr__ = (
        ('type', 'B', RADIUS_USER_NAME),
        ('len', 'B', 0),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)

        if self.type == RADIUS_VENDOR_SPECIFIC:
            self.vendor = struct.unpack('>I', self.data[:4])[0]
            self.data = self.vsa = VSA(self.data[4:self.len - self.__hdr_len__])
        else:
            self.data = self.data[:self.len - self.__hdr_len__]

    def pack_hdr(self):
        if self.type == RADIUS_VENDOR_SPECIFIC:
            self.len = self.__hdr_len__ + len(self.data) + 4
        else:
            self.len = self.__hdr_len__ + len(self.data)

        data = dpkt.Packet.pack_hdr(self)
        if self.type == RADIUS_VENDOR_SPECIFIC:
            data += struct.pack('>I', self.vendor)
        return data


class VSA(dpkt.Packet):
    """RADIUS Vendor-Specific AVP.
    This class is responsible for unpacking/packing Vendor-Specific AVPs.

    Attributes:
        __hdr__: Header fields of RADIUS.
                  - type: Type field
                  - len : Length field
    """
    __hdr__ = (
        ('type', 'B', RADIUS_USER_NAME),
        ('len', 'B', 0),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = self.data[:self.len - self.__hdr_len__]

    def pack_hdr(self):
        self.len = self.__hdr_len__ + len(self.data)
        return dpkt.Packet.pack_hdr(self)


# Accounting-Request Header with following AVPs.
#  - Calling-Station-Id AVP (General AVP)
#  - 3GPP-IMSI (Vendor-Specific AVP)
__payloads = [
    b'\x04\x01\x00\x39\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef',
    b'\x1f\x0e121212345678',
    b'\x1a\x17\x00\x00(\xaf\x01\x11123450123456789',
]
__s = b''.join(__payloads)


def test_pack():
    """Packing test.
    Create 'Accounting-Request' message by inserting values in each field
    manually, then check if the whole payload is built as the same as
    test payload bytearray above.
    """
    rad = RADIUS(
        code=RADIUS_ACCT_REQUEST,
        id=1,
        auth=b'\xde\xad\xbe\xef'*4
        )

    avplist = [
        AVP(type=RADIUS_CALLING_STATION_ID),
        AVP(type=RADIUS_VENDOR_SPECIFIC, vendor=10415)
    ]
    vsa = VSA(type=1)
    vsa.data = b'123450123456789'
    avplist[0].data = b'121212345678'
    avplist[1].data = bytes(vsa)

    rad.data = [bytes(x) for x in avplist]

    assert (bytes(rad) == __s)


def test_unpack():
    """Unpacking test.
    Unpack the payload bytearray above and check if the values are
    expectedly decoded.
    """
    rad = RADIUS(__s)
    assert (rad.code == RADIUS_ACCT_REQUEST)
    assert (rad.id == 1)
    assert (rad.len == 57)
    assert (rad.auth == b'\xde\xad\xbe\xef'*4)

    for i in range(len(rad.avps)):
        avp = rad.avps[i]
        if avp.type == RADIUS_CALLING_STATION_ID:
            assert (avp.len == 14)
            assert (avp.data == b'121212345678')
        if avp.type == RADIUS_VENDOR_SPECIFIC:
            assert (avp.len == 23)
            assert (avp.vendor == 10415)
            vsa = avp.vsa
            assert (vsa.type == 1)
            assert (vsa.len == 17)
            assert (vsa.data == b'123450123456789')
