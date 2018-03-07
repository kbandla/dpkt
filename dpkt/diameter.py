# $Id: diameter.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Diameter."""

from __future__ import print_function
from __future__ import absolute_import

import struct

from . import dpkt
from .decorators import deprecated
from .compat import compat_ord

# Diameter Base Protocol - RFC 6733
# http://tools.ietf.org/html/rfc6733


class Diameter(dpkt.Packet):
    """Diameter Base Protocol Header.
    This class is to parse diameter header and split AVPs above.

    Attributes:
        __hdr__: Header fields of Diameter.
        cmd_codes: Basic diameter command codes defined in rcf6733.
                   Other commands should be implemented by overridding
                   this attribute from another class specific to
                   each application.
    """

    __hdr__ = (
        ('v', 'B', 1),
        ('len', '3s', 0),
        ('flags', 'B', 0),
        ('cmd', '3s', 0),
        ('app_id', 'I', 0),
        ('hop_id', 'I', 0),
        ('end_id', 'I', 0)
    )

    cmd_codes = {
        'ABORT_SESSION': 274,
        'ACCOUTING': 271,
        'CAPABILITIES_EXCHANGE': 257,
        'DEVICE_WATCHDOG': 280,
        'DISCONNECT_PEER': 282,
        'RE_AUTH': 258,
        'SESSION_TERMINATION': 275
    }

    @property
    def request_flag(self):
        return (self.flags >> 7) & 0x1

    @request_flag.setter
    def request_flag(self, r):
        self.flags = (self.flags & ~0x80) | ((r & 0x1) << 7)

    @property
    def proxiable_flag(self):
        return (self.flags >> 6) & 0x1

    @proxiable_flag.setter
    def proxiable_flag(self, p):
        self.flags = (self.flags & ~0x40) | ((p & 0x1) << 6)

    @property
    def error_flag(self):
        return (self.flags >> 5) & 0x1

    @error_flag.setter
    def error_flag(self, e):
        self.flags = (self.flags & ~0x20) | ((e & 0x1) << 5)

    @property
    def retransmit_flag(self):
        return (self.flags >> 4) & 0x1

    @retransmit_flag.setter
    def retransmit_flag(self, t):
        self.flags = (self.flags & ~0x10) | ((t & 0x1) << 4)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.cmd = (compat_ord(self.cmd[0]) << 16) | \
                    (compat_ord(self.cmd[1]) << 8) | \
                    (compat_ord(self.cmd[2]))
        self.len = (compat_ord(self.len[0]) << 16) | \
                    (compat_ord(self.len[1]) << 8) | \
                    (compat_ord(self.len[2]))
        self.data = self.data[:self.len - self.__hdr_len__]

        l = []
        while self.data:
            avp = AVP(self.data)
            l.append(avp)
            self.data = self.data[len(avp):]
        self.data = self.avps = l

    def pack_hdr(self):
        l = []
        for d in self.data:
            padlen = 0 if len(d) % 4 == 0 else 4 - (len(d) % 4)
            padding = b'\x00' * padlen
            l.append(bytes(d) + padding)
        self.data = self.avps = b''.join(l)

        self.len = self.__hdr_len__ + len(bytes(self.data))
        self.len = struct.pack("BBB", (self.len >> 16) & 0xff, (self.len >> 8) & 0xff, self.len & 0xff)
        self.cmd = struct.pack("BBB", (self.cmd >> 16) & 0xff, (self.cmd >> 8) & 0xff, self.cmd & 0xff)

        return dpkt.Packet.pack_hdr(self)

    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.data))


class AVP(dpkt.Packet):
    """Basic Diameter AVPs defined in rfc6733.

    Attributes:
        __hdr__: Header fields of Basic Diameter AVPs.
        avp_codes: Basic AVP Codes defined in rfc6733.
                   Other AVPs should be implemented by overridding
                   this attribute from another class specific to
                   each application.
    """

    __hdr__ = (
        ('code', 'I', 0),
        ('flags', 'B', 0),
        ('len', '3s', 0),
    )

    avp_codes = {
        'ACCT_INTERIM_INTERVAL': 85,
        'ACCT_REALTIME_REQUIRED': 483,
        'ACCT_MULTISESSION_ID': 50,
        'ACCT_RECORD_NUMBER': 485,
        'ACCT_RECORD_TYPE': 480,
        'ACCT_SESSION_ID': 44,
        'ACCT_SUB_SESSION_ID': 287,
        'ACCT_APPLICATION_ID': 259,
        'AUTH_APPLICATION_ID': 258,
        'AUTH_REQUEST_TYPE': 274,
        'AUTH_LIFETIME': 291,
        'AUTH_GRACE_PERIOD': 276,
        'AUTH_SESSION_STATE': 277,
        'RE_AUTH_REQUEST_TYPE': 285,
        'CLASS': 25,
        'DESTINATION_HOST': 293,
        'DESTINATION_REALM': 283,
        'DISCONNECT_CAUSE': 273,
        'ERROR_MESSAGE': 281,
        'ERROR_REPORTING_HOST': 294,
        'EVENT_TIMESTAMP': 55,
        'EXPERIMENTAL_RESULT': 297,
        'EXPERIMENTAL_RESULT_CODE': 298,
        'FAILED_AVP': 279,
        'FIRMWARE_REVISION': 267,
        'HOST_IP_ADDRESS': 257,
        'INBAND_SECURITY_ID': 299,
        'MULTI_ROUND_TIME_OUT': 272,
        'ORIGIN_HOST': 264,
        'ORIGIN_REALM': 296,
        'ORIGIN_STATE_ID': 278,
        'PRODUCT_NAME': 269,
        'PROXY_HOST': 280,
        'PROXY_INFO': 284,
        'PROXY_STATE': 33,
        'REDIRECT_HOST': 292,
        'REDIRECT_HOST_USAGE': 261,
        'REDIRECT_MAX_CACHE_TIME': 262,
        'RESULT_CODE': 268,
        'ROUTE_RECORD': 282,
        'SESSION_ID': 263,
        'SESSION_TIMEOUT': 27,
        'SESSION_BINDING': 270,
        'SESSION_SERVER_FAILOVER': 271,
        'SUPPORTED_VENDOR_ID': 265,
        'TERMINATION_CAUSE': 295,
        'USER_NAME': 1,
        'VENDOR_ID': 266,
        'VENDOR_SPECIFIC_APPLICATION_ID': 260,
    }

    @property
    def vendor_flag(self):
        return (self.flags >> 7) & 0x1

    @vendor_flag.setter
    def vendor_flag(self, v):
        self.flags = (self.flags & ~0x80) | ((v & 0x1) << 7)

    @property
    def mandatory_flag(self):
        return (self.flags >> 6) & 0x1

    @mandatory_flag.setter
    def mandatory_flag(self, m):
        self.flags = (self.flags & ~0x40) | ((m & 0x1) << 6)

    @property
    def protected_flag(self):
        return (self.flags >> 5) & 0x1

    @protected_flag.setter
    def protected_flag(self, p):
        self.flags = (self.flags & ~0x20) | ((p & 0x1) << 5)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.len = (compat_ord(self.len[0]) << 16) | \
                    (compat_ord(self.len[1]) << 8) | \
                    (compat_ord(self.len[2]))
        padlen = 0 if self.len % 4 == 0 else 4 - (self.len % 4)

        if self.vendor_flag:
            self.vendor = struct.unpack('>I', self.data[:4])[0]
            self.value = self.data[4:self.len - self.__hdr_len__]
            self.data = self.data[4:self.len + padlen - self.__hdr_len__]
        else:
            self.value = self.data[:self.len - self.__hdr_len__]
            self.data = self.data[:self.len + padlen - self.__hdr_len__]

    def pack_hdr(self):
        self.len = self.__hdr_len__ + len(self.data)
        self.len = struct.pack("BBB", (self.len >> 16) & 0xff, (self.len >> 8) & 0xff, self.len & 0xff)

        data = dpkt.Packet.pack_hdr(self)
        if self.vendor_flag:
            data += struct.pack('>I', self.vendor)
        return data

    def __len__(self):
        length = self.__hdr_len__ + len(self.data)
        if self.vendor_flag:
            length += 4
        return length


# list of DWR header, Origin-Host, Origin-Realm, Origin-State-Id, Terminal-Information.
# Note that Terminal-Information has IMEI and Software-Version as its children.
__payloads_pack = [
    b'\x01\x00\x00\xbc\x80\x00\x01\x18\x00\x00\x00\x00I\x96\x02\xd2\x8b\xd085',
    b'\x00\x00\x01\x08@\x00\x007some00.node00.epc.mnc999.mcc999.3gppnetwork.org\x00',
    b'\x00\x00\x01\x16@\x00\x00\x0cyeah',
    b'\x00\x00\x01(@\x00\x00)epc.mnc999.mcc999.3gppnetwork.org\x00\x00\x00',
    b'\x00\x00\x05y\xc0\x00\x001\x00\x00(\xaf\x00\x00\x05z\xc0\x00\x00\x17\x00\x00(\xaf101234564567891',
    b'\x00\x00\x05{\xc0\x00\x00\n\x00\x00(\xaf01\x00\x00\x00'
    ]
__s = b''.join(__payloads_pack)

# list of DWR header, Origin-Host, Origin-Realm, Origin-State-Id, IMEI.
__payloads_unpack = [
    b'\x01\x00\x00\xbc\x80\x00\x01\x18\x00\x00\x00\x00I\x96\x02\xd2\x8b\xd085',
    b'\x00\x00\x01\x08@\x00\x007some00.node00.epc.mnc999.mcc999.3gppnetwork.org\x00',
    b'\x00\x00\x01\x16@\x00\x00\x0cyeah',
    b'\x00\x00\x01(@\x00\x00)epc.mnc999.mcc999.3gppnetwork.org\x00\x00\x00',
    b'\x00\x00\x05z\xc0\x00\x00\x1a\x00\x00(\xaf12345678901234\x00\x00'
    ]
__t = b''.join(__payloads_unpack)


def test_pack():
    """Packing test.
    Create 'Device-Watchdog-Request' message by inserting values in
    each field manually, then check the values are expectedly set and
    the whole payload is built as the same as test payload bytearray above.
    """
    d = Diameter(
        cmd=280,
        request_flag=1,
        proxiable_flag=0,
        app_id=0,
        hop_id=1234567890,
        end_id=2345678901,
        )

    avplist = [
        AVP(
            code=264,
            mandatory_flag=1,
            vendor_flag=0,
        ),
        AVP(
            code=278,
            mandatory_flag=1,
            vendor_flag=0,
        ),
        AVP(
            code=296,
            mandatory_flag=1,
            vendor_flag=0,
        ),
        AVP(
            code=1401,
            mandatory_flag=1,
            vendor_flag=1,
            vendor=10415
        )
    ]

    child_avplist = [
        AVP(
            code=1402,
            mandatory_flag=1,
            vendor_flag=1,
            vendor=10415
        ),
        AVP(
            code=1403,
            mandatory_flag=1,
            vendor_flag=1,
            vendor=10415
        )
    ]

    child_avplist[0].data = b'101234564567891'
    child_avplist[1].data = b'01'

    avplist[0].data = b'some00.node00.epc.mnc999.mcc999.3gppnetwork.org'
    avplist[1].data = b'yeah'
    avplist[2].data = b'epc.mnc999.mcc999.3gppnetwork.org'
    avplist[3].data = b''.join([bytes(x) for x in child_avplist])

    d.data = [bytes(x) for x in avplist]

    assert (d.cmd == d.cmd_codes['DEVICE_WATCHDOG'])
    assert (d.request_flag == 1)
    assert (d.proxiable_flag == 0)
    assert (d.app_id == 0)
    assert (d.hop_id == 1234567890)
    assert (d.end_id == 2345678901)
    assert (__s == bytes(d))


def test_unpack():
    """Unpacking test.
    Unpack the payload bytearray above and check if the values are
    expectedly decoded.
    """
    d = Diameter(__t)
    assert (d.cmd == d.cmd_codes['DEVICE_WATCHDOG'])
    assert (d.request_flag == 1)
    assert (d.proxiable_flag == 0)
    assert (d.app_id == 0)
    assert (d.hop_id == 1234567890)
    assert (d.end_id == 2345678901)

    for i in range(len(d.avps)):
        avp = d.avps[i]
        if avp.code == avp.avp_codes['ORIGIN_HOST']:
            assert (avp.mandatory_flag == 1)
            assert (avp.vendor_flag == 0)
            assert (avp.len == 55)
            assert (len(avp) == 56)
            assert (avp.value == b'some00.node00.epc.mnc999.mcc999.3gppnetwork.org')
            assert (avp.data == b'some00.node00.epc.mnc999.mcc999.3gppnetwork.org\x00')
        elif avp.code == avp.avp_codes['ORIGIN_REALM']:
            assert (avp.mandatory_flag == 1)
            assert (avp.vendor_flag == 0)
            assert (avp.len == 41)
            assert (len(avp) == 44)
            assert (avp.value == b'epc.mnc999.mcc999.3gppnetwork.org')
            assert (avp.data == b'epc.mnc999.mcc999.3gppnetwork.org\x00\x00\x00')
        elif avp.code == avp.avp_codes['ORIGIN_STATE_ID']:
            assert (avp.mandatory_flag == 1)
            assert (avp.vendor_flag == 0)
            assert (avp.len == 12)
            assert (len(avp) == 12)
            assert (avp.value == b'yeah')
            assert (avp.data == b'yeah')
        elif avp.code == 1402:
            assert (avp.mandatory_flag == 1)
            assert (avp.vendor_flag == 1)
            assert (avp.vendor == 10415)
            assert (avp.len == 26)
            assert (len(avp) == 28)
            assert (avp.value == b'12345678901234')
            assert (avp.data == b'12345678901234\x00\x00')


if __name__ == '__main__':
    test_pack()
    test_unpack()
    print('Tests Successful...')
