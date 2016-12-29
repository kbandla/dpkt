# $Id: diameter.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Diameter."""

import struct
import dpkt
from decorators import deprecated

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

    # Deprecated methods, will be removed in the future
    # ======================================================
    @deprecated('request_flag')
    def _get_r(self): return self.request_flag

    @deprecated('request_flag')
    def _set_r(self, r): self.request_flag = r

    @deprecated('proxiable_flag')
    def _get_p(self): return self.proxiable_flag

    @deprecated('proxiable_flag')
    def _set_p(self, p): self.proxiable_flag = p

    @deprecated('error_flag')
    def _get_e(self): return self.error_flag

    @deprecated('error_flag')
    def _set_e(self, e): self.error_flag = e

    @deprecated('request_flag')
    def _get_t(self): return self.request_flag

    @deprecated('request_flag')
    def _set_t(self, t): self.request_flag = t
    # ======================================================

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.cmd = (ord(self.cmd[0]) << 16) | (ord(self.cmd[1]) << 8) | (ord(self.cmd[2]))
        self.len = (ord(self.len[0]) << 16) | (ord(self.len[1]) << 8) | (ord(self.len[2]))
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
            padding = struct.pack(str(padlen) + 's', '')
            l.append(str(d) + padding)
        self.data = self.avps = b''.join(l)

        self.len = self.__hdr_len__ + len(str(self.data))
        self.len = chr((self.len >> 16) & 0xff) + chr((self.len >> 8) & 0xff) + chr(self.len & 0xff)
        self.cmd = chr((self.cmd >> 16) & 0xff) + chr((self.cmd >> 8) & 0xff) + chr(self.cmd & 0xff)

        return dpkt.Packet.pack_hdr(self)

    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.data))

    def __str__(self):
        return self.pack_hdr() + ''.join(map(str, self.data))


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

    # Deprecated methods, will be removed in the future
    # ======================================================
    @deprecated('vendor_flag')
    def _get_v(self):
        return self.vendor_flag

    @deprecated('vendor_flag')
    def _set_v(self, v):
        self.vendor_flag = v

    @deprecated('mandatory_flag')
    def _get_m(self):
        return self.mandatory_flag

    @deprecated('mandatory_flag')
    def _set_m(self, m):
        self.mandatory_flag = m

    @deprecated('protected_flag')
    def _get_p(self):
        return self.protected_flag

    @deprecated('protected_flag')
    def _set_p(self, p):
        self.protected_flag = p
    # ======================================================

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.len = (ord(self.len[0]) << 16) | (ord(self.len[1]) << 8) | (ord(self.len[2]))
        padlen = 0 if self.len % 4 == 0 else 4 - (self.len % 4)

        if self.vendor_flag:
            self.vendor = struct.unpack('>I', self.data[:4])[0]
            self.data = self.data[4:self.len + padlen - self.__hdr_len__]
        else:
            self.data = self.data[:self.len + padlen - self.__hdr_len__]

    def pack_hdr(self):
        self.len = self.__hdr_len__ + sum(map(len, str(self.data)))
        self.len = chr((self.len >> 16) & 0xff) + chr((self.len >> 8) & 0xff) + chr(self.len & 0xff)

        data = dpkt.Packet.pack_hdr(self)
        if self.vendor_flag:
            data += struct.pack('>I', self.vendor)
        return data

    def __len__(self):
        length = self.__hdr_len__ + sum(map(len, self.data))
        if self.vendor_flag:
            length += 4
        return length


# list of DWR header, Origin-Host, Origin-Realm Origin-State-Id.
__payloads = [
    b'\x01\x00\x00\x84\x80\x00\x01\x18\x00\x00\x00\x00I\x96\x02\xd2\x8b\xd085',
    b'\x00\x00\x01\x08@\x00\x007some00.node00.epc.mnc999.mcc999.3gppnetwork.org\x00',
    b'\x00\x00\x01\x16@\x00\x00\x0cyeah',
    b'\x00\x00\x01(@\x00\x00)epc.mnc999.mcc999.3gppnetwork.org\x00\x00\x00'
    ]
__s = b''.join(__payloads)


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

    # using OrderdDict to keep the order of AVPs.
    avpdict = OrderedDict()
    avps = (
        ('avp_orighost', AVP(
            code=264,
            mandatory_flag=1,
            vendor_flag=0,
            )
        ),
        ('avp_origstateid', AVP(
            code=278,
            mandatory_flag=1,
            vendor_flag=0,
            )
        ),
        ('avp_origrealm', AVP(
            code=296,
            mandatory_flag=1,
            vendor_flag=0,
            )
        )
    )
    avpdict.update(avps)

    avpdict['avp_orighost'].data = 'some00.node00.epc.mnc999.mcc999.3gppnetwork.org'
    avpdict['avp_origstateid'].data = 'yeah'
    avpdict['avp_origrealm'].data = 'epc.mnc999.mcc999.3gppnetwork.org'
    d.data = [str(v) for k, v in avpdict.iteritems()]

    assert (d.cmd == d.cmd_codes['DEVICE_WATCHDOG'])
    assert (d.request_flag == 1)
    assert (d.proxiable_flag == 0)
    assert (d.app_id == 0)
    assert (d.hop_id == 1234567890)
    assert (d.end_id == 2345678901)
    assert (__s == str(d))

def test_unpack():
    """Packing test.
    Unpack the payload bytearray above and check if the values are
    expectedly decoded.
    """
    d = Diameter(__s)
    assert (d.cmd == d.cmd_codes['DEVICE_WATCHDOG'])
    assert (d.request_flag == 1)
    assert (d.proxiable_flag == 0)
    assert (d.app_id == 0)
    assert (d.hop_id == 1234567890)
    assert (d.end_id == 2345678901)

    for i in xrange(len(d.avps)):
        avp = d.avps[i]
        if avp.code == avp.avp_codes['ORIGIN_HOST']:
            assert (avp.mandatory_flag == 1)
            assert (avp.vendor_flag == 0)
            assert (avp.len == 55)
            assert (len(avp) == 56)
            assert (avp.data == b'some00.node00.epc.mnc999.mcc999.3gppnetwork.org\x00')
        if avp.code == avp.avp_codes['ORIGIN_REALM']:
            assert (avp.mandatory_flag == 1)
            assert (avp.vendor_flag == 0)
            assert (avp.len == 41)
            assert (len(avp) == 44)
            assert (avp.data == b'epc.mnc999.mcc999.3gppnetwork.org\x00\x00\x00')
        if avp.code == avp.avp_codes['ORIGIN_STATE_ID']:
            assert (avp.mandatory_flag == 1)
            assert (avp.vendor_flag == 0)
            assert (avp.len == 12)
            assert (len(avp) == 12)
            assert (avp.data == 'yeah')


if __name__ == '__main__':
    from collections import OrderedDict

    test_pack()
    test_unpack()
    print 'Tests Successful...'
