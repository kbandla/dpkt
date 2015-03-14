# $Id: diameter.py 23 2006-11-08 15:45:33Z dugsong $

"""Diameter."""

import struct
import dpkt
from configs.decorators import deprecated_method_decorator

# Diameter Base Protocol - RFC 3588
# http://tools.ietf.org/html/rfc3588

# Request/Answer Command Codes
ABORT_SESSION = 274
ACCOUTING = 271
CAPABILITIES_EXCHANGE = 257
DEVICE_WATCHDOG = 280
DISCONNECT_PEER = 282
RE_AUTH = 258
SESSION_TERMINATION = 275


class Diameter(dpkt.Packet):
    __hdr__ = (
        ('v', 'B', 1),
        ('len', '3s', 0),
        ('flags', 'B', 0),
        ('cmd', '3s', 0),
        ('app_id', 'I', 0),
        ('hop_id', 'I', 0),
        ('end_id', 'I', 0)
    )

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
    @deprecated_method_decorator
    def _get_r(self): return self.request_flag

    @deprecated_method_decorator
    def _set_r(self, r): self.request_flag = r
    @deprecated_method_decorator
    def _get_p(self): return self.proxiable_flag

    @deprecated_method_decorator
    def _set_p(self, p): self.proxiable_flag = p

    @deprecated_method_decorator
    def _get_e(self): return self.error_flag

    @deprecated_method_decorator
    def _set_e(self, e): self.error_flag = e

    @deprecated_method_decorator
    def _get_t(self): return self.request_flag

    @deprecated_method_decorator
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
        self.len = chr((self.len >> 16) & 0xff) + chr((self.len >> 8) & 0xff) + chr(self.len & 0xff)
        self.cmd = chr((self.cmd >> 16) & 0xff) + chr((self.cmd >> 8) & 0xff) + chr(self.cmd & 0xff)
        return dpkt.Packet.pack_hdr(self)

    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.data))

    def __str__(self):
        return self.pack_hdr() + ''.join(map(str, self.data))


class AVP(dpkt.Packet):
    __hdr__ = (
        ('code', 'I', 0),
        ('flags', 'B', 0),
        ('len', '3s', 0),
    )

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
    @deprecated_method_decorator
    def _get_v(self): return self.vendor_flag

    @deprecated_method_decorator
    def _set_v(self, v): self.vendor_flag = v

    @deprecated_method_decorator
    def _get_m(self): return self.mandatory_flag

    @deprecated_method_decorator
    def _set_m(self, m): self.mandatory_flag = m

    @deprecated_method_decorator
    def _get_p(self): return self.protected_flag

    @deprecated_method_decorator
    def _set_p(self, p): self.protected_flag = p
    # ======================================================

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.len = (ord(self.len[0]) << 16) | (ord(self.len[1]) << 8) | (ord(self.len[2]))

        if self.vendor_flag:
            self.vendor = struct.unpack('>I', self.data[:4])[0]
            self.data = self.data[4:self.len - self.__hdr_len__]
        else:
            self.data = self.data[:self.len - self.__hdr_len__]

    def pack_hdr(self):
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


if __name__ == '__main__':
    import unittest

    class DiameterTestCase(unittest.TestCase):
        def testPack(self):
            d = Diameter(self.s)
            self.failUnless(self.s == str(d))
            d = Diameter(self.t)
            self.failUnless(self.t == str(d))

        def testUnpack(self):
            d = Diameter(self.s)
            self.failUnless(d.len == 40)
            # self.failUnless(d.cmd == DEVICE_WATCHDOG_REQUEST)
            self.failUnless(d.request_flag == 1)
            self.failUnless(d.error_flag == 0)
            self.failUnless(len(d.avps) == 2)

            avp = d.avps[0]
            # self.failUnless(avp.code == ORIGIN_HOST)
            self.failUnless(avp.mandatory_flag == 1)
            self.failUnless(avp.vendor_flag == 0)
            self.failUnless(avp.len == 12)
            self.failUnless(len(avp) == 12)
            self.failUnless(avp.data == '\x68\x30\x30\x32')

            # also test the optional vendor id support
            d = Diameter(self.t)
            self.failUnless(d.len == 44)
            avp = d.avps[0]
            self.failUnless(avp.vendor_flag == 1)
            self.failUnless(avp.len == 16)
            self.failUnless(len(avp) == 16)
            self.failUnless(avp.vendor == 3735928559)
            self.failUnless(avp.data == '\x68\x30\x30\x32')

        s = '\x01\x00\x00\x28\x80\x00\x01\x18\x00\x00\x00\x00\x00\x00\x41\xc8\x00\x00\x00\x0c\x00\x00\x01\x08\x40\x00\x00\x0c\x68\x30\x30\x32\x00\x00\x01\x28\x40\x00\x00\x08'
        t = '\x01\x00\x00\x2c\x80\x00\x01\x18\x00\x00\x00\x00\x00\x00\x41\xc8\x00\x00\x00\x0c\x00\x00\x01\x08\xc0\x00\x00\x10\xde\xad\xbe\xef\x68\x30\x30\x32\x00\x00\x01\x28\x40\x00\x00\x08'

    unittest.main()
