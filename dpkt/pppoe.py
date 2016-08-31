# $Id: pppoe.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""PPP-over-Ethernet."""

import dpkt
import ppp
import struct
from decorators import deprecated

# RFC 2516 codes
PPPoE_PADI = 0x09
PPPoE_PADO = 0x07
PPPoE_PADR = 0x19
PPPoE_PADS = 0x65
PPPoE_PADT = 0xA7
PPPoE_SESSION = 0x00


class PPPoE(dpkt.Packet):
    """PPP-over-Ethernet.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of PPPoE.
        TODO.
    """
    
    __hdr__ = (
        ('_v_type', 'B', 0x11),
        ('code', 'B', 0),
        ('session', 'H', 0),
        ('len', 'H', 0)  # payload length
    )

    @property
    def v(self):
        return self._v_type >> 4

    @v.setter
    def v(self, v):
        self._v_type = (v << 4) | (self._v_type & 0xf)

    @property
    def type(self):
        return self._v_type & 0xf

    @type.setter
    def type(self, t):
        self._v_type = (self._v_type & 0xf0) | t

    # Deprecated methods, will be removed in the future
    # =================================================
    @deprecated('v')
    def _get_v(self): return self.v

    @deprecated('v')
    def _set_v(self, v): self.v = v

    @deprecated('type')
    def _get_type(self): return self.type

    @deprecated('type')
    def _set_type(self, t): self.type = t
    # =================================================

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        try:
            if self.code == 0:
                # We need to use the pppoe.PPP header here, because PPPoE
                # doesn't do the normal encapsulation.
                self.data = self.ppp = PPP(self.data)
        except dpkt.UnpackError:
            pass


class PPP(ppp.PPP):
    # Light version for protocols without the usual encapsulation, for PPPoE
    __hdr__ = (
        # Usuaully two-bytes, but while protocol compression is not recommended, it is supported
        ('p', 'B', ppp.PPP_IP),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.p & ppp.PFC_BIT == 0:
            try:
                self.p = struct.unpack('>H', buf[:2])[0]
            except struct.error:
                raise dpkt.NeedData
            self.data = self.data[1:]
        try:
            self.data = self._protosw[self.p](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, struct.error, dpkt.UnpackError):
            pass

    def pack_hdr(self):
        try:
            # Protocol compression is *not* recommended (RFC2516), but we do it anyway
            if self.p > 0xff:
                return struct.pack('>H', self.p)
            return dpkt.Packet.pack_hdr(self)
        except struct.error, e:
            raise dpkt.PackError(str(e))


def test_pppoe_discovery():
    s = (b"11070000002801010000010300046413"
         b"85180102000442524153010400103d0f"
         b"0587062484f2df32b9ddfd77bd5b").decode('hex')

    p = PPPoE(s)

    assert p.code == PPPoE_PADO
    assert p.v == 1
    assert p.type == 1

    s = (b"11190000002801010000010300046413"
         b"85180102000442524153010400103d0f"
         b"0587062484f2df32b9ddfd77bd5b").decode('hex')

    p = PPPoE(s)

    assert p.code == PPPoE_PADR

    assert p.pack_hdr() == s[:6]


def test_pppoe_session():
    s = b"11000011000cc0210101000a050605fcd459".decode('hex')

    p = PPPoE(s)

    assert p.code == PPPoE_SESSION
    assert isinstance(p.ppp, PPP)
    assert p.data.p == 0xc021   # LCP
    assert len(p.data.data) == 10

    assert p.data.pack_hdr() == b"\xc0\x21"

    s = (b"110000110066005760000000003c3a40fc000000000000000000000000000001"
         b"fc0000000002010000000000000100018100bf291f9700010102030405060708"
         b"090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728"
         b"292a2b2c2d2e2f3031323334").decode("hex")

    p = PPPoE(s)
    assert p.code == PPPoE_SESSION
    assert isinstance(p.ppp, PPP)
    assert p.data.p == ppp.PPP_IP6
    assert p.data.data.p == 58   # ICMPv6

    assert p.ppp.pack_hdr() == b"\x57"


def test_ppp_packing():
    p = PPP()
    assert p.pack_hdr() == b"\x21"

    p.p = 0xc021   # LCP
    assert p.pack_hdr() == b"\xc0\x21"


def test_ppp_short():
    import pytest
    pytest.raises(dpkt.NeedData, PPP, b"\x00")


# XXX - TODO TLVs, etc.
