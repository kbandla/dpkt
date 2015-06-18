# $Id: vrrp.py 88 2013-03-05 19:43:17Z andrewflnr@gmail.com $
# -*- coding: utf-8 -*-
"""Virtual Router Redundancy Protocol."""

import dpkt
from decorators import deprecated


class VRRP(dpkt.Packet):
    __hdr__ = (
        ('_v_type', 'B', 0x21),
        ('vrid', 'B', 0),
        ('priority', 'B', 0),
        ('count', 'B', 0),
        ('atype', 'B', 0),
        ('advtime', 'B', 0),
        ('sum', 'H', 0),
    )
    addrs = ()
    auth = ''

    @property
    def v(self):  # high 4 bits of _v_type
        return self._v_type >> 4

    @v.setter
    def v(self, v):
        self._v_type = (self._v_type & 0x0f) | (v << 4)

    @property
    def type(self):  # low 4 bits of _v_type
        return self._v_type & 0x0f

    @type.setter
    def type(self, v):
        self._v_type = (self._v_type & 0xf0) | (v & 0x0f)

    # Deprecated methods, will be removed in the future
    # =================================================
    @deprecated('v')
    def _get_v(self): return self.v

    @deprecated('v')
    def _set_v(self, v): self.v = v

    @deprecated('type')
    def _get_type(self): return self.type

    @deprecated('type')
    def _set_type(self, v): self.type = v
    # =================================================

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        l = []
        off = 0
        for off in range(0, 4 * self.count, 4):
            l.append(self.data[off:off + 4])
        self.addrs = l
        self.auth = self.data[off + 4:]
        self.data = ''

    def __len__(self):
        return self.__hdr_len__ + (4 * self.count) + len(self.auth)

    def __str__(self):
        data = ''.join(self.addrs) + self.auth
        if not self.sum:
            self.sum = dpkt.in_cksum(self.pack_hdr() + data)
        return self.pack_hdr() + data


def test_vrrp():
    # no addresses
    s = '\x00\x00\x00\x00\x00\x00\xff\xff'
    v = VRRP(s)
    assert v.sum == 0xffff
    assert str(v) == s

    # have address
    s = '\x21\x01\x64\x01\x00\x01\xba\x52\xc0\xa8\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00'
    v = VRRP(s)
    assert v.count == 1
    assert v.addrs == ['\xc0\xa8\x00\x01']  # 192.168.0.1
    assert str(v) == s

    # test checksum generation
    v.sum = 0
    assert str(v) == s

    # test length
    assert len(v) == len(s)

    # test getters
    assert v.v == 2
    assert v.type == 1

    # test setters
    v.v = 3
    v.type = 2
    assert str(v)[0] == '\x32'


if __name__ == '__main__':
    test_vrrp()

    print 'Tests Successful...'
