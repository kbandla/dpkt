# $Id: tns.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Transparent Network Substrate."""

import dpkt


class TNS(dpkt.Packet):
    __hdr__ = (
        ('length', 'H', 0),
        ('pktsum', 'H', 0),
        ('type', 'B', 0),
        ('rsvd', 'B', 0),
        ('hdrsum', 'H', 0),
        ('msg', '0s', ''),
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        n = self.length - self.__hdr_len__
        if n > len(self.data):
            raise dpkt.NeedData('short message (missing %d bytes)' %
                                (n - len(self.data)))
        self.msg = self.data[:n]
        self.data = self.data[n:]


def test_tns():
    s = ('\x00\x23\x00\x00\x01\x00\x00\x00\x01\x34\x01\x2c\x00\x00\x08\x00\x7f'
         '\xff\x4f\x98\x00\x00\x00\x01\x00\x01\x00\x22\x00\x00\x00\x00\x01\x01X')
    t = TNS(s)
    assert t.msg.startswith('\x01\x34')

    # test a truncated packet
    try:
        t = TNS(s[:-10])
    except dpkt.NeedData:
        pass


if __name__ == '__main__':
    test_tns()

    print 'Tests Successful...'
