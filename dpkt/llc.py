# -*- coding: utf-8 -*-

import struct
import dpkt
import stp
import ethernet


class LLC(dpkt.Packet):
    """802.2 Logical Link Control"""

    __hdr__ = (
        ('dsap', 'B', 0xaa),   # Destination Service Access Point
        ('ssap', 'B', 0xaa),   # Source Service Access Point
        ('ctl', 'B', 3)        # Control Byte
    )
    _typesw = {}

    def __init__(self, *args, **kwargs):
        # late init to prevent circular reference import issues with ethernet.py
        self._typesw = ethernet.Ethernet._typesw
        dpkt.Packet.__init__(self, *args, **kwargs)

    @property
    def is_snap(self):
        return self.dsap == self.ssap == 0xaa

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.is_snap:
            self.oui, self.type = struct.unpack('>IH', '\x00' + self.data[:5])
            self.data = self.data[5:]
            try:
                self.data = self._typesw[self.type](self.data)
                setattr(self, self.data.__class__.__name__.lower(), self.data)
            except (KeyError, dpkt.UnpackError):
                pass
        else:
            # non-SNAP
            if self.dsap == 0x06:  # SAP_IP
                self.data = self.ip = self._typesw[ethernet.ETH_TYPE_IP](self.data)
            elif self.dsap == 0x10 or self.dsap == 0xe0:  # SAP_NETWARE{1,2}
                self.data = self.ipx = self._typesw[ethernet.ETH_TYPE_IPX](self.data)
            elif self.dsap == 0x42:  # SAP_STP
                self.data = self.stp = stp.STP(self.data)

    def pack_hdr(self):
        buf = dpkt.Packet.pack_hdr(self)
        if self.is_snap:  # add SNAP sublayer
            oui = getattr(self, 'oui', 0)
            buf += struct.pack('>IH', oui, self.type)[1:]
        return buf

    def __len__(self):  # add 5 bytes of SNAP header if needed
        return self.__hdr_len__ + 5 * int(self.is_snap) + len(self.data)


def test_llc():
    s = ('\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x00\x28\x07\x27\x40\x00\x80\x06\x1d'
         '\x39\x8d\xd4\x37\x3d\x3f\xf5\xd1\x69\xc0\x5f\x01\xbb\xb2\xd6\xef\x23\x38\x2b'
         '\x4f\x08\x50\x10\x42\x04\xac\x17\x00\x00')
    llc_pkt = LLC(s)
    ip_pkt = llc_pkt.data
    assert (llc_pkt.type == ethernet.ETH_TYPE_IP)
    assert (ip_pkt.dst == '\x3f\xf5\xd1\x69')
    assert str(llc_pkt) == s
    assert len(llc_pkt) == len(s)


if __name__ == '__main__':
    test_llc()
    print 'Tests Successful...'
