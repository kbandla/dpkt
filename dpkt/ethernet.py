# $Id: ethernet.py 65 2010-03-26 02:53:51Z dugsong $
# -*- coding: utf-8 -*-
"""Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
with automatic 802.1q, MPLS, PPPoE, and Cisco ISL decapsulation."""

from copy import copy
import struct

import dpkt
import stp

ETH_CRC_LEN = 4
ETH_HDR_LEN = 14

ETH_LEN_MIN = 64  # minimum frame length with CRC
ETH_LEN_MAX = 1518  # maximum frame length with CRC

ETH_MTU = (ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN)
ETH_MIN = (ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN)

# Ethernet payload types - http://standards.ieee.org/regauth/ethertype
ETH_TYPE_PUP = 0x0200  # PUP protocol
ETH_TYPE_IP = 0x0800  # IP protocol
ETH_TYPE_ARP = 0x0806  # address resolution protocol
ETH_TYPE_AOE = 0x88a2  # AoE protocol
ETH_TYPE_CDP = 0x2000  # Cisco Discovery Protocol
ETH_TYPE_DTP = 0x2004  # Cisco Dynamic Trunking Protocol
ETH_TYPE_REVARP = 0x8035  # reverse addr resolution protocol
ETH_TYPE_8021Q = 0x8100  # IEEE 802.1Q VLAN tagging
ETH_TYPE_IPX = 0x8137  # Internetwork Packet Exchange
ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol
ETH_TYPE_PPP = 0x880B  # PPP
ETH_TYPE_MPLS = 0x8847  # MPLS
ETH_TYPE_MPLS_MCAST = 0x8848  # MPLS Multicast
ETH_TYPE_PPPoE_DISC = 0x8863  # PPP Over Ethernet Discovery Stage
ETH_TYPE_PPPoE = 0x8864  # PPP Over Ethernet Session Stage
ETH_TYPE_LLDP = 0x88CC  # Link Layer Discovery Protocol


class Ethernet(dpkt.Packet):
    __hdr__ = (
        ('dst', '6s', ''),
        ('src', '6s', ''),
        ('type', 'H', ETH_TYPE_IP)
    )
    _typesw = {}

    def _unpack_data(self, buf):
        if self.type == ETH_TYPE_8021Q:
            self.vlan_tags = []

            # support up to 2 tags (double tagging aka QinQ)
            for _ in range(2):
                tag = VLANtag8021Q(buf)
                buf = buf[tag.__hdr_len__:]
                self.vlan_tags.append(tag)
                self.type = tag.type
                if self.type != ETH_TYPE_8021Q:
                    break
            # backward compatibility, use the 1st tag
            self.vlanid, self.priority, self.cfi = self.vlan_tags[0].as_tuple()

        elif self.type == ETH_TYPE_MPLS or self.type == ETH_TYPE_MPLS_MCAST:
            self.labels = []  # old list containing labels as tuples
            self.mpls_labels = []  # new list containing labels as instances of MPLSlabel

            # XXX - max # of labels is undefined, just use 24
            for i in range(24):
                lbl = MPLSlabel(buf)
                buf = buf[lbl.__hdr_len__:]
                self.mpls_labels.append(lbl)
                self.labels.append(lbl.as_tuple())
                if lbl.s:  # bottom of stack
                    break
            self.type = ETH_TYPE_IP

        try:
            self.data = self._typesw[self.type](buf)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            self.data = buf

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.type > 1500:
            # Ethernet II
            self._unpack_data(self.data)

        elif (self.dst.startswith('\x01\x00\x0c\x00\x00') or
              self.dst.startswith('\x03\x00\x0c\x00\x00')):
            # Cisco ISL
            tag = VLANtagISL(buf)
            buf = buf[tag.__hdr_len__:]
            self.vlan_tags = [tag]
            self.vlan = tag.id  # backward compatibility
            self.unpack(buf)

        elif self.data.startswith('\xff\xff'):
            # Novell "raw" 802.3
            self.type = ETH_TYPE_IPX
            self.data = self.ipx = self._typesw[ETH_TYPE_IPX](self.data[2:])

        else:
            self.data = self.llc = LLC(self.data)

    def pack_hdr(self):
        tags_buf = ''
        if getattr(self, 'mpls_labels', None):
            # mark all labels with s=0, last one with s=1
            for lbl in self.mpls_labels:
                lbl.s = 0
            lbl.s = 1

            # re-pack Eth header if necessary
            if self.type not in (ETH_TYPE_MPLS, ETH_TYPE_MPLS_MCAST):
                self.type = ETH_TYPE_MPLS
            tags_buf = ''.join(lbl.pack_hdr() for lbl in self.mpls_labels)

        elif getattr(self, 'vlan_tags', None):
            # set encapsulation types
            t1 = self.vlan_tags[0]
            if len(self.vlan_tags) == 1:
                if isinstance(t1, VLANtag8021Q):
                    t1.type = copy(self.type)
                    self.type = ETH_TYPE_8021Q
                elif isinstance(t1, VLANtagISL):
                    t1.type = 0  # 0 means Ethernet
                    return t1.pack_hdr() + dpkt.Packet.pack_hdr(self)

            elif len(self.vlan_tags) == 2:
                t2 = self.vlan_tags[1]
                if isinstance(t1, VLANtag8021Q) and isinstance(t2, VLANtag8021Q):
                    t2.type = copy(self.type)
                    self.type = t1.type = ETH_TYPE_8021Q
            else:
                raise dpkt.PackError('maximum is 2 VLAN tags per Ethernet frame')
            tags_buf = ''.join(tag.pack_hdr() for tag in self.vlan_tags)

        # if self.data is LLC then this is IEEE 802.3 Ethernet and self.type
        # then actually encodes the length of data
        if isinstance(self.data, LLC):
            self.type = len(self.data)

        return dpkt.Packet.pack_hdr(self) + tags_buf

    @classmethod
    def set_type(cls, t, pktclass):
        cls._typesw[t] = pktclass

    @classmethod
    def get_type(cls, t):
        return cls._typesw[t]


# XXX - auto-load Ethernet dispatch table from ETH_TYPE_* definitions
def __load_types():
    g = globals()
    for k, v in g.iteritems():
        if k.startswith('ETH_TYPE_'):
            name = k[9:]
            modname = name.lower()
            try:
                mod = __import__(modname, g)
                Ethernet.set_type(v, getattr(mod, name))
            except (ImportError, AttributeError):
                continue


if not Ethernet._typesw:
    __load_types()


# Misc protocols


class LLC(dpkt.Packet):
    """802.2 Logical Link Control"""

    __hdr__ = (
        ('dsap', 'B', 0xaa),   # Destination Service Access Point
        ('ssap', 'B', 0xaa),   # Source Service Access Point
        ('ctl', 'B', 3)        # Control Byte
    )
    _typesw = Ethernet._typesw

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.dsap == self.ssap == 0xaa:
            # SNAP
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
                self.data = self.ip = self._typesw[ETH_TYPE_IP](self.data)
            elif self.dsap == 0x10 or self.dsap == 0xe0:  # SAP_NETWARE{1,2}
                self.data = self.ipx = self._typesw[ETH_TYPE_IPX](self.data)
            elif self.dsap == 0x42:  # SAP_STP
                self.data = self.stp = stp.STP(self.data)

    def pack_hdr(self):
        buf = dpkt.Packet.pack_hdr(self)
        if self.dsap == self.ssap == 0xaa:  # add SNAP sublayer
            oui = getattr(self, 'oui', 0)
            buf += struct.pack('>IH', oui, self.type)[1:]
        return buf

    def __len__(self):
        return len(str(self))  # this adds SNAP header length as necessary


class MPLSlabel(dpkt.Packet):
    """A single entry in MPLS label stack"""

    __hdr__ = (
        ('_val_exp_s_ttl', 'I', 0),
    )
    # field names are according to RFC3032

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.val = (self._val_exp_s_ttl & 0xfffff000) >> 12  # label value, 20 bits
        self.exp = (self._val_exp_s_ttl & 0x00000e00) >> 9   # experimental use, 3 bits
        self.s = (self._val_exp_s_ttl & 0x00000100) >> 8     # bottom of stack flag, 1 bit
        self.ttl = self._val_exp_s_ttl & 0x000000ff          # time to live, 8 bits
        self.data = ''

    def pack_hdr(self):
        self._val_exp_s_ttl = (
            ((self.val & 0xfffff) << 12) |
            ((self.exp & 7) << 9) |
            ((self.s & 1) << 8) |
            ((self.ttl & 0xff))
        )
        return dpkt.Packet.pack_hdr(self)

    def as_tuple(self):  # backward-compatible representation
        return (self.val, self.exp, self.ttl)


class VLANtag8021Q(dpkt.Packet):
    """IEEE 802.1q VLAN tag"""

    __hdr__ = (
        ('_pri_cfi_id', 'H', 0),
        ('type', 'H', ETH_TYPE_IP)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.pri = (self._pri_cfi_id & 0xe000) >> 13   # priority, 3 bits
        self.cfi = (self._pri_cfi_id & 0x1000) >> 12   # canonical format indicator, 1 bit
        self.id = self._pri_cfi_id & 0x0fff           # VLAN id, 12 bits
        self.data = ''

    def pack_hdr(self):
        self._pri_cfi_id = (
            ((self.pri & 7) << 13) |
            ((self.cfi & 1) << 12) |
            ((self.id & 0xfff))
        )
        return dpkt.Packet.pack_hdr(self)

    def as_tuple(self):
        return (self.id, self.pri, self.cfi)


class VLANtagISL(dpkt.Packet):
    """Cisco Inter-Switch Link VLAN tag"""

    __hdr__ = (
        ('da', '5s', '\x01\x00\x0c\x00\x00'),
        ('_type_pri', 'B', 3),
        ('sa', '6s', ''),
        ('len', 'H', 0),
        ('snap', '3s', '\xaa\xaa\x03'),
        ('hsa', '3s', '\x00\x00\x0c'),
        ('_id_bpdu', 'H', 0),
        ('indx', 'H', 0),
        ('res', 'H', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.type = (self._type_pri & 0xf0) >> 4  # encapsulation type, 4 bits; 0 means Ethernet
        self.pri = self._type_pri & 0x03  # user defined bits, 2 bits are used; means priority
        self.id = self._id_bpdu >> 1  # VLAN id
        self.bpdu = self._id_bpdu & 1
        self.data = ''

    def pack_hdr(self):
        self._type_pri = ((self.type & 0xf) << 4) | (self.pri & 0x3)
        self._id_bpdu = ((self.id & 0x7fff) << 1) | (self.bpdu & 1)
        return dpkt.Packet.pack_hdr(self)


# Unit tests


def test_eth():  # TODO recheck this test
    import ip6
    s = ('\x00\xb0\xd0\xe1\x80\x72\x00\x11\x24\x8c\x11\xde\x86\xdd\x60\x00\x00\x00'
         '\x00\x28\x06\x40\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x11\x24\xff\xfe\x8c'
         '\x11\xde\xfe\x80\x00\x00\x00\x00\x00\x00\x02\xb0\xd0\xff\xfe\xe1\x80\x72'
         '\xcd\xd3\x00\x16\xff\x50\xd7\x13\x00\x00\x00\x00\xa0\x02\xff\xff\x67\xd3'
         '\x00\x00\x02\x04\x05\xa0\x01\x03\x03\x00\x01\x01\x08\x0a\x7d\x18\x3a\x61'
         '\x00\x00\x00\x00')
    eth = Ethernet(s)
    assert eth
    assert isinstance(eth.data, ip6.IP6)
    assert str(eth) == s


def test_llc():  # copied from llc.py
    s = ('\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x00\x28\x07\x27\x40\x00\x80\x06\x1d'
         '\x39\x8d\xd4\x37\x3d\x3f\xf5\xd1\x69\xc0\x5f\x01\xbb\xb2\xd6\xef\x23\x38\x2b'
         '\x4f\x08\x50\x10\x42\x04\xac\x17\x00\x00')
    llc = LLC(s)
    assert llc.type == ETH_TYPE_IP
    assert llc.data.dst == '\x3f\xf5\xd1\x69'
    assert str(llc) == s


def test_mpls_label():
    s = '\x00\x01\x0b\xff'
    m = MPLSlabel(s)
    assert m.val == 16
    assert m.exp == 5
    assert m.s == 1
    assert m.ttl == 255
    assert str(m) == s
    #print repr(m)


def test_802dot1q_tag():
    s = '\xa0\x76\x01\x65'
    t = VLANtag8021Q(s)
    assert t.pri == 5
    assert t.cfi == 0
    assert t.id == 118
    assert str(t) == s
    t.cfi = 1
    assert str(t) == '\xb0\x76\x01\x65'
    #print repr(t)


def test_isl_tag():
    s = ('\x01\x00\x0c\x00\x00\x03\x00\x02\xfd\x2c\xb8\x97\x00\x00\xaa\xaa\x03\x00\x00\x00\x04\x57'
         '\x00\x00\x00\x00')
    t = VLANtagISL(s)
    assert t.pri == 3
    assert t.id == 555
    assert t.bpdu == 1
    assert str(t) == s
    #print repr(t)


def test_eth_802dot1q():
    import ip
    s = ('\x00\x60\x08\x9f\xb1\xf3\x00\x40\x05\x40\xef\x24\x81\x00\x90\x20\x08'
         '\x00\x45\x00\x00\x34\x3b\x64\x40\x00\x40\x06\xb7\x9b\x83\x97\x20\x81'
         '\x83\x97\x20\x15\x04\x95\x17\x70\x51\xd4\xee\x9c\x51\xa5\x5b\x36\x80'
         '\x10\x7c\x70\x12\xc7\x00\x00\x01\x01\x08\x0a\x00\x04\xf0\xd4\x01\x99'
         '\xa3\xfd')
    eth = Ethernet(s)
    assert eth.cfi == 1
    assert eth.vlanid == 32
    assert eth.priority == 4
    assert len(eth.vlan_tags) == 1
    assert eth.vlan_tags[0].type == ETH_TYPE_IP
    assert isinstance(eth.data, ip.IP)

    # construction
    assert str(eth) == s
    # construction w/o the tag; eth.type is still ETH_TYPE_8021Q
    del eth.vlan_tags, eth.cfi, eth.vlanid, eth.priority
    assert str(eth) == s[:14] + s[18:]


def test_eth_802dot1q_stacked():  # 2 VLAN tags
    import arp
    import ip
    s = ('\x00\x1b\xd4\x1b\xa4\xd8\x00\x13\xc3\xdf\xae\x18\x81\x00\x00\x76\x81\x00\x00\x0a\x08\x00'
         '\x45\x00\x00\x64\x00\x0f\x00\x00\xff\x01\x92\x9b\x0a\x76\x0a\x01\x0a\x76\x0a\x02\x08\x00'
         '\xce\xb7\x00\x03\x00\x00\x00\x00\x00\x00\x00\x1f\xaf\x70\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
         '\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
         '\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
         '\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd')
    eth = Ethernet(s)
    assert len(eth.vlan_tags) == 2
    assert eth.vlan_tags[0].id == 118
    assert eth.vlan_tags[1].id == 10
    assert eth.vlan_tags[0].type == ETH_TYPE_8021Q
    assert eth.vlan_tags[1].type == ETH_TYPE_IP
    assert [t.as_tuple() for t in eth.vlan_tags] == [(118, 0, 0), (10, 0, 0)]
    assert isinstance(eth.data, ip.IP)

    # construction
    assert str(eth) == s
    # construction w/o the tags; eth.type is still ETH_TYPE_8021Q
    del eth.vlan_tags, eth.cfi, eth.vlanid, eth.priority
    assert str(eth) == s[:14] + s[22:]

    # 2 VLAN tags + ARP
    s = ('\xff\xff\xff\xff\xff\xff\xca\x03\x0d\xb4\x00\x1c\x81\x00\x00\x64\x81\x00\x00\xc8\x08\x06'
         '\x00\x01\x08\x00\x06\x04\x00\x01\xca\x03\x0d\xb4\x00\x1c\xc0\xa8\x02\xc8\x00\x00\x00\x00'
         '\x00\x00\xc0\xa8\x02\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    eth = Ethernet(s)
    assert len(eth.vlan_tags) == 2
    assert eth.vlan_tags[0].type == ETH_TYPE_8021Q
    assert eth.vlan_tags[1].type == ETH_TYPE_ARP
    assert isinstance(eth.data, arp.ARP)


def test_eth_mpls_stacked():  # 2 MPLS labels
    import ip
    s = ('\x00\x30\x96\xe6\xfc\x39\x00\x30\x96\x05\x28\x38\x88\x47\x00\x01\x20\xff\x00\x01\x01\xff'
         '\x45\x00\x00\x64\x00\x50\x00\x00\xff\x01\xa7\x06\x0a\x1f\x00\x01\x0a\x22\x00\x01\x08\x00'
         '\xbd\x11\x0f\x65\x12\xa0\x00\x00\x00\x00\x00\x53\x9e\xe0\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
         '\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
         '\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
         '\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd')
    eth = Ethernet(s)
    assert len(eth.mpls_labels) == 2
    assert eth.mpls_labels[0].val == 18
    assert eth.mpls_labels[1].val == 16
    assert eth.labels == [(18, 0, 255), (16, 0, 255)]
    assert isinstance(eth.data, ip.IP)

    # construction
    assert str(eth) == s
    # construction w/o labels; eth.type is still ETH_TYPE_MPLS
    del eth.labels, eth.mpls_labels
    assert str(eth) == s[:14] + s[22:]


def test_isl_eth_llc_stp():  # ISL VLAN - Ethernet - LLC/non-SNAP - STP
    s = ('\x01\x00\x0c\x00\x00\x03\x00\x02\xfd\x2c\xb8\x97\x00\x00\xaa\xaa\x03\x00\x00\x00\x02\x9b'
         '\x00\x00\x00\x00\x01\x80\xc2\x00\x00\x00\x00\x02\xfd\x2c\xb8\x98\x00\x26\x42\x42\x03\x00'
         '\x00\x00\x00\x00\x80\x00\x00\x02\xfd\x2c\xb8\x83\x00\x00\x00\x00\x80\x00\x00\x02\xfd\x2c'
         '\xb8\x83\x80\x26\x00\x00\x14\x00\x02\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x41\xc6'
         '\x75\xd6')
    eth = Ethernet(s)
    assert eth.vlan == 333
    assert len(eth.vlan_tags) == 1
    assert eth.vlan_tags[0].id == 333
    assert eth.vlan_tags[0].pri == 3

    # stack
    assert isinstance(eth.data, LLC)
    assert isinstance(eth.data.data, stp.STP)
    assert str(eth) == s


def test_eth_llc_snap_cdp():  # Ethernet - LLC/SNAP - CDP
    import cdp
    s = ('\x01\x00\x0c\xcc\xcc\xcc\xc4\x022k\x00\x00\x01T\xaa\xaa\x03\x00\x00\x0c \x00\x02\xb4,B'
         '\x00\x01\x00\x06R2\x00\x05\x00\xffCisco IOS Software, 3700 Software (C3745-ADVENTERPRI'
         'SEK9_SNA-M), Version 12.4(25d), RELEASE SOFTWARE (fc1)\nTechnical Support: http://www.'
         'cisco.com/techsupport\nCopyright (c) 1986-2010 by Cisco Systems, Inc.\nCompiled Wed 18'
         '-Aug-10 08:18 by prod_rel_team\x00\x06\x00\x0eCisco 3745\x00\x02\x00\x11\x00\x00\x00\x01'
         '\x01\x01\xcc\x00\x04\n\x00\x00\x02\x00\x03\x00\x13FastEthernet0/0\x00\x04\x00\x08\x00'
         '\x00\x00)\x00\t\x00\x04\x00\x0b\x00\x05\x00')
    eth = Ethernet(s)

    # stack
    assert isinstance(eth.data, LLC)
    assert isinstance(eth.data.data, cdp.CDP)
    assert len(eth.data.data.data) == 8  # number of CDP TLVs; ensures they are decoded
    assert str(eth) == s


if __name__ == '__main__':
    test_eth()
    test_llc()
    test_mpls_label()
    test_802dot1q_tag()
    test_isl_tag()

    test_eth_802dot1q()
    test_eth_802dot1q_stacked()
    test_eth_mpls_stacked()
    test_isl_eth_llc_stp()
    test_eth_llc_snap_cdp()

    print 'Tests Successful...'
