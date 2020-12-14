# $Id: ethernet.py 65 2010-03-26 02:53:51Z dugsong $
# -*- coding: utf-8 -*-
"""Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
with automatic 802.1q, MPLS, PPPoE, and Cisco ISL decapsulation."""
from __future__ import print_function
from __future__ import absolute_import

import struct
from zlib import crc32

from . import dpkt
from . import llc
from .compat import compat_ord, iteritems

try:
    isinstance("", basestring)
    def isstr(s):
        return isinstance(s, basestring)
except NameError:
    def isstr(s):
        return isinstance(s, str)

ETH_CRC_LEN = 4
ETH_HDR_LEN = 14

ETH_LEN_MIN = 64  # minimum frame length with CRC
ETH_LEN_MAX = 1518  # maximum frame length with CRC

ETH_MTU = (ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN)
ETH_MIN = (ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN)

# Ethernet payload types - http://standards.ieee.org/regauth/ethertype
ETH_TYPE_UNKNOWN = 0x0000
ETH_TYPE_EDP = 0x00bb  # Extreme Networks Discovery Protocol
ETH_TYPE_PUP = 0x0200  # PUP protocol
ETH_TYPE_IP = 0x0800  # IP protocol
ETH_TYPE_ARP = 0x0806  # address resolution protocol
ETH_TYPE_AOE = 0x88a2  # AoE protocol
ETH_TYPE_CDP = 0x2000  # Cisco Discovery Protocol
ETH_TYPE_DTP = 0x2004  # Cisco Dynamic Trunking Protocol
ETH_TYPE_REVARP = 0x8035  # reverse addr resolution protocol
ETH_TYPE_8021Q = 0x8100  # IEEE 802.1Q VLAN tagging
ETH_TYPE_8021AD = 0x88a8  # IEEE 802.1ad
ETH_TYPE_QINQ1 = 0x9100  # Legacy QinQ
ETH_TYPE_QINQ2 = 0x9200  # Legacy QinQ
ETH_TYPE_IPX = 0x8137  # Internetwork Packet Exchange
ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol
ETH_TYPE_PPP = 0x880B  # PPP
ETH_TYPE_MPLS = 0x8847  # MPLS
ETH_TYPE_MPLS_MCAST = 0x8848  # MPLS Multicast
ETH_TYPE_PPPoE_DISC = 0x8863  # PPP Over Ethernet Discovery Stage
ETH_TYPE_PPPoE = 0x8864  # PPP Over Ethernet Session Stage
ETH_TYPE_LLDP = 0x88CC  # Link Layer Discovery Protocol
ETH_TYPE_TEB = 0x6558  # Transparent Ethernet Bridging
ETH_TYPE_PROFINET = 0x8892  # PROFINET protocol

# all QinQ types for fast checking
_ETH_TYPES_QINQ = frozenset([ETH_TYPE_8021Q, ETH_TYPE_8021AD, ETH_TYPE_QINQ1, ETH_TYPE_QINQ2])


class Ethernet(dpkt.Packet):
    """Ethernet.

    Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
    with automatic 802.1q, MPLS, PPPoE, and Cisco ISL decapsulation.

    Attributes:
        __hdr__: Header fields of Ethernet.
        TODO.
    """

    __hdr__ = (
        ('dst', '6s', b''),
        ('src', '6s', b''),
        ('type', 'H', ETH_TYPE_IP)
    )
    _typesw = {}
    _typesw_rev = {}  # reverse mapping

    def __init__(self, *args, **kwargs):
        self._next_type = None
        dpkt.Packet.__init__(self, *args, **kwargs)
        # if data was given in kwargs, try to unpack it
        if self.data:
            if isstr(self.data) or isinstance(self.data, bytes):
                self._unpack_data(self.data)

    def _unpack_data(self, buf):
        # unpack vlan tag and mpls label stacks
        if self._next_type in _ETH_TYPES_QINQ:
            self.vlan_tags = []

            # support up to 2 tags (double tagging aka QinQ)
            for _ in range(2):
                tag = VLANtag8021Q(buf)
                buf = buf[tag.__hdr_len__:]
                self.vlan_tags.append(tag)
                self._next_type = tag.type
                if self._next_type != ETH_TYPE_8021Q:
                    break
            # backward compatibility, use the 1st tag
            self.vlanid, self.priority, self.cfi = self.vlan_tags[0].as_tuple()

        elif self._next_type == ETH_TYPE_MPLS or self._next_type == ETH_TYPE_MPLS_MCAST:
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

            # poor man's heuristics to guessing the next type
            if compat_ord(buf[0]) == 0x45:  # IP version 4 + header len 20 bytes
                self._next_type = ETH_TYPE_IP

            # pseudowire Ethernet
            elif len(buf) >= self.__hdr_len__:
                if buf[:2] == b'\x00\x00':  # looks like the control word (ECW)
                    buf = buf[4:]  # skip the ECW
                self._next_type = ETH_TYPE_TEB  # re-use TEB class mapping to decode Ethernet

        try:
            eth_type = self._next_type or self.type
            self.data = self._typesw[eth_type](buf)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            self.data = buf

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.type > 1500:
            # Ethernet II
            self._next_type = self.type
            self._unpack_data(self.data)

        elif (self.dst.startswith(b'\x01\x00\x0c\x00\x00') or
              self.dst.startswith(b'\x03\x00\x0c\x00\x00')):
            # Cisco ISL
            tag = VLANtagISL(buf)
            buf = buf[tag.__hdr_len__:]
            self.vlan_tags = [tag]
            self.vlan = tag.id  # backward compatibility
            self.unpack(buf)

        elif self.data.startswith(b'\xff\xff'):
            # Novell "raw" 802.3
            self.type = ETH_TYPE_IPX
            self.data = self.ipx = self._typesw[ETH_TYPE_IPX](self.data[2:])

        elif self.type == ETH_TYPE_UNKNOWN:
            # Unknown type, assume Ethernet
            self._unpack_data(self.data)

        else:
            # IEEE 802.3 Ethernet - LLC
            # try to unpack FCS here; we follow the same heuristic approach as Wireshark:
            # if the upper layer len(self.data) can be fully decoded and returns its size,
            # and there's a difference with size in the Eth header, then assume the last
            # 4 bytes is the FCS and remaining bytes are a trailer.
            eth_len = self.len = self.type
            if len(self.data) > eth_len:
                tail_len = len(self.data) - eth_len
                if tail_len >= 4:
                    # if the last 4 bytes are zeroes that's unlikely a FCS
                    if self.data[-4:] == b'\x00\x00\x00\x00':
                        self.trailer = self.data[eth_len:]
                    else:
                        self.fcs = struct.unpack('>I', self.data[-4:])[0]
                        self.trailer = self.data[eth_len:-4]
            self.data = self.llc = llc.LLC(self.data[:eth_len])

    def pack_hdr(self):
        tags_buf = b''
        new_type = self.type  # replacement self.type when packing eth header
        is_isl = False  # ISL wraps Ethernet, this determines order of packing

        if getattr(self, 'mpls_labels', None):
            # mark all labels with s=0, last one with s=1
            for lbl in self.mpls_labels:
                lbl.s = 0
            lbl.s = 1

            # set encapsulation type
            if new_type not in (ETH_TYPE_MPLS, ETH_TYPE_MPLS_MCAST):
                new_type = ETH_TYPE_MPLS
            tags_buf = b''.join(lbl.pack_hdr() for lbl in self.mpls_labels)

        elif getattr(self, 'vlan_tags', None):
            # set last tag type to next layer pointed by self.data
            last_tag_type = self.type  # default
            if isinstance(self.data, dpkt.Packet):
                last_tag_type = self._typesw_rev.get(self.data.__class__, self.type)

            # set encapsulation types
            t1 = self.vlan_tags[0]
            if len(self.vlan_tags) == 1:
                if isinstance(t1, VLANtag8021Q):
                    if new_type not in _ETH_TYPES_QINQ:  # preserve the type if already set
                        new_type = ETH_TYPE_8021Q
                    t1.type = last_tag_type
                elif isinstance(t1, VLANtagISL):
                    t1.type = 0  # 0 means Ethernet
                    is_isl = True
            elif len(self.vlan_tags) == 2:
                t2 = self.vlan_tags[1]
                if isinstance(t1, VLANtag8021Q) and isinstance(t2, VLANtag8021Q):
                    t1.type = ETH_TYPE_8021Q
                    if new_type not in _ETH_TYPES_QINQ:
                        new_type = ETH_TYPE_8021AD
                t2.type = last_tag_type
            else:
                raise dpkt.PackError('maximum is 2 VLAN tags per Ethernet frame')
            tags_buf = b''.join(tag.pack_hdr() for tag in self.vlan_tags)

        # initial type is based on next layer, pointed by self.data;
        # try to find an ETH_TYPE matching the data class
        elif isinstance(self.data, dpkt.Packet):
            new_type = self._typesw_rev.get(self.data.__class__, new_type)

        # if self.data is LLC then this is IEEE 802.3 Ethernet and self.type
        # then actually encodes the length of data
        if isinstance(self.data, llc.LLC):
            new_type = len(self.data)

        hdr_buf = dpkt.Packet.pack_hdr(self)[:-2] + struct.pack('>H', new_type)
        if not is_isl:
            return hdr_buf + tags_buf
        else:
            return tags_buf + hdr_buf

    def __str__(self):
        tail = b''
        if isinstance(self.data, llc.LLC):
            if hasattr(self, 'fcs'):
                if self.fcs:
                    fcs = self.fcs
                else:
                    # if fcs field is present but 0/None, then compute it and add to the tail
                    fcs_buf = self.pack_hdr() + bytes(self.data) + getattr(self, 'trailer', '')
                    # if ISL header is present, exclude it from the calculation
                    if getattr(self, 'vlan_tags', None):
                        if isinstance(self.vlan_tags[0], VLANtagISL):
                            fcs_buf = fcs_buf[VLANtagISL.__hdr_len__:]
                    revcrc = crc32(fcs_buf) & 0xffffffff
                    fcs = struct.unpack('<I', struct.pack('>I', revcrc))[0]  # bswap32
                tail = getattr(self, 'trailer', b'') + struct.pack('>I', fcs)
        return str(dpkt.Packet.__bytes__(self) + tail)

    def __len__(self):
        tags = getattr(self, 'mpls_labels', []) + getattr(self, 'vlan_tags', [])
        _len = dpkt.Packet.__len__(self) + sum(t.__hdr_len__ for t in tags)
        if isinstance(self.data, llc.LLC) and hasattr(self, 'fcs'):
            _len += len(getattr(self, 'trailer', '')) + 4
        return _len

    @classmethod
    def set_type(cls, t, pktclass):
        cls._typesw[t] = pktclass
        cls._typesw_rev[pktclass] = t

    @classmethod
    def get_type(cls, t):
        return cls._typesw[t]

    @classmethod
    def get_type_rev(cls, k):
        return cls._typesw_rev[k]


# XXX - auto-load Ethernet dispatch table from ETH_TYPE_* definitions
def __load_types():
    g = globals()
    for k, v in iteritems(g):
        if k.startswith('ETH_TYPE_'):
            name = k[9:]
            modname = name.lower()
            try:
                mod = __import__(modname, g, level=1)
                Ethernet.set_type(v, getattr(mod, name))
            except (ImportError, AttributeError):
                continue
    # add any special cases below
    Ethernet.set_type(ETH_TYPE_TEB, Ethernet)


def _mod_init():
    """Post-initialization called when all dpkt modules are fully loaded"""
    if not Ethernet._typesw:
        __load_types()


# Misc protocols


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
        self.data = b''

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
        self.data = b''

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
        ('da', '5s', b'\x01\x00\x0c\x00\x00'),
        ('_type_pri', 'B', 3),
        ('sa', '6s', b''),
        ('len', 'H', 0),
        ('snap', '3s', b'\xaa\xaa\x03'),
        ('hsa', '3s', b'\x00\x00\x0c'),
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
        self.data = b''

    def pack_hdr(self):
        self._type_pri = ((self.type & 0xf) << 4) | (self.pri & 0x3)
        self._id_bpdu = ((self.id & 0x7fff) << 1) | (self.bpdu & 1)
        return dpkt.Packet.pack_hdr(self)


# Unit tests


def test_eth():
    from . import ip  # IPv6 needs this to build its protocol stack
    from . import ip6
    from . import tcp
    s = (b'\x00\xb0\xd0\xe1\x80\x72\x00\x11\x24\x8c\x11\xde\x86\xdd\x60\x00\x00\x00'
         b'\x00\x28\x06\x40\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x11\x24\xff\xfe\x8c'
         b'\x11\xde\xfe\x80\x00\x00\x00\x00\x00\x00\x02\xb0\xd0\xff\xfe\xe1\x80\x72'
         b'\xcd\xd3\x00\x16\xff\x50\xd7\x13\x00\x00\x00\x00\xa0\x02\xff\xff\x67\xd3'
         b'\x00\x00\x02\x04\x05\xa0\x01\x03\x03\x00\x01\x01\x08\x0a\x7d\x18\x3a\x61'
         b'\x00\x00\x00\x00')
    eth = Ethernet(s)
    assert eth
    assert isinstance(eth.data, ip6.IP6)
    assert isinstance(eth.data.data, tcp.TCP)
    assert str(eth) == str(s)
    assert len(eth) == len(s)


def test_eth_zero_ethtype():
    s = (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x89\x12\x04')
    eth = Ethernet(s)
    assert eth
    assert eth.type == ETH_TYPE_UNKNOWN
    assert str(eth) == str(s)
    assert len(eth) == len(s)


def test_eth_init_with_data():
    # initialize with a data string, test that it gets unpacked
    from . import arp
    eth1 = Ethernet(
        dst=b'PQRSTU', src=b'ABCDEF', type=ETH_TYPE_ARP,
        data=b'\x00\x01\x08\x00\x06\x04\x00\x01123456abcd7890abwxyz')
    assert isinstance(eth1.data, arp.ARP)

    # now initialize with a class, test packing
    eth2 = Ethernet(
        dst=b'PQRSTU', src=b'ABCDEF',
        data=arp.ARP(sha=b'123456', spa=b'abcd', tha=b'7890ab', tpa=b'wxyz'))
    assert str(eth1) == str(eth2)
    assert len(eth1) == len(eth2)


def test_mpls_label():
    s = b'\x00\x01\x0b\xff'
    m = MPLSlabel(s)
    assert m.val == 16
    assert m.exp == 5
    assert m.s == 1
    assert m.ttl == 255
    assert str(m) == str(s)
    assert len(m) == len(s)


def test_802dot1q_tag():
    s = b'\xa0\x76\x01\x65'
    t = VLANtag8021Q(s)
    assert t.pri == 5
    assert t.cfi == 0
    assert t.id == 118
    assert str(t) == str(s)
    t.cfi = 1
    assert str(t) == str(b'\xb0\x76\x01\x65')
    assert len(t) == len(s)


def test_isl_tag():
    s = (b'\x01\x00\x0c\x00\x00\x03\x00\x02\xfd\x2c\xb8\x97\x00\x00\xaa\xaa\x03\x00\x00\x00\x04\x57'
         b'\x00\x00\x00\x00')
    t = VLANtagISL(s)
    assert t.pri == 3
    assert t.id == 555
    assert t.bpdu == 1
    assert str(t) == str(s)
    assert len(t) == len(s)


def test_eth_802dot1q():
    from . import ip
    s = (b'\x00\x60\x08\x9f\xb1\xf3\x00\x40\x05\x40\xef\x24\x81\x00\x90\x20\x08'
         b'\x00\x45\x00\x00\x34\x3b\x64\x40\x00\x40\x06\xb7\x9b\x83\x97\x20\x81'
         b'\x83\x97\x20\x15\x04\x95\x17\x70\x51\xd4\xee\x9c\x51\xa5\x5b\x36\x80'
         b'\x10\x7c\x70\x12\xc7\x00\x00\x01\x01\x08\x0a\x00\x04\xf0\xd4\x01\x99'
         b'\xa3\xfd')
    eth = Ethernet(s)
    assert eth.cfi == 1
    assert eth.vlanid == 32
    assert eth.priority == 4
    assert len(eth.vlan_tags) == 1
    assert eth.vlan_tags[0].type == ETH_TYPE_IP
    assert isinstance(eth.data, ip.IP)

    # construction
    assert str(eth) == str(s), 'pack 1'
    assert str(eth) == str(s), 'pack 2'
    assert len(eth) == len(s)

    # construction with kwargs
    eth2 = Ethernet(src=eth.src, dst=eth.dst, vlan_tags=eth.vlan_tags, data=eth.data)
    assert str(eth2) == str(s)

    # construction w/o the tag
    del eth.vlan_tags, eth.cfi, eth.vlanid, eth.priority
    assert str(eth) == str(s[:12] + b'\x08\x00' + s[18:])


def test_eth_802dot1q_stacked():  # 2 VLAN tags
    from . import arp
    from . import ip
    s = (b'\x00\x1b\xd4\x1b\xa4\xd8\x00\x13\xc3\xdf\xae\x18\x81\x00\x00\x76\x81\x00\x00\x0a\x08\x00'
         b'\x45\x00\x00\x64\x00\x0f\x00\x00\xff\x01\x92\x9b\x0a\x76\x0a\x01\x0a\x76\x0a\x02\x08\x00'
         b'\xce\xb7\x00\x03\x00\x00\x00\x00\x00\x00\x00\x1f\xaf\x70\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
         b'\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
         b'\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd'
         b'\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd\xab\xcd')
    eth = Ethernet(s)
    assert eth.type == ETH_TYPE_8021Q
    assert len(eth.vlan_tags) == 2
    assert eth.vlan_tags[0].id == 118
    assert eth.vlan_tags[1].id == 10
    assert eth.vlan_tags[0].type == ETH_TYPE_8021Q
    assert eth.vlan_tags[1].type == ETH_TYPE_IP
    assert [t.as_tuple() for t in eth.vlan_tags] == [(118, 0, 0), (10, 0, 0)]
    assert isinstance(eth.data, ip.IP)

    # construction
    assert str(eth) == str(s), 'pack 1'
    assert str(eth) == str(s), 'pack 2'
    assert len(eth) == len(s)

    # construction with kwargs
    eth2 = Ethernet(src=eth.src, dst=eth.dst, vlan_tags=eth.vlan_tags, data=eth.data)

    # construction sets ip.type to 802.1ad instead of 802.1q so account for it
    assert str(eth2) == str(s[:12] + b'\x88\xa8' + s[14:])

    # construction w/o the tags
    del eth.vlan_tags, eth.cfi, eth.vlanid, eth.priority
    assert str(eth) == str(s[:12] + b'\x08\x00' + s[22:])

    # 2 VLAN tags + ARP
    s = (b'\xff\xff\xff\xff\xff\xff\xca\x03\x0d\xb4\x00\x1c\x81\x00\x00\x64\x81\x00\x00\xc8\x08\x06'
         b'\x00\x01\x08\x00\x06\x04\x00\x01\xca\x03\x0d\xb4\x00\x1c\xc0\xa8\x02\xc8\x00\x00\x00\x00'
         b'\x00\x00\xc0\xa8\x02\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    eth = Ethernet(s)
    assert len(eth.vlan_tags) == 2
    assert eth.vlan_tags[0].type == ETH_TYPE_8021Q
    assert eth.vlan_tags[1].type == ETH_TYPE_ARP
    assert isinstance(eth.data, arp.ARP)


def test_eth_mpls_stacked():  # Eth - MPLS - MPLS - IP - ICMP
    from . import ip
    from . import icmp
    s = (b'\x00\x30\x96\xe6\xfc\x39\x00\x30\x96\x05\x28\x38\x88\x47\x00\x01\x20\xff\x00\x01\x01\xff'
         b'\x45\x00\x00\x64\x00\x50\x00\x00\xff\x01\xa7\x06\x0a\x1f\x00\x01\x0a\x22\x00\x01\x08\x00'
         b'\xbd\x11\x0f\x65\x12\xa0\x00\x00\x00\x00\x00\x53\x9e\xe0' + b'\xab\xcd' * 32)
    eth = Ethernet(s)
    assert len(eth.mpls_labels) == 2
    assert eth.mpls_labels[0].val == 18
    assert eth.mpls_labels[1].val == 16
    assert eth.labels == [(18, 0, 255), (16, 0, 255)]
    assert isinstance(eth.data, ip.IP)
    assert isinstance(eth.data.data, icmp.ICMP)

    # construction
    assert str(eth) == str(s), 'pack 1'
    assert str(eth) == str(s), 'pack 2'
    assert len(eth) == len(s)

    # construction with kwargs
    eth2 = Ethernet(src=eth.src, dst=eth.dst, mpls_labels=eth.mpls_labels, data=eth.data)
    assert str(eth2) == str(s)

    # construction w/o labels
    del eth.labels, eth.mpls_labels
    assert str(eth) == str(s[:12] + b'\x08\x00' + s[22:])


def test_isl_eth_llc_stp():  # ISL - 802.3 Ethernet(w/FCS) - LLC - STP
    from . import stp
    s = (b'\x01\x00\x0c\x00\x00\x03\x00\x02\xfd\x2c\xb8\x97\x00\x00\xaa\xaa\x03\x00\x00\x00\x02\x9b'
         b'\x00\x00\x00\x00\x01\x80\xc2\x00\x00\x00\x00\x02\xfd\x2c\xb8\x98\x00\x26\x42\x42\x03\x00'
         b'\x00\x00\x00\x00\x80\x00\x00\x02\xfd\x2c\xb8\x83\x00\x00\x00\x00\x80\x00\x00\x02\xfd\x2c'
         b'\xb8\x83\x80\x26\x00\x00\x14\x00\x02\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x41\xc6'
         b'\x75\xd6')
    eth = Ethernet(s)
    assert eth.vlan == 333
    assert len(eth.vlan_tags) == 1
    assert eth.vlan_tags[0].id == 333
    assert eth.vlan_tags[0].pri == 3

    # check that FCS was decoded
    assert eth.fcs == 0x41c675d6
    assert eth.trailer == b'\x00' * 8

    # stack
    assert isinstance(eth.data, llc.LLC)
    assert isinstance(eth.data.data, stp.STP)

    # construction
    assert str(eth) == str(s), 'pack 1'
    assert str(eth) == str(s), 'pack 2'
    assert len(eth) == len(s)

    # construction with kwargs
    eth2 = Ethernet(src=eth.src, dst=eth.dst, vlan_tags=eth.vlan_tags, data=eth.data)
    eth2.trailer = eth.trailer
    eth2.fcs = None
    # test FCS computation
    assert str(eth2) == str(s)

    # construction w/o the ISL tag
    del eth.vlan_tags, eth.vlan
    assert str(eth) == str(s[26:])


def test_eth_llc_snap_cdp():  # 802.3 Ethernet - LLC/SNAP - CDP
    from . import cdp
    s = (b'\x01\x00\x0c\xcc\xcc\xcc\xc4\x022k\x00\x00\x01T\xaa\xaa\x03\x00\x00\x0c \x00\x02\xb4,B'
         b'\x00\x01\x00\x06R2\x00\x05\x00\xffCisco IOS Software, 3700 Software (C3745-ADVENTERPRI'
         b'SEK9_SNA-M), Version 12.4(25d), RELEASE SOFTWARE (fc1)\nTechnical Support: http://www.'
         b'cisco.com/techsupport\nCopyright (c) 1986-2010 by Cisco Systems, Inc.\nCompiled Wed 18'
         b'-Aug-10 08:18 by prod_rel_team\x00\x06\x00\x0eCisco 3745\x00\x02\x00\x11\x00\x00\x00\x01'
         b'\x01\x01\xcc\x00\x04\n\x00\x00\x02\x00\x03\x00\x13FastEthernet0/0\x00\x04\x00\x08\x00'
         b'\x00\x00)\x00\t\x00\x04\x00\x0b\x00\x05\x00')
    eth = Ethernet(s)

    # stack
    assert isinstance(eth.data, llc.LLC)
    assert isinstance(eth.data.data, cdp.CDP)
    assert len(eth.data.data.tlvs) == 8  # number of CDP TLVs; ensures they are decoded
    assert str(eth) == str(s), 'pack 1'
    assert str(eth) == str(s), 'pack 2'
    assert len(eth) == len(s)


def test_eth_llc_ipx():  # 802.3 Ethernet - LLC - IPX
    from . import ipx
    s = (b'\xff\xff\xff\xff\xff\xff\x00\xb0\xd0\x22\xf7\xf3\x00\x54\xe0\xe0\x03\xff\xff\x00\x50\x00'
         b'\x14\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\x04\x55\x00\x00\x00\x00\x00\xb0\xd0\x22\xf7'
         b'\xf3\x04\x55\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x02\x5f\x5f\x4d\x53\x42'
         b'\x52\x4f\x57\x53\x45\x5f\x5f\x02\x01\x00')
    eth = Ethernet(s)

    # stack
    assert isinstance(eth.data, llc.LLC)
    assert isinstance(eth.data.data, ipx.IPX)
    assert eth.data.data.pt == 0x14
    assert str(eth) == str(s), 'pack 1'
    assert str(eth) == str(s), 'pack 2'
    assert len(eth) == len(s)


def test_eth_pppoe():   # Eth - PPPoE - IPv6 - UDP - DHCP6
    from . import ip  # IPv6 needs this to build its protocol stack
    from . import ip6
    from . import ppp
    from . import pppoe
    from . import udp
    s = (b'\xca\x01\x0e\x88\x00\x06\xcc\x05\x0e\x88\x00\x00\x88\x64\x11\x00\x00\x11\x00\x64\x57\x6e'
         b'\x00\x00\x00\x00\x3a\x11\xff\xfe\x80\x00\x00\x00\x00\x00\x00\xce\x05\x0e\xff\xfe\x88\x00'
         b'\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x02\x22\x02\x23\x00'
         b'\x3a\x1a\x67\x01\xfc\x24\xab\x00\x08\x00\x02\x05\xe9\x00\x01\x00\x0a\x00\x03\x00\x01\xcc'
         b'\x05\x0e\x88\x00\x00\x00\x06\x00\x06\x00\x19\x00\x17\x00\x18\x00\x19\x00\x0c\x00\x09\x00'
         b'\x01\x00\x00\x00\x00\x00\x00\x00\x00')
    eth = Ethernet(s)

    # stack
    assert isinstance(eth.data, pppoe.PPPoE)
    assert isinstance(eth.data.data, ppp.PPP)
    assert isinstance(eth.data.data.data, ip6.IP6)
    assert isinstance(eth.data.data.data.data, udp.UDP)

    # construction
    assert str(eth) == str(s)
    assert len(eth) == len(s)


def test_eth_2mpls_ecw_eth_llc_stp():  # Eth - MPLS - MPLS - PW ECW - 802.3 Eth(no FCS) - LLC - STP
    from . import stp
    s = (b'\xcc\x01\x0d\x5c\x00\x10\xcc\x00\x0d\x5c\x00\x10\x88\x47\x00\x01\x20\xfe\x00\x01\x01\xff'
         b'\x00\x00\x00\x00\x01\x80\xc2\x00\x00\x00\xcc\x04\x0d\x5c\xf0\x00\x00\x26\x42\x42\x03\x00'
         b'\x00\x00\x00\x00\x80\x00\xcc\x04\x0d\x5c\x00\x00\x00\x00\x00\x00\x80\x00\xcc\x04\x0d\x5c'
         b'\x00\x00\x80\x01\x00\x00\x14\x00\x02\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    eth = Ethernet(s)
    assert len(eth.mpls_labels) == 2
    assert eth.mpls_labels[0].val == 18
    assert eth.mpls_labels[1].val == 16

    # stack
    eth2 = eth.data
    assert isinstance(eth2, Ethernet)
    assert eth2.len == 38  # 802.3 Ethernet
    # no FCS, all trailer
    assert not hasattr(eth2, 'fcs')
    assert eth2.trailer == b'\x00' * 8
    assert isinstance(eth2.data, llc.LLC)
    assert isinstance(eth2.data.data, stp.STP)
    assert eth2.data.data.port_id == 0x8001

    # construction
    # XXX - FIXME: make packing account for the ECW
    # assert str(eth) == str(s)


# QinQ: Eth - 802.1ad - 802.1Q - IP
def test_eth_802dot1ad_802dot1q_ip():
    from . import ip
    s = (b'\x00\x10\x94\x00\x00\x0c\x00\x10\x94\x00\x00\x14\x88\xa8\x00\x1e\x81\x00\x00\x64\x08\x00'
         b'\x45\x00\x05\xc2\x54\xb0\x00\x00\xff\xfd\xdd\xbf\xc0\x55\x01\x16\xc0\x55\x01\x0e' +
         1434 * b'\x00' + b'\x4f\xdc\xcd\x64\x20\x8d\xb6\x4e\xa8\x45\xf8\x80\xdd\x0c\xf9\x72\xc4'
         b'\xd0\xcf\xcb\x46\x6d\x62\x7a')

    eth = Ethernet(s)
    assert eth.type == ETH_TYPE_8021AD
    assert eth.vlan_tags[0].id == 30
    assert eth.vlan_tags[1].id == 100
    assert isinstance(eth.data, ip.IP)

    e1 = Ethernet(s[:-1458])  # strip IP data

    # construction
    e2 = Ethernet(
        dst=b'\x00\x10\x94\x00\x00\x0c', src=b'\x00\x10\x94\x00\x00\x14',
        type=ETH_TYPE_8021AD,
        vlan_tags=[
            VLANtag8021Q(pri=0, id=30, cfi=0),
            VLANtag8021Q(pri=0, id=100, cfi=0)
        ],
        data=ip.IP(
            len=1474, id=21680, ttl=255, p=253, sum=56767,
            src=b'\xc0U\x01\x16', dst=b'\xc0U\x01\x0e', opts=b''
        )
    )
    assert str(e1) == str(e2)


def test_eth_pack():
    eth = Ethernet(data=b'12345')
    assert str(eth)


def test_eth_802dot1q_with_unfamiliar_data():
    profinet_data = (b'\xfe\xff\x05\x01\x05\x01\x00\x02\x00\x00\x00\x6c\x02'
         b'\x05\x00\x12\x00\x00\x02\x01\x02\x02\x02\x03\x02\x04\x02\x05\x02'
         b'\x06\x01\x01\x01\x02\x02\x01\x00\x08\x00\x00\x53\x37\x2d\x33\x30'
         b'\x30\x02\x02\x00\x22\x00\x00\x70\x6c\x63\x78\x62\x33\x30\x30\x78'
         b'\x6b\x63\x70\x75\x78\x61\x33\x31\x37\x2d\x32\x78\x61\x70\x6e\x78'
         b'\x72\x64\x70\x32\x32\x63\x66\x02\x03\x00\x06\x00\x00\x00\x2a\x01'
         b'\x01\x02\x04\x00\x04\x00\x00\x02\x00\x01\x02\x00\x0e\x00\x01\xc0'
         b'\xa8\x3c\x87\xff\xff\xff\x00\xc0\xa8\x3c\x87')

    s = (b'\x00\x0c\x29\x65\x1c\x29\x00\x0e\x8c\x8a\xa2\x5e\x81\x00\x00\x00'
         b'\x88\x92' + profinet_data)

    eth = Ethernet(s)
    assert eth.type == ETH_TYPE_8021Q
    assert len(eth.vlan_tags) == 1
    assert eth.vlan_tags[0].type == ETH_TYPE_PROFINET
    assert isinstance(eth.data, bytes)
    assert eth.data == profinet_data


def test_eth_802dot1q_with_arp_data():  # https://github.com/kbandla/dpkt/issues/460
    from .arp import ARP
    e = Ethernet(src=b'foobar', dst=b'\xff' * 6)
    v = VLANtag8021Q(pri=0, cfi=0, id=1)
    e.vlan_tags = [v]
    a = ARP(sha = b'foobar', spa = b'\x0a\x0a\x0a\x0a',
            tha = b'', tpa = b'\x0a\x0a\x0a\x05')
    e.data = a
    assert bytes(e) == (
        b'\xff\xff\xff\xff\xff\xfffoobar\x81\x00\x00\x01\x08\x06'  # 0x0806 = next layer is ARP
        b'\x00\x01\x08\x00\x06\x04\x00\x01foobar\x0a\x0a\x0a\x0a'
        b'\x00\x00\x00\x00\x00\x00\x0a\x0a\x0a\x05')


if __name__ == '__main__':
    test_eth()
    test_eth_init_with_data()
    test_mpls_label()
    test_802dot1q_tag()
    test_isl_tag()
    test_eth_802dot1q()
    test_eth_802dot1q_stacked()
    test_eth_mpls_stacked()
    test_isl_eth_llc_stp()
    test_eth_llc_snap_cdp()
    test_eth_llc_ipx()
    test_eth_pppoe()
    test_eth_2mpls_ecw_eth_llc_stp()
    test_eth_802dot1ad_802dot1q_ip()
    test_eth_pack()
    test_eth_802dot1q_with_unfamiliar_data()
    test_eth_802dot1q_with_arp_data()

    print('Tests Successful...')
