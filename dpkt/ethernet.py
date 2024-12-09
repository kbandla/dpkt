# $Id: ethernet.py 65 2010-03-26 02:53:51Z dugsong $
# -*- coding: utf-8 -*-
"""
Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
with automatic 802.1q, MPLS, PPPoE, and Cisco ISL decapsulation.
"""
from __future__ import print_function
from __future__ import absolute_import

import struct
from zlib import crc32

from . import dpkt
from . import llc
from .utils import mac_to_str
from .compat import compat_ord, iteritems, isstr

try:
    from Crypto.Cipher import AES
    crypto_support = True
except ImportError:
    crypto_support = False

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
ETH_TYPE_MACSEC = 0x88E5  # MAC security

# all QinQ types for fast checking
_ETH_TYPES_QINQ = frozenset([ETH_TYPE_8021Q, ETH_TYPE_8021AD, ETH_TYPE_QINQ1, ETH_TYPE_QINQ2])


class Ethernet(dpkt.Packet):
    """Ethernet.

    Ethernet II, LLC (802.3+802.2), LLC/SNAP, and Novell raw 802.3,
    with automatic 802.1q, MPLS, PPPoE, and Cisco ISL decapsulation.

    Attributes:
        __hdr__: Header fields of Ethernet.
            dst: (bytes): Destination MAC address
            src: (bytes): Source MAC address
            type: (int): Ethernet frame type (Ethernet II, Novell raw IEEE 802.3, IEEE 802.2 LLC, IEEE 802.2 SNAP)
    """

    __hdr__ = (
        ('dst', '6s', b''),
        ('src', '6s', b''),
        ('type', 'H', ETH_TYPE_IP)
    )
    _typesw = {}
    _typesw_rev = {}  # reverse mapping

    __pprint_funcs__ = {
        'dst': mac_to_str,
        'src': mac_to_str
    }

    def __init__(self, *args, **kwargs):
        self._next_type = None
        # We are setting these directly here. in case dpkt.Packet.__init__ is called with data as the first argument
        # all the other arguments will be ignored
        self.macsec_ciphersuite = kwargs.get('macsec_ciphersuite', None)
        self.macsec_sak = kwargs.get('macsec_sak', None)

        dpkt.Packet.__init__(self, *args, **kwargs)
        # if data was given in kwargs, try to unpack it
        if kwargs.get('data', None):
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

            elif compat_ord(buf[0]) & 0xf0 == 0x60:  # IP version 6 
                self._next_type = ETH_TYPE_IP6

            # pseudowire Ethernet
            elif len(buf) >= self.__hdr_len__:
                if buf[:2] == b'\x00\x00':  # looks like the control word (ECW)
                    buf = buf[4:]  # skip the ECW
                self._next_type = ETH_TYPE_TEB  # re-use TEB class mapping to decode Ethernet
        elif self._next_type == ETH_TYPE_MACSEC:
            buf = self._unpack_macsec(buf)
        try:
            eth_type = self._next_type or self.type
            self.data = self._typesw[eth_type](buf)
            
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            self.data = buf

    def _unpack_macsec(self, buf):
        if self.macsec_ciphersuite is None:
            raise dpkt.PackError("MACsec ciphersuite is not set, unable to decode MACsec frame")

        self.sec_tag = MACsec(buf)
        offset = self.sec_tag.__hdr_len__
        if self.sec_tag.sc:
            self.sec_tag.sci = buf[offset : offset + 8]
            offset += 8  # SCI is 8 bytes long

        buf = buf[offset:]

        if self.sec_tag.sl == 0:            
            self.sec_tag.icv = buf[-self.macsec_ciphersuite.icv_len:]
            buf = buf[:-self.macsec_ciphersuite.icv_len]
        else:
            if len(buf) < self.sec_tag.sl:
                raise dpkt.PackError("Not enough data to unpack MACsec frame")
            
            self.sec_tag.icv = buf[self.sec_tag.sl : self.sec_tag.sl + self.macsec_ciphersuite.icv_len]
            buf = buf[:self.sec_tag.sl]


        if not crypto_support:
            # in case we are not able to decrypt the frame, we just leave the data as is
            self.data = buf
            self._next_type = 0

        if(self.sec_tag.e and self.sec_tag.c):
            # Confientiality and Integrity
            nonce = self.sec_tag.sci + struct.pack('>I', self.sec_tag.pn)
            cipher = AES.new(self.macsec_sak, AES.MODE_GCM, mac_len = self.macsec_ciphersuite.icv_len, nonce = nonce)
            buf = cipher.decrypt(buf)

            self._next_type = struct.unpack('>H', buf[0:2])[0]
            return buf[2:]
        else:
             # Integrity
            self._next_type = struct.unpack('>H', buf[0:2])[0]
            return buf[2:]

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
            # try to unpack FCS, padding and trailer here
            # we follow a heuristic approach similar to that of Wireshark

            # size of eth body, not including the header
            eth_len = self.len = self.type

            # actual size of the remaining data, could include eth body, padding, fcs, trailer
            data_len = len(self.data)
            if data_len > eth_len:
                # everything after eth body
                tail = self.data[eth_len:]

                # could be padding + fcs, possibly trailer
                if len(tail) > 4:
                    # determine size of padding
                    if eth_len < 46:  # 46=60-14; 14=size of eth hdr; all padded to 60 bytes
                        pad_len = 46 - eth_len
                        padding = tail[:pad_len]

                        # heuristic
                        if padding == pad_len * b'\x00':  # padding is likely zeroes
                            self.padding = padding
                            tail = tail[pad_len:]
                        # else proceed to decode as fcs+trailer

                # 4 bytes FCS and possible trailer
                if len(tail) >= 4:
                    self.fcs = struct.unpack('>I', tail[:4])[0]
                    tail = tail[4:]

                if tail:
                    self.trailer = tail

            self.data = self.llc = llc.LLC(self.data[:eth_len])

    def pack_hdr(self):
        tags_buf = b''
        sec_tag_buf = b''
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

        elif getattr(self, 'sec_tag', None):
            last_tag_type = self.type  # default
            new_type = ETH_TYPE_MACSEC
            if isinstance(self.data, dpkt.Packet):
                last_tag_type = self._typesw_rev.get(self.data.__class__, self.type)
            sec_tag = self.sec_tag
            sec_tag.type = last_tag_type
            if self.macsec_ciphersuite is None:
                raise dpkt.PackError("MACsec ciphersuite is not set")
            sec_tag_buf = sec_tag.pack_hdr()

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
            return hdr_buf + sec_tag_buf + tags_buf
        else:
            return tags_buf + hdr_buf

    def __bytes__(self):
        tail = b''
        if isinstance(self.data, llc.LLC):
            fcs = b''
            if hasattr(self, 'fcs'):
                if self.fcs:
                    fcs = self.fcs
                else:
                    # if fcs field is present but 0/None, then compute it and add to the tail
                    fcs_buf = self.pack_hdr() + bytes(self.data)
                    # if ISL header is present, exclude it from the calculation
                    if getattr(self, 'vlan_tags', None):
                        if isinstance(self.vlan_tags[0], VLANtagISL):
                            fcs_buf = fcs_buf[VLANtagISL.__hdr_len__:]
                    fcs_buf += getattr(self, 'padding', b'')
                    revcrc = crc32(fcs_buf) & 0xffffffff
                    fcs = struct.unpack('<I', struct.pack('>I', revcrc))[0]  # bswap32
                fcs = struct.pack('>I', fcs)
            tail = getattr(self, 'padding', b'') + fcs + getattr(self, 'trailer', b'')

        if getattr(self, 'sec_tag', None)  is not None:
            return self._bytes_macsec()
        
        return bytes(dpkt.Packet.__bytes__(self) + tail)

    def _bytes_macsec(self):
        if not crypto_support:
            # Leave the payload data in clear and add a dummy ICV of zeros
            # This results in an invalid MACsec frame, but it's the best we can do without the crypto library
            return bytes(self.pack_hdr() + bytes(self.data) + self.sec_tag.icv)
        
        hdr_data = self.pack_hdr()

        if getattr(self, 'macsec_sak', None) is None:
            raise dpkt.PackError("Not able to pack MACsec frame. SAK not set")
        
        if(self.macsec_ciphersuite.blocksize / 8 != len(self.macsec_sak)):
            raise dpkt.PackError("SAK length does not match the blocksize of the ciphersuite")  
        
        if(isinstance(self.data, dpkt.Packet)):
            # When the next layer is a dpkt.Packet, we take the ethertype from the sec_tag
            data = struct.pack('>H', self.sec_tag.type) + bytes(self.data)
        else:
            # Othwerise, we asume the userdata is raw data and includes the ethertype already
            data = bytes(self.data)
        
        # For the XPN case, we need to include 64bits of PN. Not supported right now
        iv = self.sec_tag.sci + struct.pack('>I', self.sec_tag.pn) 
        cipher = AES.new(self.macsec_sak, AES.MODE_GCM, mac_len = self.macsec_ciphersuite.icv_len, nonce = iv)

        if self.sec_tag.e and self.sec_tag.c:
            cipher.update(hdr_data)
            data, self.sec_tag.icv = cipher.encrypt_and_digest(data)
            
            return bytes(hdr_data + data + self.sec_tag.icv)
        else:
            cipher.update(hdr_data + data)
            self.sec_tag.icv = cipher.digest()

            return bytes(hdr_data + data + self.sec_tag.icv)

    def __len__(self):
        tags = getattr(self, 'mpls_labels', []) + getattr(self, 'vlan_tags', [])
        _len = dpkt.Packet.__len__(self) + sum(t.__hdr_len__ for t in tags)
        if isinstance(self.data, llc.LLC):
            _len += len(getattr(self, 'padding', b''))
            if hasattr(self, 'fcs'):
                _len += 4
            _len += len(getattr(self, 'trailer', b''))
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

ICV_LEN = {
    'AES-GCM-128': 16,
    'AES-GCM-256': 16,
}

MACSEC_CIPHERSUITES = {
    'AES-GCM-128' : MACsecCipherSuite('AES', 128, 'GCM'),
    'AES-GCM-256' : MACsecCipherSuite('AES', 256, 'GCM'),
}

class MACsecCipherSuite(object):
    def __init__(self, cipher, blocksize, mode):
        self._cipher = cipher
        self._blocksize = blocksize
        self._mode = mode

    @property
    def name(self):
        return self._cipher + "-" + self._mode + "-" + str(self.blocksize)

    @property
    def blocksize(self):
        return self._blocksize

    @property
    def icv_len(self):
        return ICV_LEN[self.name]
    
    def __repr__(self):
        return self.name

class MACsec(dpkt.Packet):
    """IEEE 802.1AE MACsec tag"""

    __hdr__ = (
        ('_tci_an', 'B', 0),
        ('sl', 'B', 0), # short length
        ('pn', 'L', 0), # packet number (LSBs for XPN)
        # We cannot have 'type' as as a field to indicate the next layer type
        # his is because type is potentially encrypted and can not be serialized as part of the header
    )

    __bit_fields__ = {
        '_tci_an': (
            ('v', 1), # version, 1 bit
            ('es', 1), # end station, 1 bit
            ('sc', 1), # secure channel explicitly encoded, 1 bit
            ('scb', 1), # EPON single copy broadcast, 1 bit
            ('e', 1), # Encryption bit, 1 bit
            ('c', 1), # Changed Text bit, 1 bit
            ('an', 2),  # association number, 2 bits
        )
    }

    def __init__(self, *args, **kwargs):
        self.sci = b'\0\0\0\0\0\0\0\0' # 8 bytes sci
        self.icv = b'' # integrity check value, this is the trailer
        self.type = 0 # next layer type

        dpkt.Packet.__init__(self, *args, **kwargs)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = b''

    def pack_hdr(self):
        sci = b''
        if self.sc:
            sci = self.sci
            if len(sci) != 8:
                raise dpkt.PackError("SCI must be 8 bytes long")
        return dpkt.Packet.pack_hdr(self) + sci

    def __len__(self):
        sci_len = 0
        if self.sc:
            sci_len = 8
        return self.__hdr_len__ + sci_len
    
class MPLSlabel(dpkt.Packet):
    """A single entry in MPLS label stack"""

    __hdr__ = (
        ('_val_exp_s_ttl', 'I', 0),
    )
    # field names are according to RFC3032
    __bit_fields__ = {
        '_val_exp_s_ttl': (
            ('val', 20),  # label value, 20 bits
            ('exp', 3),   # experimental use, 3 bits
            ('s', 1),     # bottom of stack flag, 1 bit
            ('ttl', 8),   # time to live, 8 bits
        )
    }

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = b''

    def as_tuple(self):  # backward-compatible representation
        return (self.val, self.exp, self.ttl)


class VLANtag8021Q(dpkt.Packet):
    """IEEE 802.1q VLAN tag"""

    __hdr__ = (
        ('_pri_cfi_id', 'H', 0),
        ('type', 'H', ETH_TYPE_IP)
    )
    __bit_fields__ = {
        '_pri_cfi_id': (
            ('pri', 3),  # priority, 3 bits
            ('cfi', 1),  # canonical format indicator, 1 bit
            ('id', 12),  # VLAN id, 12 bits
        )
    }

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = b''

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
    __bit_fields__ = {
        '_type_pri': (
            ('type', 4),  # encapsulation type, 4 bits; 0 means Ethernet
            ('pri', 4),   # user defined bits, 2 lo bits are used; means priority
        ),
        '_id_bpdu': (
            ('id', 15),   # vlan id, 15 bits
            ('bpdu', 1),  # bridge protocol data unit indicator
        )
    }

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = b''


# Unit tests


def test_eth():
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
    from binascii import unhexlify

    import pytest

    from . import ip

    s = unhexlify(
        '001bd41ba4d80013c3dfae18810000768100000a0800'
        '45000064000f0000ff01929b0a760a010a760a020800'
        'ceb70003000000000000001faf70abcdabcdabcdabcd'
        'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd'
        'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd'
        'abcdabcdabcdabcdabcdabcd'
    )
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
    assert len(eth) == len(s)
    assert bytes(eth) == s

    # test packing failure with too many tags
    eth.vlan_tags += eth.vlan_tags[0]  # just duplicate the first tag
    with pytest.raises(dpkt.PackError, match='maximum is 2 VLAN tags per Ethernet frame'):
        bytes(eth)

    # construction with kwargs
    eth2 = Ethernet(src=eth.src, dst=eth.dst, vlan_tags=eth.vlan_tags[:2], data=eth.data)

    # construction sets ip.type to 802.1ad instead of 802.1q so account for it
    assert str(eth2) == str(s[:12] + b'\x88\xa8' + s[14:])

    # construction w/o the tags
    del eth.vlan_tags, eth.cfi, eth.vlanid, eth.priority
    assert str(eth) == str(s[:12] + b'\x08\x00' + s[22:])


def test_eth_vlan_arp():
    from . import arp

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

    # exercise .pprint() for the coverage tests
    eth.pprint()

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

def test_eth_mpls_ipv6():  # Eth - MPLS - IP6 - TCP
    from . import ip6
    from . import tcp

    s = ( b'\x00\x30\x96\xe6\xfc\x39\x00\x30\x96\x05\x28\x38\x88\x47\x00\x01'
          b'\x01\xff\x62\x8c\xed\x7b\x00\x28\x06\xfd\x22\x22\x22\x22\x03\x3f'
          b'\x53\xd3\x48\xfb\x8b\x5a\x41\x7f\xe6\x17\x11\x11\x11\x11\x40\x0b'
          b'\x08\x09\x00\x00\x00\x00\x00\x00\x20\x0e\xa1\x8e\x01\xbb\xd6\xde'
          b'\x73\x17\x00\x00\x00\x00\xa0\x02\xff\xff\x58\x7f\x00\x00\x02\x04'
          b'\x05\x8c\x04\x02\x08\x0a\x69\x23\xe8\x63\x00\x00\x00\x00\x01\x03'
          b'\x03\x0a\xaf\x9c\xb6\x93')

    eth = Ethernet(s)
    assert len(eth.mpls_labels) == 1
    assert eth.mpls_labels[0].val == 16
    assert eth.labels == [(16, 0, 255)]
    assert isinstance(eth.data, ip6.IP6)
    assert isinstance(eth.data.data, tcp.TCP)

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

    # check that FCS and padding were decoded
    assert eth.fcs == 0x41c675d6
    assert eth.padding == b'\x00' * 8

    # stack
    assert isinstance(eth.data, llc.LLC)
    assert isinstance(eth.data.data, stp.STP)

    # construction
    assert str(eth) == str(s), 'pack 1'
    assert str(eth) == str(s), 'pack 2'
    assert len(eth) == len(s)

    # construction with kwargs
    eth2 = Ethernet(src=eth.src, dst=eth.dst, vlan_tags=eth.vlan_tags, data=eth.data)
    eth2.padding = b'\x00' * 8
    # test FCS computation
    eth2.fcs = None
    assert str(eth2) == str(s)

    # TODO: test padding construction
    # eth2.padding = None
    # assert str(eth2) == str(s)

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
    # no FCS, no trailer, just 8 bytes of padding (60=38+14+8)
    assert not hasattr(eth2, 'fcs')
    assert eth2.padding == b'\x00' * 8
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
    profinet_data = (
        b'\xfe\xff\x05\x01\x05\x01\x00\x02\x00\x00\x00\x6c\x02'
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
    a = ARP(sha=b'foobar', spa=b'\x0a\x0a\x0a\x0a',
            tha=b'', tpa=b'\x0a\x0a\x0a\x05')
    e.data = a
    assert bytes(e) == (
        b'\xff\xff\xff\xff\xff\xfffoobar\x81\x00\x00\x01\x08\x06'  # 0x0806 = next layer is ARP
        b'\x00\x01\x08\x00\x06\x04\x00\x01foobar\x0a\x0a\x0a\x0a'
        b'\x00\x00\x00\x00\x00\x00\x0a\x0a\x0a\x05')


# 802.3 Ethernet - LLC/STP - Padding - FCS - Metamako trailer
def test_eth_8023_llc_trailer():  # https://github.com/kbandla/dpkt/issues/438
    d = (b'\x01\x80\xc2\x00\x00\x00\x78\x0c\xf0\xb4\xd8\x91\x00\x27\x42\x42\x03\x00\x00\x02\x02\x3c'
         b'\x00\x01\x2c\x33\x11\xf2\x39\xc1\x00\x00\x00\x02\x80\x01\x78\x0c\xf0\xb4\xd8\xbc\x80\xaa'
         b'\x01\x00\x14\x00\x02\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4d\xb9\x81\x20\x5c\x1e'
         b'\x5f\xba\x3a\xa5\x47\xfa\x01\x8e\x52\x03')
    eth = Ethernet(d)
    assert eth.len == 39
    assert eth.padding == b'\x00\x00\x00\x00\x00\x00\x00'
    assert eth.fcs == 0x4db98120
    assert eth.trailer == b'\x5c\x1e\x5f\xba\x3a\xa5\x47\xfa\x01\x8e\x52\x03'
    assert isinstance(eth.data, llc.LLC)

    # packing
    assert bytes(eth) == d

    # FCS computation
    eth.fcs = None
    assert bytes(eth) == d


def test_eth_novell():
    from binascii import unhexlify

    import dpkt

    buf = unhexlify(
        '010203040506'  # dst
        '0708090a0b0c'  # src
        '0000'          # type (ignored)
        'ffff'          # indicates Novell

        # IPX packet
        '0000'          # sum
        '0001'          # len
        '02'            # tc
        '03'            # pt
        '0102030405060708090a0b0c'  # dst
        '0102030405060708090a0b0c'  # src
    )

    eth = Ethernet(buf)
    assert isinstance(eth.data, dpkt.ipx.IPX)
    assert eth.data.tc == 2
    assert eth.data.data == b''


def test_macsec_c11():
    # C.1.1 GCM-AES-128 (54-octet frame integrity protection)
   
    userdata = """08 00 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C
    1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C
    2D 2E 2F 30 31 32 33 34 00 01""".strip().replace("\n", "").replace(" ", "")

    c11 = """
    D6 09 B1 F0 56 63
    7A 0D 46 DF 99 8D
    88 E5
    22
    2A
    B2 C2 84 65
    12 15 35 24 C0 89 5E 81
    08 00 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C
    1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C
    2D 2E 2F 30 31 32 33 34 00 01
    F0 94 78 A9 B0 90 07 D0 6F 46 E9 B6 A1 DA 25 DD
    """.strip().replace("\n", "").replace(" ", "")
    userdata = bytearray.fromhex(userdata)
    c11 = bytearray.fromhex(c11)

    sak = bytearray.fromhex("AD7A2BD03EAC835A6F620FDCB506B345")

    e  = Ethernet(dst= bytearray([0xD6, 0x09, 0xB1, 0xF0, 0x56, 0x63]),
                src=bytearray([0x7A, 0x0D, 0x46, 0xDF, 0x99, 0x8D]),
                sec_tag=MACsec(sc = 1, an = 0x2, e=0, c=0, pn = 0xB2C28465, sl = 0x2a,
                                sci=bytearray([0x12, 0x15, 0x35, 0x24, 0xC0, 0x89, 0x5E, 0x81])),
                macsec_ciphersuite =  MACSEC_CIPHERSUITES['AES-GCM-128'],
                macsec_sak = sak,
                data=userdata)
    assert(e.pack() == c11)

    # Check if we can unpack a packet and get the same result for packing
    e2 = Ethernet(c11, macsec_ciphersuite =  MACSEC_CIPHERSUITES['AES-GCM-128'], macsec_sak = sak)
    assert(e2.pack() == c11)

    

def test_macsec_c71():
    # C.7.1 GCM-AES-128 (61-octet frame confidentiality protection)
    sak = bytearray.fromhex("013FE00B5F11BE7F866D0CBBC55A7A90")

    userdata = bytearray([
        0x08, 0x00, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
        0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x00,
        0x06
    ])
    e  = Ethernet(dst= bytearray([0x84, 0xC5, 0xD5, 0x13, 0xD2, 0xAA]),
                src=bytearray([0xF6, 0xE5, 0xBB, 0xD2, 0x72, 0x77]),
                sec_tag=MACsec(sc = 1, an = 0x3, e=1, c=1, pn = 0x8932d612,
                                sci=bytearray([0x7C, 0xFD, 0xE9, 0xF9, 0xE3, 0x37, 0x24, 0xC6])),
                macsec_ciphersuite =  MACSEC_CIPHERSUITES['AES-GCM-128'],
                macsec_sak = sak,
                data=userdata)
    c71 = """
    84 C5 D5 13 D2 AA
    F6 E5 BB D2 72 77
    88 E5
    2F
    00
    89 32 D6 12
    7C FD E9 F9 E3 37 24 C6
    3A 4D E6 FA 32 19 10 14 DB B3 03 D9 2E E3 A9 E8
    A1 B5 99 C1 4D 22 FB 08 00 96 E1 38 11 81 6A 3C
    9C 9B CF 7C 1B 9B 96 DA 80 92 04 E2 9D 0E 2A 76
    42
    BF D3 10 A4 83 7C 81 6C CF A5 AC 23 AB 00 39 88
    """.strip().replace("\n", "").replace(" ", "")
    c71 = bytearray.fromhex(c71)
    assert (e.pack() == c71)


    e2 = Ethernet(c71,
                 macsec_ciphersuite =  MACSEC_CIPHERSUITES['AES-GCM-128'],
                 macsec_sak = sak,)
    
    assert (e2.pack() == c71)