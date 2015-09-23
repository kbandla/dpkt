"""IEEE 802.1q"""

import struct
import dpkt

# Ethernet payload types - http://standards.ieee.org/regauth/ethertype
ETH_TYPE_PUP = 0x0200  # PUP protocol
ETH_TYPE_IP = 0x0800  # IP protocol
ETH_TYPE_ARP = 0x0806  # address resolution protocol
ETH_TYPE_CDP = 0x2000  # Cisco Discovery Protocol
ETH_TYPE_DTP = 0x2004  # Cisco Dynamic Trunking Protocol
ETH_TYPE_REVARP = 0x8035  # reverse addr resolution protocol
ETH_TYPE_DOT1Q = 0x8100  # IEEE 802.1Q VLAN tagging
ETH_TYPE_IPX = 0x8137  # Internetwork Packet Exchange
ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol
ETH_TYPE_PPP = 0x880B  # PPP
ETH_TYPE_MPLS = 0x8847  # MPLS
ETH_TYPE_MPLS_MCAST = 0x8848  # MPLS Multicast
ETH_TYPE_PPPoE_DISC = 0x8863  # PPP Over Ethernet Discovery Stage
ETH_TYPE_PPPoE = 0x8864  # PPP Over Ethernet Session Stage

class DOT1Q(dpkt.Packet):
    __hdr__ = (
        ('x2', 'H', 0),
        ('type', 'H', 0)
        )
    _typesw = {}

    # pcp == Priority Code Point(802.1p)
    def _get_pcp(self): return self.x2 >> 13
    def _set_pcp(self, pcp): self.x2 = (self.x2 & 0x1fff) | (pcp << 13)
    pcp = property(_get_pcp, _set_pcp)

    # dei == Drop Eligible Indicator(almost never actually used)
    def _get_dei(self): return (self.x2 >> 12) & 1 
    def _set_dei(self, dei): self.x2 = (self.x2 & 61439) | (dei << 12)
    dei = property(_get_dei, _set_dei)

    # tag == vlan tag
    def _get_tag(self): return self.x2 & (65535 >> 4)
    def _set_tag(self, tag): self.x2 = (self.x2 & 0xfff) | tag
    tag = property(_get_tag, _set_tag)

    def set_type(cls, t, pktclass):
        cls._typesw[t] = pktclass
    set_type = classmethod(set_type)

    def get_type(cls, t):
        return cls._typesw[t]
    get_type = classmethod(get_type)

    def _unpack_data(self, buf):
      if self.type == ETH_TYPE_MPLS or \
            self.type == ETH_TYPE_MPLS_MCAST:
        # XXX - skip labels (max # of labels is undefined, just use 24)
        self.labels = []
        for i in range(24):
          entry = struct.unpack('>I', buf[i*4:i*4+4])[0]
          label = ((entry & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT, \
                     (entry & MPLS_QOS_MASK) >> MPLS_QOS_SHIFT, \
                     (entry & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT)
          self.labels.append(label)
          if entry & MPLS_STACK_BOTTOM:
            break
          self.type = ETH_TYPE_IP
          buf = buf[(i + 1) * 4:]
      try:
        self.data = self._typesw[self.type](buf)
        setattr(self, self.data.__class__.__name__.lower(), self.data)
      except (KeyError, dpkt.UnpackError):
        self.data = buf

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self._unpack_data(self.data)

# XXX - auto-load Ethernet dispatch table from ETH_TYPE_* definitions
def __load_types():
  g = globals()
  for k, v in g.iteritems():
    if k.startswith('ETH_TYPE_'):
      name = k[9:]
      modname = name.lower()
      try:
        mod = __import__(modname, g)
      except ImportError:
        continue
      DOT1Q.set_type(v, getattr(mod, name))

if not DOT1Q._typesw:
  __load_types()
