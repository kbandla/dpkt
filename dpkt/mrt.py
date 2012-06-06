# $Id: mrt.py 29 2007-01-26 02:29:07Z jon.oberheide $
# Patched with Mattia Rossi's code from MDFMT:
# http://caia.swin.edu.au/urp/bgp/tools.html

"""Multi-threaded Routing Toolkit."""

import dpkt
import bgp
import struct
import socket

# Multi-threaded Routing Toolkit
# http://www.ietf.org/internet-drafts/draft-ietf-grow-mrt-03.txt

# MRT Types
NULL			= 0
START			= 1
DIE			= 2
I_AM_DEAD		= 3
PEER_DOWN		= 4
BGP			= 5	# Deprecated by BGP4MP
RIP			= 6
IDRP			= 7
RIPNG			= 8
BGP4PLUS		= 9	# Deprecated by BGP4MP
BGP4PLUS_01		= 10	# Deprecated by BGP4MP
OSPF			= 11
TABLE_DUMP		= 12
TABLE_DUMP_V2		= 13
BGP4MP			= 16
BGP4MP_ET		= 17
ISIS			= 32
ISIS_ET			= 33
OSPF_ET			= 64

# BGP4MP Subtypes
BGP4MP_STATE_CHANGE	= 0
BGP4MP_MESSAGE		= 1
BGP4MP_ENTRY		= 2
BGP4MP_SNAPSHOT		= 3
BGP4MP_MESSAGE_32BIT_AS	= 4

# Address Family Types
AFI_IPv4		= 1
AFI_IPv6		= 2

# TableDump v2 Subtypes
TABLE_DUMP_V2_PEER_INDEX_TABLE          = 1
TABLE_DUMP_V2_RIB_IPV4_UNICAST          = 2
TABLE_DUMP_V2_RIB_IPV4_MULTICAST        = 3
TABLE_DUMP_V2_RIB_IPV6_UNICAST          = 4
TABLE_DUMP_V2_RIB_IPV6_MULTICAST        = 5
TABLE_DUMP_V2_RIB_GENERIC               = 6

class MRTHeader(dpkt.Packet):
    __hdr__ = (
        ('ts', 'I', 0),
        ('type', 'H', 0),
        ('subtype', 'H', 0),
        ('len', 'I', 0)
        )

class TableDump(dpkt.Packet):
    __hdr__ = (
        ('view', 'H', 0),
        ('seq', 'H', 0),
        ('prefix', 'I', 0),
        ('prefix_len', 'B', 0),
        ('status', 'B', 1),
        ('originated_ts', 'I', 0),
        ('peer_ip', 'I', 0),
        ('peer_as', 'H', 0),
        ('attr_len', 'H', 0)
        )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        plen = self.attr_len
        l = []
        while plen > 0:
            attr = bgp.BGP.Update.Attribute(self.data)
            self.data = self.data[len(attr):]
            plen -= len(attr)
            l.append(attr)
        self.attributes = l

class TableDump2_PeerIndex(dpkt.Packet):
    __hdr__ = (
	('id', 'I', 0),
	('viewname_len', 'H', 0),
	)

    __hdr_defaults__ = {
	'view_name' : 0,
	'peer_count' : 0,
	'peers' : []
	}

    def unpack(self, buf):
	dpkt.Packet.unpack(self, buf)
	vlen = self.viewname_len
        self.view_name = self.data[:vlen]
	pcount = self.peer_count = struct.unpack('>H', \
	    self.data[vlen:vlen + 2])[0]
	l = []
	for i in range(pcount):
	    peer = self.Peer(self.data[vlen + 2:])
	    self.data = self.data[len(peer):]
	    l.append(peer)
	self.data = self.peers = l

    class Peer(dpkt.Packet):

        __hdr__ = (
	    ('type', 'B', 0),
	    ('id', 'I', 0)
	    )

	__hdr_defaults__ = {
	    'address': 0,
	    'asn': 0,
	    }

	def unpack(self, buf):
	    self.len=0
	    dpkt.Packet.unpack(self, buf)
	    if (self.type >> 0) & 0x01 :
	        self.address = self.data[:16]
	        self.data = self.data[16:]
		self.len += 16
	    else:
	        self.address = socket.inet_ntoa(self.data[:4])
	        self.data = self.data[4:]
		self.len += 4
	    if (self.type >> 1) & 0x01 :
	        self.asn = struct.unpack('>L', \
		    self.data[:4])[0]
		self.len += 4
	    else :
	        self.asn = struct.unpack('>H', \
		    self.data[:2])[0]
		self.len += 2
	    self.data=''

	def __len__(self):
	    return self.__hdr_len__ + \
		self.len

class TableDump2_IPV4(dpkt.Packet):
    __hdr__ = (
	('seq','I',0),
	)

    __hdr_defaults__ = {
	'ribentry' : []
	}

    def unpack(self,buf):
	dpkt.Packet.unpack(self, buf)
	pre = bgp.RouteIPV4(self.data)
	self.prefix_len = pre.len
	self.prefix = pre.prefix
	self.entry_count = struct.unpack('>H', \
	    self.data[len(pre):len(pre)+2])[0]
	self.data = self.data[len(pre)+2:]
	l = []
	for i in range(self.entry_count):
	    entry = TableDump2_RIBEntry(self.data)
	    self.data = self.data[len(entry):]
	    l.append(entry)
	self.data = self.ribentry = l

class TableDump2_IPV6(dpkt.Packet):
    __hdr__ = (
        ('seq','I',0),
        )

    def unpack(self,buf):
        dpkt.Packet.unpack(self, buf)
        pre = bgp.RouteIPV6(self.data)
        self.prefix_len = pre.len
        self.prefix = pre.prefix
	self.entry_count = struct.unpack('>H', \
            self.data[len(pre):len(pre)+2])[0]
	self.data = self.data[len(pre)+2:]
        l = []
        for i in range(self.entry_count):
            entry = TableDump2_RIBEntry(self.data)
            self.data = self.data[len(entry):]
            l.append(entry)
        self.data = self.ribentry = l

class TableDump2_RIBGeneric(dpkt.Packet):
    __hdr__ = (
	('seq', 'I', 0),
	('afi', 'H', 0),
	('safi', 'B', 0)
	)

    def unpack(self,buf):
        dpkt.Packet.unpack(self, buf)
        route = bgp.RouteGeneric(self.data)
        self.entry_count = struct.unpack('>H', \
            self.data[len(route):len(route)+2])[0]
        self.data = self.data[len(route)+2:]
        l = []
        for i in range(self.entry_count):
            entry = TableDump2_RIBEntry(self.data)
            self.data = self.data[len(entry):]
            l.append(entry)
        self.data = self.ribentry = l

class TableDump2_RIBEntry(dpkt.Packet):
    __hdr__ = (
        ('peer_index', 'H', 0),
        ('originated_ts', 'I', 0),
        ('attr_len', 'H', 0)
        )

    def unpack(self,buf):
	dpkt.Packet.unpack(self,buf)
	plen = self.attr_len
        l = []
        while plen > 0:
            attr = bgp.BGP.Update.Attribute(self.data)
            self.data = self.data[len(attr):]
            plen -= len(attr)
            l.append(attr)
        self.attributes = l

    def __len__(self):
	return self.__hdr_len__ + self.attr_len
	

class BGP4MPMessage(dpkt.Packet):
    __hdr__ = (
        ('src_as', 'H', 0),
        ('dst_as', 'H', 0),
        ('intf', 'H', 0),
        ('family', 'H', AFI_IPv4),
        ('src_ip', 'I', 0),
        ('dst_ip', 'I', 0)
        )

class BGP4MPMessage_32(dpkt.Packet):
    __hdr__ = (
        ('src_as', 'I', 0),
        ('dst_as', 'I', 0),
        ('intf', 'H', 0),
        ('family', 'H', AFI_IPv4),
        ('src_ip', 'I', 0),
        ('dst_ip', 'I', 0)
        )
