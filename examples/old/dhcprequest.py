#!/usr/bin/env python
from __future__ import print_function

import sys
import socket

# Since pcapy is not a requirement of dpkt, test the import and give message
try:
    import pcapy
except ImportError:
    print('Could not import pcapy. Please do a $pip install pcapy')
    sys.exit(1)

# dpkt imports
from dpkt import dhcp
from dpkt import udp
from dpkt import ip
from dpkt import ethernet

# Grab the default interface and use that for the injection
devices = pcapy.findalldevs()
iface_name = devices[0]
print('Auto Setting Interface to: {:s}'.format(iface_name))
interface = pcapy.open_live(iface_name, 65536 , 1 , 0)

# Get local ip
src_ip = socket.inet_pton(socket.AF_INET, interface.getnet())

# Generate broadcast ip and eth_addr
broadcast_ip = socket.inet_pton(socket.AF_INET, '255.255.255.255')
broadcast_eth_addr = b'\xFF\xFF\xFF\xFF\xFF\xFF'

# build a dhcp discover packet to request an ip
d = dhcp.DHCP(
    xid=1337,
    op=dhcp.DHCPDISCOVER,
    opts=(
        (dhcp.DHCP_OP_REQUEST, b''),
        (dhcp.DHCP_OPT_REQ_IP, b''),
        (dhcp.DHCP_OPT_ROUTER, b''),
        (dhcp.DHCP_OPT_NETMASK, b''),
        (dhcp.DHCP_OPT_DNS_SVRS, b'')
    )
)

# build udp packet
u = udp.UDP(
    dport=67,
    sport=68,
    data=d
)
u.ulen = len(u)

# build ip packet
i = ip.IP(
    dst = broadcast_ip,
    src = src_ip,
    data = u,
    p = ip.IP_PROTO_UDP
)
i.len = len(i)

# build ethernet frame
e = ethernet.Ethernet(
    dst = broadcast_eth_addr,
    data = i
)

# Inject the packet (send it out)
interface.sendpacket(bytes(e))

print('DHCP request sent!')

