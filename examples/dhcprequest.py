#!/usr/bin/env python

import dnet
from dpkt import dhcp
from dpkt import udp
from dpkt import ip
from dpkt import ethernet

sysintf = 'eth0'
hw = dnet.eth(sysintf)
intf = dnet.intf()

# build a dhcp discover packet to request an ip
d = dhcp.DHCP(
        chaddr = hw.get(),
        xid = 1337,
        op = dhcp.DHCPDISCOVER,
        opts = (
            (dhcp.DHCP_OP_REQUEST, ''),
            (dhcp.DHCP_OPT_REQ_IP, ''),
            (dhcp.DHCP_OPT_ROUTER, ''),
            (dhcp.DHCP_OPT_NETMASK, ''),
            (dhcp.DHCP_OPT_DNS_SVRS, '')
        )
    )

# build udp packet
u = udp.UDP(
        dport = 67,
        sport = 68,
        data = d
    )
u.ulen = len(u)

# build ip packet
i = ip.IP(
        dst = dnet.ip_aton('255.255.255.255'),
        src = intf.get(sysintf)['addr'].ip,
        data = u,
        p = ip.IP_PROTO_UDP
    )
i.len = len(i)

# build ethernet frame
e = ethernet.Ethernet(
        dst = dnet.ETH_ADDR_BROADCAST,
        src = hw.get(),
        data = i
    )

# send the data out
hw.send(str(e))

