"""fast, simple packet creation and parsing."""
from __future__ import absolute_import
from __future__ import division
import sys

__author__ = 'Various'
__author_email__ = ''
__license__ = 'BSD-3-Clause'
__url__ = 'https://github.com/kbandla/dpkt'
__version__ = '1.9.4'

from dpkt.dpkt import *

from dpkt import ah
from dpkt import aoe
from dpkt import aim
from dpkt import arp
from dpkt import asn1
from dpkt import bgp
from dpkt import cdp
from dpkt import dhcp
from dpkt import diameter
from dpkt import dns
from dpkt import dtp
from dpkt import esp
from dpkt import ethernet
from dpkt import gre
from dpkt import gzip
from dpkt import h225
from dpkt import hsrp
from dpkt import http
from dpkt import http2
from dpkt import icmp
from dpkt import icmp6
from dpkt import ieee80211
from dpkt import igmp
from dpkt import ip
from dpkt import ip6
from dpkt import ipx
from dpkt import llc
from dpkt import loopback
from dpkt import mrt
from dpkt import netbios
from dpkt import netflow
from dpkt import ntp
from dpkt import ospf
from dpkt import pcap
from dpkt import pcapng
from dpkt import pim
from dpkt import pmap
from dpkt import ppp
from dpkt import pppoe
from dpkt import qq
from dpkt import radiotap
from dpkt import radius
from dpkt import rfb
from dpkt import rip
from dpkt import rpc
from dpkt import rtp
from dpkt import rx
from dpkt import sccp
from dpkt import sctp
from dpkt import sip
from dpkt import sll
from dpkt import smb
from dpkt import ssl
from dpkt import stp
from dpkt import stun
from dpkt import tcp
from dpkt import telnet
from dpkt import tftp
from dpkt import tns
from dpkt import tpkt
from dpkt import udp
from dpkt import vrrp
from dpkt import yahoo

# Note: list() is used to get a copy of the dict in order to avoid
# "RuntimeError: dictionary changed size during iteration"
# exception in Python 3 caused by _mod_init() funcs that load another modules
for name, mod in list(sys.modules.items()):
    if name.startswith('dpkt.') and hasattr(mod, '_mod_init'):
        mod._mod_init()
