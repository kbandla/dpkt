#!/usr/bin/env python
"""
This example expands on the print_packets example. It checks for ICMP packets and displays the ICMP contents.
"""
import dpkt
import datetime
from dpkt.utils import mac_to_str, inet_to_str


def print_icmp(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now grab the data within the Ethernet frame (the IP packet)
        ip = eth.data

        # Now check if this is an ICMP packet
        if isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            # Print out the info
            print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
            print('Ethernet Frame: ', mac_to_str(eth.src), mac_to_str(eth.dst), eth.type)
            print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' %
                  (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl,
                   do_not_fragment, more_fragments, fragment_offset))
            print('ICMP: type:%d code:%d checksum:%d data: %s\n' %
                  (icmp.type, icmp.code, icmp.sum, repr(icmp.data)))


def test():
    """Open up a test pcap file and print out the packets"""
    with open('data/dns_icmp.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_icmp(pcap)


if __name__ == '__main__':
    test()
