"""
Use DPKT to read in a pcap file and print out the contents of truncated
DNS packets. This example show how to read/handle truncated packets
"""
import sys
import dpkt
import datetime
from dpkt.utils import mac_to_str, inet_to_str, make_dict
from pprint import pprint


def print_packet(buf):
    """Print out information about each packet in a pcap

       Args:
           buf: buffer of bytes for this packet
    """
    print(type(buf))

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(buf)
    print('Ethernet Frame: ', mac_to_str(eth.src), mac_to_str(eth.dst), eth.type)

    # Make sure the Ethernet data contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
        return

    # Now unpack the data within the Ethernet frame (the IP packet)
    # Pulling out src, dst, length, fragment info, TTL, and Protocol
    ip = eth.data

    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

    # Print out the info
    print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' %
          (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment,
           more_fragments, fragment_offset))

    # Check for UDP in the transport layer
    if isinstance(ip.data, dpkt.udp.UDP):

        # Set the UDP data
        udp = ip.data
        print('UDP: sport={:d} dport={:d} sum={:d} ulen={:d}'.format(udp.sport, udp.dport,
                                                                     udp.sum, udp.ulen))

        # Now see if we can parse the contents of the truncated DNS request
        try:
            dns = dpkt.dns.DNS()
            dns.unpack(udp.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, Exception) as e:
            print('\nError Parsing DNS, Might be a truncated packet...')
            print('Exception: {!r}'.format(e))

    # Print out the DNS info
    print('Queries: {:d}'.format(len(dns.qd)))
    for query in dns.qd:
        print('\t {:s} Type:{:d}'.format(query.name, query.type))
    print('Answers: {:d}'.format(len(dns.an)))
    for answer in dns.an:
        if answer.type == 5:
            print('\t {:s}: type: CNAME Answer: {:s}'.format(answer.name, answer.cname))
        elif answer.type == 1:
            print('\t {:s}: type: A Answer: {:s}'.format(answer.name, inet_to_str(answer.ip)))
        else:
            pprint(make_dict(answer))


def process_packets(pcap):
    """Process each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    try:
        for timestamp, buf in pcap:
            # Print out the timestamp in UTC
            print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
            print_packet(buf)
    except dpkt.dpkt.NeedData:
        print('\nPCAP capture is truncated, stopping processing...')
        sys.exit(1)


def test():
    """Open up a test pcap file and print out the packets"""
    with open('data/truncated_dns_2.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        process_packets(pcap)


if __name__ == '__main__':
    test()
