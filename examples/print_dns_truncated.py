"""
Use DPKT to read in a pcap file and print out the contents of trucated
DNS packets. This example show how to read/handle trucated packets
"""
import dpkt
import datetime
from dpkt.utils import mac_to_str, inet_to_str
from pprint import pprint

def make_dict(obj):
    """This method creates a dictionary out of a non-builtin object"""

    # Recursion base case
    if is_builtin(obj):
        return obj

    output_dict = {}
    for key in dir(obj):
        if not key.startswith('__') and not callable(getattr(obj, key)):
            attr = getattr(obj, key)
            if isinstance(attr, list):
                output_dict[key] = []
                for item in attr:
                    output_dict[key].append(make_dict(item))
            else:
                output_dict[key] = make_dict(attr)

    # All done
    return output_dict


def is_builtin(obj):
    return obj.__class__.__module__ in ['__builtin__', 'builtins']


def print_packets(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Print out the timestamp in UTC
        print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        print('Ethernet Frame: ', mac_to_str(eth.src), mac_to_str(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' %
              (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, 
               more_fragments, fragment_offset))

        # Check for UDP in the transport layer
        if isinstance(ip.data, dpkt.udp.UDP):

            # Set the UDP data
            udp = ip.data

            # Now see if we can parse the contents of the trucated DNS request
            try:
                dns = dpkt.dns.DNS()
                dns.unpack(udp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                print('Trucated DNS...')
                print(udp.data)
                continue
            except Exception as e:
                print('Exception: {!r}'.format(e))
    
        # Print out info
        dns_data = make_dict(dns)
        pprint(dns_data)


def test():
    """Open up a test pcap file and print out the packets"""
    with open('/Users/briford/data/pcaps/dpkt_test/test.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)


if __name__ == '__main__':
    test()
