
Print Packets Example
=====================
This example uses DPKT to read in a pcap file and print out the contents of the packets This example is
focused on the fields in the Ethernet Frame and IP packet

**Code Excerpt**

.. code-block:: python

    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Print out the timestamp in UTC
        print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

        # Make sure the Ethernet frame contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
              (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)

**Example Output**

.. code-block:: json

        Timestamp:  2004-05-13 10:17:07.311224
        Ethernet Frame:  00:00:01:00:00:00 fe:ff:20:00:01:00 2048
        IP: 145.254.160.237 -> 65.208.228.223   (len=48 ttl=128 DF=1 MF=0 offset=0)

        Timestamp:  2004-05-13 10:17:08.222534
        Ethernet Frame:  fe:ff:20:00:01:00 00:00:01:00:00:00 2048
        IP: 65.208.228.223 -> 145.254.160.237   (len=48 ttl=47 DF=1 MF=0 offset=0)

        ...

**dpkt/examples/print_packets.py**

.. automodule:: examples.print_packets
