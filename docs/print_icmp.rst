
Print ICMP Example
==================

This example expands on the print_packets example. It checks for ICMP packets and displays the ICMP contents.

**Code Excerpt**

.. code-block:: python

    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
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
            print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
            print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type
            print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
                  (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
            print 'ICMP: type:%d code:%d checksum:%d data: %s\n' % (icmp.type, icmp.code, icmp.sum, repr(icmp.data))

**Example Output**

.. code-block:: json

      Timestamp:  2013-05-30 22:45:17.283187
      Ethernet Frame:  60:33:4b:13:c5:58 02:1a:11:f0:c8:3b 2048
      IP: 192.168.43.9 -> 8.8.8.8   (len=84 ttl=64 DF=0 MF=0 offset=0)
      ICMP: type:8 code:0 checksum:48051 data: Echo(id=55099, data='Q\xa7\xd6}\x00\x04Q\xe4\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567')

      Timestamp:  2013-05-30 22:45:17.775391
      Ethernet Frame:  02:1a:11:f0:c8:3b 60:33:4b:13:c5:58 2048
      IP: 8.8.8.8 -> 192.168.43.9   (len=84 ttl=40 DF=0 MF=0 offset=0)
      ICMP: type:0 code:0 checksum:50099 data: Echo(id=55099, data='Q\xa7\xd6}\x00\x04Q\xe4\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567')

      ...

**dpkt/examples/print_icmp.py**

.. automodule:: examples.print_icmp
