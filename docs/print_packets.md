# Print Packets Example

This example uses DPKT to read in a pcap file and print out the contents
of the packets. This example is focused on the fields in the Ethernet
Frame and IP packet.

**Code Excerpt**

``` python
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

    # Now access the data within the Ethernet frame (the IP packet)
    # Pulling out src, dst, length, fragment info, TTL, and Protocol
    ip = eth.data

    # Print out the info, including the fragment flags and offset
    print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' %
          (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, ip.df, ip.mf, ip.offset))

# Pretty print the last packet
print('** Pretty print demo **\n')
eth.pprint()
```

**Example Output**

```
Timestamp:  2004-05-13 10:17:07.311224
Ethernet Frame:  00:00:01:00:00:00 fe:ff:20:00:01:00 2048
IP: 145.254.160.237 -> 65.208.228.223   (len=48 ttl=128 DF=1 MF=0 offset=0)

Timestamp:  2004-05-13 10:17:08.222534
Ethernet Frame:  fe:ff:20:00:01:00 00:00:01:00:00:00 2048
IP: 65.208.228.223 -> 145.254.160.237   (len=48 ttl=47 DF=1 MF=0 offset=0)

** Pretty print demo **

Ethernet(
  dst=b'\x00\x00\x01\x00\x00\x00',  # 00:00:01:00:00:00
  src=b'\xfe\xff \x00\x01\x00',  # fe:ff:20:00:01:00
  type=2048,
  data=IP(
    v=4,
    hl=5,
    tos=0,
    len=40,
    id=0,
    off=16384,
    ttl=47,
    p=6,
    sum=62004,  # 0xf234
    src=b'A\xd0\xe4\xdf',  # 65.208.228.223
    dst=b'\x91\xfe\xa0\xed',  # 145.254.160.237
    opts=b'',
    data=TCP(
      sport=80,
      dport=3372,
      seq=290236745,
      ack=951058420,
      off=5,
      flags=16,  # ACK
      win=6432,
      sum=15459,  # 0x3c63
      urp=0,
      opts=b'',
    )  # TCP
  )  # IP
)  # Ethernet
```

**See full code at: <https://github.com/kbandla/dpkt/blob/master/examples/print_packets.py>**

