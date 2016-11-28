
Print HTTP Requests Example
===========================

This example expands on the print_packets example. It checks for HTTP request headers and displays their contents.

**NOTE:** We are not reconstructing 'flows' so the request (and response if you tried to parse it) will only
parse correctly if they fit within a single packet. Requests can often fit in a single packet but
Responses almost never will. For proper reconstruction of flows you may want to look at other projects
that use DPKT (http://chains.readthedocs.io and others)

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

        # Check for TCP in the transport layer
        if isinstance(ip.data, dpkt.tcp.TCP):

            # Set the TCP data
            tcp = ip.data

            # Now see if we can parse the contents as a HTTP request
            try:
                request = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            # Print out the info
            print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
            print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type
            print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
                  (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
            print 'HTTP request: %s\n' % repr(request)


**Example Output**

.. code-block:: json

        Timestamp:  2004-05-13 10:17:08.222534
        Ethernet Frame:  00:00:01:00:00:00 fe:ff:20:00:01:00 2048
        IP: 145.254.160.237 -> 65.208.228.223   (len=519 ttl=128 DF=1 MF=0 offset=0)
        HTTP request: Request(body='', uri='/download.html', headers={'accept-language': 'en-us,en;q=0.5', 'accept-encoding': 'gzip,deflate', 'connection': 'keep-alive', 'keep-alive': '300', 'accept': 'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1', 'user-agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113', 'accept-charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7', 'host': 'www.ethereal.com', 'referer': 'http://www.ethereal.com/development.html'}, version='1.1', data='', method='GET')

        Timestamp:  2004-05-13 10:17:10.295515
        Ethernet Frame:  00:00:01:00:00:00 fe:ff:20:00:01:00 2048
        IP: 145.254.160.237 -> 216.239.59.99   (len=761 ttl=128 DF=1 MF=0 offset=0)
        HTTP request: Request(body='', uri='/pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020&format=468x60_as&output=html&url=http%3A%2F%2Fwww.ethereal.com%2Fdownload.html&color_bg=FFFFFF&color_text=333333&color_link=000000&color_url=666633&color_border=666633', headers={'accept-language': 'en-us,en;q=0.5', 'accept-encoding': 'gzip,deflate', 'connection': 'keep-alive', 'keep-alive': '300', 'accept': 'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1', 'user-agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113', 'accept-charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7', 'host': 'pagead2.googlesyndication.com', 'referer': 'http://www.ethereal.com/download.html'}, version='1.1', data='', method='GET')

        ...

**dpkt/examples/print_http_requests.py**

.. automodule:: examples.print_http_requests
