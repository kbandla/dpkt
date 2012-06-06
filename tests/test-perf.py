#!/usr/bin/env python

import time, sys

import dnet
sys.path.insert(0, '.')
import dpkt
from impacket import ImpactDecoder, ImpactPacket
from openbsd import packet
import scapy
import xstruct

xip = xstruct.structdef('>', [
    ('v_hl', ('B', 1), (4 << 4) | (dnet.IP_HDR_LEN >> 2)),
    ('tos', ('B', 1), dnet.IP_TOS_DEFAULT),
    ('len', ('H', 1), dnet.IP_HDR_LEN),
    ('id', ('H', 1), 0),
    ('off', ('H', 1), 0),
    ('ttl', ('B', 1), dnet.IP_TTL_DEFAULT),
    ('p', ('B', 1), 0),
    ('sum', ('H', 1), 0),
    ('src', ('s', dnet.IP_ADDR_LEN), dnet.IP_ADDR_ANY),
    ('dst', ('s', dnet.IP_ADDR_LEN), dnet.IP_ADDR_ANY)
    ])

xudp = xstruct.structdef('>', [
    ('sport', ('B', 1), 0),
    ('dport', ('B', 1), 0),
    ('ulen', ('H', 1), dnet.UDP_HDR_LEN),
    ('sum', ('H', 1), 0)
    ])

def compare_create(cnt):
    """
dpkt: 14915.2445937 pps
dpkt (manual): 15494.3632903 pps
impacket: 3929.30572776 pps
openbsd.packet: 1503.7928579 pps
scapy: 348.449269721 pps
xstruct: 88314.8953732 pps
"""
    src = dnet.addr('1.2.3.4').ip
    dst = dnet.addr('5.6.7.8').ip
    data = 'hello world'

    start = time.time()
    for i in xrange(cnt):
        dnet.ip_checksum(
            str(dpkt.ip.IP(src=src, dst=dst, p=dnet.IP_PROTO_UDP,
                         len = dnet.IP_HDR_LEN + dnet.UDP_HDR_LEN + len(data),
                         data=dpkt.udp.UDP(sport=111, dport=222,
                                       ulen=dnet.UDP_HDR_LEN + len(data),
                                       data=data))))
    print 'dpkt:', cnt / (time.time() - start), 'pps'
    
    start = time.time()
    for i in xrange(cnt):
        dnet.ip_checksum(str(dpkt.ip.IP(src=src, dst=dst, p=dnet.IP_PROTO_UDP,
                                     len=dnet.IP_HDR_LEN + dnet.UDP_HDR_LEN +
                                     len(data))) +
                         str(dpkt.udp.UDP(sport=111, dport=222,
                                      ulen=dnet.UDP_HDR_LEN + len(data))) +
                         data)
    print 'dpkt (manual):', cnt / (time.time() - start), 'pps'
    
    start = time.time()
    for i in xrange(cnt):
        ip = ImpactPacket.IP()
        ip.set_ip_src('1.2.3.4')
        ip.set_ip_dst('5.6.7.8')
        udp = ImpactPacket.UDP()
        udp.set_uh_sport(111)
        udp.set_uh_dport(222)
        udp.contains(ImpactPacket.Data(data))
        ip.contains(udp)
        ip.get_packet()
    print 'impacket:', cnt / (time.time() - start), 'pps'

    start = time.time()
    for i in xrange(cnt):
        p = packet.createPacket(packet.IP, packet.UDP)
        p['ip'].src = '1.2.3.4'
        p['ip'].dst = '5.6.7.8'
        p['udp'].sport = 111
        p['udp'].dport = 22
        p['udp'].payload = data
        p.finalise()
        p.getRaw()
    print 'openbsd.packet:', cnt / (time.time() - start), 'pps'
    
    start = time.time()
    for i in xrange(cnt):
        ip = scapy.IP(src='1.2.3.4', dst='5.6.7.8') / \
             scapy.UDP(sport=111, dport=222) / data
        ip.build()
    print 'scapy:', cnt / (time.time() - start), 'pps'
    
    start = time.time()
    for i in xrange(cnt):
        udp = xudp()
        udp.sport = 111
        udp.dport = 222
        udp.ulen = dnet.UDP_HDR_LEN + len(data)
        ip = xip()
        ip.src = src
        ip.dst = dst
        ip.p = dnet.IP_PROTO_UDP
        ip.len = dnet.IP_HDR_LEN + udp.ulen
        dnet.ip_checksum(str(ip) + str(udp) + data)
    print 'xstruct:', cnt / (time.time() - start), 'pps'
    
def compare_parse(cnt):
    """
dpkt: 23347.462887 pps
impacket: 9937.75963595 pps
openbsd.packet: 6826.5955563 pps
scapy: 1461.74727127 pps
xstruct: 206100.202449 pps
"""
    s = 'E\x00\x00T\xc2\xf3\x00\x00\xff\x01\xe2\x18\n\x00\x01\x92\n\x00\x01\x0b\x08\x00\xfc\x11:g\x00\x00A,\xc66\x00\x0e\xcf\x12\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f!"#$%&\'()*+,-./01234567'

    start = time.time()
    for i in xrange(cnt):
        dpkt.ip.IP(s)
    print 'dpkt:', cnt / (time.time() - start), 'pps'
    
    decoder = ImpactDecoder.IPDecoder()
    start = time.time()
    for i in xrange(cnt):
        decoder.decode(s)
    print 'impacket:', cnt / (time.time() - start), 'pps'

    start = time.time()
    for i in xrange(cnt):
        packet.Packet(packet.IP, s)
    print 'openbsd.packet:', cnt / (time.time() - start), 'pps'

    start = time.time()
    for i in xrange(cnt):
        scapy.IP(s)
    print 'scapy:', cnt / (time.time() - start), 'pps'

    start = time.time()
    for i in xrange(cnt):
        ip = xip(s[:dnet.IP_HDR_LEN])
        udp = xudp(s[dnet.IP_HDR_LEN:dnet.IP_HDR_LEN + dnet.UDP_HDR_LEN])
        data = s[dnet.IP_HDR_LEN + dnet.UDP_HDR_LEN:]
    print 'xstruct:', cnt / (time.time() - start), 'pps'

def compare_checksum(cnt):
    s = 'A' * 80
    start = time.time()
    for i in range(cnt):
        dpkt.in_cksum(s)
    print 'dpkt.in_cksum:', cnt / (time.time() - start), 'pps'
    
    start = time.time()
    for i in range(cnt):
        dnet.ip_cksum_carry(dnet.ip_cksum_add(s, 0))
    print 'dnet.ip_cksum_add/carry:', cnt / (time.time() - start), 'pps'

def main():
    import psyco
    psyco.full()

    ITER=10000
    
    print 'checksum:'
    compare_checksum(100000)

    print 'create:'
    compare_create(ITER)

    print 'parse:'
    compare_parse(ITER)
    
if __name__ == '__main__':
    main()
    """
    import hotshot, hotshot.stats
    prof = hotshot.Profile('/var/tmp/dpkt.prof')
    prof.runcall(main)
    prof.close()
    stats = hotshot.stats.load('/var/tmp/dpkt.prof')
    stats.strip_dirs()
    stats.sort_stats('time', 'calls')
    stats.print_stats(20)
    """
