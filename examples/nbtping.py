#!/usr/bin/env python

import socket
from dpkt import netbios
import ping

class NBTPing(ping.Ping):
    def __init__(self):
        ping.Ping.__init__(self)
        self.op.add_option('-p', dest='port', type='int', default=137,
                      help='Remote NetBIOS name server port')

    def open_sock(self, opts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((opts.ip, opts.port))
        sock.settimeout(opts.wait)
        return sock
    
    def gen_ping(self, opts):
        for i in xrange(opts.count):
            ns = netbios.NS(id=i,
                qd=[ netbios.NS.Q(type=netbios.NS_NBSTAT, name='*') ])
            yield str(ns)

    def print_header(self, opts):
        print 'NBTPING %s:' % opts.ip
        
    def print_reply(self, opts, buf, rtt):
        ns = netbios.NS(buf)
        d = {}
        for rr in ns.an:
            for name, svc, flags in rr.nodenames:
                unique = (flags & netbios.NS_NAME_G == 0)
                if svc == 0 and unique and 'host' not in d:
                    d['host'] = name
                elif svc == 0x03 and unique:
                    if 'user' not in d or d['user'].startswith(d['host']):
                        d['user'] = name
        print '%d bytes from %s: id=%d time=%.3f ms host=%s user=%s' % \
              (len(buf), opts.ip, ns.id, rtt * 1000,
               d.get('host', ''), d.get('user', ''))

if __name__ == '__main__':
    NBTPing().main()
