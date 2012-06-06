#!/usr/bin/env python

import random, socket
import dpkt
import ping

class DNSPing(ping.Ping):
    def __init__(self):
        ping.Ping.__init__(self)
        self.op.add_option('-z', dest='zone', type='string',
                      default=socket.gethostname().split('.', 1)[1],
                      help='Domain to formulate queries in')
        self.op.add_option('-n', dest='hostname', type='string',
                      help='Query only for a given hostname')
        self.op.add_option('-p', dest='port', type='int', default=53,
                      help='Remote DNS server port')
        self.op.add_option('-R', dest='norecurse', action='store_true',
                      help='Disable recursive queries')

    def open_sock(self, opts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((opts.ip, opts.port))
        sock.settimeout(opts.wait)
        return sock

    def gen_ping(self, opts):
        for i in xrange(opts.count):
            dns = dpkt.dns.DNS(id=i)
            if opts.norecurse:
                dns.op &= ~dpkt.dns.DNS_RD
            if not opts.hostname:
                name = '%s.%s' % (str(random.random())[-6:], opts.zone)
            else:
                name = opts.hostname
            dns.qd = [ dpkt.dns.DNS.Q(name=name) ]
            yield str(dns)

    def print_header(self, opts):
        print 'DNSPING %s:' % opts.ip,
        if opts.hostname:
            print 'Name: %s' % opts.hostname
        else:
            print 'Name: *.%s' % opts.zone
        
    def print_reply(self, opts, buf, rtt):
        dns = dpkt.dns.DNS(buf)
        print '%d bytes from %s: id=%d time=%.3f ms' % \
              (len(buf), opts.ip, dns.id, rtt * 1000)

if __name__ == '__main__':
    DNSPing().main()
