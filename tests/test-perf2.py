#!/usr/bin/env python

import dpkt
import time, unittest

class TestPerf(unittest.TestCase):
    rounds = 10000

    def setUp(self):
        self.start = time.time()
    def tearDown(self):
        print self.rounds / (time.time() - self.start), 'rounds/s'

    def test_pack(self):
        for i in xrange(self.rounds):
            str(dpkt.ip.IP())
        print 'pack:',

    def test_unpack(self):
        buf = str(dpkt.ip.IP())
        for i in xrange(self.rounds):
            dpkt.ip.IP(buf)
        print 'unpack:',
        
if __name__ == '__main__':
    unittest.main()
