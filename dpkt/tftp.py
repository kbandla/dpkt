# $Id: tftp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Trivial File Transfer Protocol."""

import struct
import dpkt

# Opcodes
OP_RRQ = 1  # read request
OP_WRQ = 2  # write request
OP_DATA = 3  # data packet
OP_ACK = 4  # acknowledgment
OP_ERR = 5  # error code

# Error codes
EUNDEF = 0  # not defined
ENOTFOUND = 1  # file not found
EACCESS = 2  # access violation
ENOSPACE = 3  # disk full or allocation exceeded
EBADOP = 4  # illegal TFTP operation
EBADID = 5  # unknown transfer ID
EEXISTS = 6  # file already exists
ENOUSER = 7  # no such user


class TFTP(dpkt.Packet):
    __hdr__ = (('opcode', 'H', 1), )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.opcode in (OP_RRQ, OP_WRQ):
            l = self.data.split('\x00')
            self.filename = l[0]
            self.mode = l[1]
            self.data = ''
        elif self.opcode in (OP_DATA, OP_ACK):
            self.block = struct.unpack('>H', self.data[:2])[0]
            self.data = self.data[2:]
        elif self.opcode == OP_ERR:
            self.errcode = struct.unpack('>H', self.data[:2])
            self.errmsg = self.data[2:].split('\x00')[0]
            self.data = ''

    def __len__(self):
        return len(str(self))

    def __str__(self):
        if self.opcode in (OP_RRQ, OP_WRQ):
            s = '%s\x00%s\x00' % (self.filename, self.mode)
        elif self.opcode in (OP_DATA, OP_ACK):
            s = struct.pack('>H', self.block)
        elif self.opcode == OP_ERR:
            s = struct.pack('>H', self.errcode) + ('%s\x00' % self.errmsg)
        else:
            s = ''
        return self.pack_hdr() + s + self.data


def test_op_rrq():
    s = '\x00\x01\x72\x66\x63\x31\x33\x35\x30\x2e\x74\x78\x74\x00\x6f\x63\x74\x65\x74\x00'
    t = TFTP(s)
    assert t.filename == 'rfc1350.txt'
    assert t.mode == 'octet'
    assert str(t) == s


def test_op_data():
    s = '\x00\x03\x00\x01\x0a\x0a\x4e\x65\x74\x77\x6f\x72\x6b\x20\x57\x6f\x72\x6b\x69\x6e\x67\x20\x47\x72\x6f\x75\x70'
    t = TFTP(s)
    assert t.block == 1
    assert t.data == '\x0a\x0aNetwork Working Group'
    assert str(t) == s


def test_op_err():
    pass  # XXX - TODO


if __name__ == '__main__':
    test_op_rrq()
    test_op_data()
    test_op_err()

    print 'Tests Successful...'
