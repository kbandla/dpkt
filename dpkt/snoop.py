# $Id$
# -*- coding: utf-8 -*-
"""Snoop file format."""
from __future__ import absolute_import

import time

from . import dpkt
from .compat import intround

# RFC 1761

SNOOP_MAGIC = 0x736E6F6F70000000

SNOOP_VERSION = 2

SDL_8023 = 0
SDL_8024 = 1
SDL_8025 = 2
SDL_8026 = 3
SDL_ETHER = 4
SDL_HDLC = 5
SDL_CHSYNC = 6
SDL_IBMCC = 7
SDL_FDDI = 8
SDL_OTHER = 9

dltoff = {SDL_ETHER: 14}


class PktHdr(dpkt.Packet):
    """snoop packet header.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of snoop packet header.
        TODO.
    """

    __byte_order__ = '!'
    __hdr__ = (
        # 32-bit unsigned integer representing the length in octets of the
        # captured packet as received via a network.
        ('orig_len', 'I', 0),
        # 32-bit unsigned integer representing the length of the Packet Data
        # field.  This is the number of octets of the captured packet that are
        # included in this packet record.  If the received packet was
        # truncated, the Included Length field will be less than the Original
        # Length field.
        ('incl_len', 'I', 0),
        # 32-bit unsigned integer representing the total length of this packet
        # record in octets.  This includes the 24 octets of descriptive
        # information, the length of the Packet Data field, and the length of
        # the Pad field.
        ('rec_len', 'I', 0),
        # 32-bit unsigned integer representing the number of packets that were
        # lost by the system that created the packet file between the first
        # packet record in the file and this one.  Packets may be lost because
        # of insufficient resources in the capturing system, or for other
        # reasons.  Note: some implementations lack the ability to count
        # dropped packets.  Those implementations may set the cumulative drops
        # value to zero.
        ('cum_drops', 'I', 0),
        # 32-bit unsigned integer representing the time, in seconds since
        # January 1, 1970, when the packet arrived.
        ('ts_sec', 'I', 0),
        # 32-bit unsigned integer representing microsecond resolution of packet
        # arrival time.
        ('ts_usec', 'I', 0),
    )


class FileHdr(dpkt.Packet):
    """snoop file header.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of snoop file header.
        TODO.
    """

    __byte_order__ = '!'
    __hdr__ = (
        ('magic', 'Q', SNOOP_MAGIC),
        ('v', 'I', SNOOP_VERSION),
        ('linktype', 'I', SDL_ETHER),
    )


class FileWriter(object):
    def __init__(self, fileobj):
        self._f = fileobj
        self.write = self._f.write

    def close(self):
        self._f.close()


class Writer(FileWriter):
    """Simple snoop dumpfile writer.

    TODO: Longer class information....

    Attributes:
        TODO.
    """
    precision_multiplier = 1000000

    def __init__(self, fileobj, linktype=SDL_ETHER):
        super(Writer, self).__init__(fileobj)
        fh = FileHdr(linktype=linktype)

        self._PktHdr = PktHdr()
        self._pack_hdr = self._PktHdr._pack_hdr

        self.write(bytes(fh))

    def writepkt(self, pkt, ts=None):
        """Write single packet and optional timestamp to file.

        Args:
            pkt: `bytes` will be called on this and written to file.
            ts (float): Timestamp in seconds. Defaults to current time.
       """
        if ts is None:
            ts = time.time()

        self.writepkt_time(bytes(pkt), ts)

    def writepkt_time(self, pkt, ts):
        """Write single packet and its timestamp to file.

        Args:
            pkt (bytes): Some `bytes` to write to the file
            ts (float): Timestamp in seconds
       """
        pkt_len = len(pkt)
        pad_len = (4 - pkt_len) & 3

        pkt_header = self._pack_hdr(
            pkt_len,
            pkt_len,
            PktHdr.__hdr_len__ + pkt_len + pad_len,
            0,
            int(ts),
            intround(ts % 1 * self.precision_multiplier),
        )
        self.write(pkt_header + pkt + b'\x00' * pad_len)

    def writepkts(self, pkts):
        """Write an iterable of packets to file.

        Timestamps should be in seconds.
        Packets must be of type `bytes` as they will not be cast.

        Args:
            pkts: iterable containing (ts, pkt)
       """
        # take local references to these variables so we don't need to
        # dereference every time in the loop
        write = self.write
        pack_hdr = self._pack_hdr

        for ts, pkt in pkts:
            pkt_len = len(pkt)
            pad_len = (4 - pkt_len) & 3

            pkt_header = pack_hdr(
                pkt_len,
                pkt_len,
                PktHdr.__hdr_len__ + pkt_len + pad_len,
                0,
                int(ts),
                intround(ts % 1 * self.precision_multiplier),
            )
            fd.write(pkt_header + pkt + b'\x00' * pad_len)

class Reader(object):
    """Simple pypcap-compatible snoop file reader.

    TODO: Longer class information....

    Attributes:
        TODO.
    """

    def __init__(self, fileobj):
        self.name = fileobj.name
        self.fd = fileobj.fileno()
        self.__f = fileobj
        buf = self.__f.read(FileHdr.__hdr_len__)
        self.__fh = FileHdr(buf)
        self.__ph = PktHdr
        if self.__fh.magic != SNOOP_MAGIC:
            raise ValueError('invalid snoop header')
        self.dloff = dltoff[self.__fh.linktype]
        self.filter = ''

    def fileno(self):
        return self.fd

    def datalink(self):
        return self.__fh.linktype

    def setfilter(self, value, optimize=1):
        return NotImplementedError

    def readpkts(self):
        return list(self)

    def dispatch(self, cnt, callback, *args):
        if cnt > 0:
            for i in range(cnt):
                ts, pkt = next(self)
                callback(ts, pkt, *args)
        else:
            for ts, pkt in self:
                callback(ts, pkt, *args)

    def loop(self, callback, *args):
        self.dispatch(0, callback, *args)

    def __iter__(self):
        self.__f.seek(FileHdr.__hdr_len__)
        while 1:
            buf = self.__f.read(PktHdr.__hdr_len__)
            if not buf:
                break
            hdr = self.__ph(buf)
            buf = self.__f.read(hdr.rec_len - PktHdr.__hdr_len__)
            yield (hdr.ts_sec + (hdr.ts_usec / 1000000.0), buf[:hdr.incl_len])


def test_snoop_pkt_header():
    from binascii import unhexlify
    buf = unhexlify(
        '000000010000000200000003000000040000000500000006'
    )

    pkt = PktHdr(buf)
    assert pkt.orig_len == 1
    assert pkt.incl_len == 2
    assert pkt.rec_len == 3
    assert pkt.cum_drops == 4
    assert pkt.ts_sec == 5
    assert pkt.ts_usec == 6
    assert bytes(pkt) == buf


def test_snoop_file_header():
    from binascii import unhexlify
    buf = unhexlify(
        '000000000000000b000000160000014d'
    )
    hdr = FileHdr(buf)
    assert hdr.magic == 11
    assert hdr.v == 22
    assert hdr.linktype == 333


class TestSnoopWriter(object):
    from .compat import BytesIO
    from binascii import unhexlify

    @classmethod
    def setup_class(cls):
        cls.fobj = TestSnoopWriter.BytesIO()
        # write the file header only
        cls.writer = Writer(cls.fobj)

        cls.pkt = TestSnoopWriter.unhexlify(
            '000000010000000200000003000000040000000500000006'
        )

        cls.pkt_and_header = TestSnoopWriter.unhexlify(
            '00000018'  # orig_len
            '00000018'  # incl_len
            '00000030'  # rec_len
            '00000000'  # cum_drops
            '00000000'  # ts_sec
            '00000000'  # ts_usec

            # data
            '000000010000000200000003000000040000000500000006'
        )

    def test_snoop_file_writer_filehdr(self):
        correct_header = TestSnoopWriter.unhexlify(
            '736e6f6f700000000000000200000004'
        )

        # jump to the start and read the file header
        self.fobj.seek(0)
        buf = self.fobj.read()
        assert buf == correct_header

    def test_writepkt(self):
        loc = self.fobj.tell()
        self.writer.writepkt(self.pkt)

        # jump back to just before the writing of the packet
        self.fobj.seek(loc)
        # read the packet back in
        buf = self.fobj.read()
        # compare everything except the timestamp
        assert buf[:16] == self.pkt_and_header[:16]
        assert buf[24:] == self.pkt_and_header[24:]

    def test_writepkt_time(self):
        loc = self.fobj.tell()
        self.writer.writepkt_time(self.pkt, 0)
        self.fobj.seek(loc)
        # read the packet we just wrote
        buf = self.fobj.read()
        assert buf == self.pkt_and_header

    def test_writepkts(self):
        loc = self.fobj.tell()
        self.writer.writepkts([
            (0, self.pkt),
            (1, self.pkt),
            (2, self.pkt),
        ])
        self.fobj.seek(loc)
        buf = self.fobj.read()

        pkt_len = len(self.pkt_and_header)
        # chunk up the file and check each packet
        for idx in range(0, 3):
            pkt = buf[idx * pkt_len:(idx + 1) * pkt_len]

            assert pkt[:16] == self.pkt_and_header[:16]
            assert pkt[16:20] == dpkt.struct.pack('>I', idx)
            assert pkt[20:] == self.pkt_and_header[20:]

    def test_snoop_writer_close(self):
        assert not self.fobj.closed

        # check that the underlying file object is closed
        self.writer.close()
        assert self.fobj.closed


class TestFileWriter(object):
    from .compat import BytesIO
    def setup_method(self):
        self.fobj = TestFileWriter.BytesIO()
        self.writer = FileWriter(self.fobj)

    def test_write(self):
        buf = b'\x01' * 10
        self.writer.write(buf)
        self.fobj.seek(0)
        assert self.fobj.read() == buf

    def test_close(self):
        assert not self.fobj.closed
        self.writer.close()
        assert self.fobj.closed
