"""
pcap Next Generation file format
"""
# Spec: https://pcapng.github.io/pcapng/

# pylint: disable=no-member
# pylint: disable=attribute-defined-outside-init

from struct import pack as struct_pack, unpack as struct_unpack
import sys
import time

import dpkt

BYTE_ORDER_MAGIC = 0x1A2B3C4D
BYTE_ORDER_MAGIC_LE = 0x4D3C2B1A

PCAPNG_VERSION_MAJOR = 1
PCAPNG_VERSION_MINOR = 0

# Block types
PCAPNG_BT_IDB = 0x00000001     # Interface Description Block
PCAPNG_BT_PB = 0x00000002      # Packet Block (deprecated)
PCAPNG_BT_SPB = 0x00000003     # Simple Packet Block
PCAPNG_BT_EPB = 0x00000006     # Enhanced Packet Block
PCAPNG_BT_SHB = 0x0A0D0D0A     # Section Header Block

# Options
PCAPNG_OPT_ENDOFOPT = 0        # end of options
PCAPNG_OPT_COMMENT = 1         # comment

# SHB options
PCAPNG_OPT_SHB_HARDWARE = 2    # description of the hardware
PCAPNG_OPT_SHB_OS = 3          # name of the operating system
PCAPNG_OPT_SHB_USERAPPL = 4    # name of the application

# IDB options
PCAPNG_OPT_IF_NAME = 2         # interface name
PCAPNG_OPT_IF_DESCRIPTION = 3  # interface description
PCAPNG_OPT_IF_IPV4ADDR = 4     # IPv4 network address and netmask for the interface
PCAPNG_OPT_IF_IPV6ADDR = 5     # IPv6 network address and prefix length for the interface
PCAPNG_OPT_IF_MACADDR = 6      # interface hardware MAC address
PCAPNG_OPT_IF_EUIADDR = 7      # interface hardware EUI address
PCAPNG_OPT_IF_SPEED = 8        # interface speed in bits/s
PCAPNG_OPT_IF_TSRESOL = 9      # timestamp resolution
PCAPNG_OPT_IF_TZONE = 10       # time zone
PCAPNG_OPT_IF_FILTER = 11      # capture filter
PCAPNG_OPT_IF_OS = 12          # operating system
PCAPNG_OPT_IF_FCSLEN = 13      # length of the Frame Check Sequence in bits
PCAPNG_OPT_IF_TSOFFSET = 14    # offset (in seconds) that must be added to packet timestamp

# <copied from pcap.py>
DLT_NULL = 0
DLT_EN10MB = 1
DLT_EN3MB = 2
DLT_AX25 = 3
DLT_PRONET = 4
DLT_CHAOS = 5
DLT_IEEE802 = 6
DLT_ARCNET = 7
DLT_SLIP = 8
DLT_PPP = 9
DLT_FDDI = 10
DLT_PFSYNC = 18
DLT_IEEE802_11 = 105
DLT_LINUX_SLL = 113
DLT_PFLOG = 117
DLT_IEEE802_11_RADIO = 127

if sys.platform.find('openbsd') != -1:
    DLT_LOOP = 12
    DLT_RAW = 14
else:
    DLT_LOOP = 108
    DLT_RAW = 12

dltoff = {DLT_NULL: 4, DLT_EN10MB: 14, DLT_IEEE802: 22, DLT_ARCNET: 6,
          DLT_SLIP: 16, DLT_PPP: 4, DLT_FDDI: 21, DLT_PFLOG: 48, DLT_PFSYNC: 4,
          DLT_LOOP: 4, DLT_LINUX_SLL: 16}
# </copied from pcap.py>


def _swap32b(num):
    """swap endianness of an uint32"""
    return struct_unpack('<I', struct_pack('>I', num))[0]


def _align32b(num):
    """return the `num` aligned to the 32-bit boundary"""
    r = num % 4
    return num if not r else num + 4 - r


def _align32str(s):
    """return str `s` padded with zeroes to align to the 32-bit boundary"""
    return struct_pack('%ss' % _align32b(len(s)), s)


class PcapngOption(dpkt.Packet):
    """A single Option"""
    __hdr__ = (
        ('code', 'H', PCAPNG_OPT_ENDOFOPT),
        ('len', 'H', 0),
        ('val', '0s', '')
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.val = buf[self.__hdr_len__:self.__hdr_len__ + self.len]
        self.data = ''  # discard any padding

        # decode comment
        if self.code == PCAPNG_OPT_COMMENT:
            self.val = self.val.decode('utf-8')

    def pack_hdr(self):
        # encode comment
        if self.code == PCAPNG_OPT_COMMENT and isinstance(self.val, unicode):
            self.val = self.val.encode('utf-8')
        self.len = len(self.val)
        return dpkt.Packet.pack_hdr(self) + _align32str(self.val)

    def __len__(self):
        return len(self.pack_hdr())


class PcapngOptionLE(PcapngOption):
    __byte_order__ = '<'


class PcapngBlock(dpkt.Packet):
    """Generic pcapng block"""
    __hdr__ = (
        ('type', 'I', 0),  # block type
        ('len', 'I', 12),  # block total length: total size of this block, in octets
        #( body, variable size )
        ('_len', 'I', 12),  # dup of len
    )

    @property
    def tail(self):
        return self._len

    def unpack_options(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.len > len(buf):
            raise dpkt.NeedData
        self._do_unpack_options(buf)

    def _do_unpack_options(self, buf, oo=None):
        self.opts = []
        self.data = ''
        oo = oo or self.__hdr_len__ - 4  # options offset
        ol = self.len - oo - 4  # length

        opts_buf = buf[oo:oo + ol]
        while opts_buf:
            opt = (PcapngOptionLE(opts_buf) if self.__byte_order__ == '<'
                   else PcapngOption(opts_buf))

            self.opts.append(opt)
            opts_buf = opts_buf[opt.__hdr_len__ + _align32b(opt.len):]
            if opt.code == PCAPNG_OPT_ENDOFOPT:
                break

        # duplicate total length field
        self._len = struct_unpack(
            self.__byte_order__ + 'I', buf[oo + ol:oo + ol + 4])[0]
        if self._len != self.len:
            raise dpkt.UnpackError('length fields do not match')

    def _do_pack_options(self):
        if self.opts[-1].code != PCAPNG_OPT_ENDOFOPT:
            raise dpkt.PackError('options must end with opt_endofopt')
        return ''.join(str(o) for o in self.opts)

    def pack_hdr(self):
        if not self.opts:
            return dpkt.Packet.pack_hdr(self)

        opts_buf = self._do_pack_options()
        self.len = self._len = self.__hdr_len__ + len(opts_buf)

        hdr_buf = dpkt.Packet.pack_hdr(self)
        return hdr_buf[:-4] + opts_buf + hdr_buf[-4:]

    def __len__(self):
        if not self.opts:
            return self.__hdr_len__

        opts_len = sum(len(o) for o in self.opts)
        return self.__hdr_len__ + opts_len


class PcapngBlockLE(PcapngBlock):
    __byte_order__ = '<'


class SectionHeaderBlock(PcapngBlock):
    """Section Header block"""
    __hdr__ = (
        ('type', 'I', PCAPNG_BT_SHB),
        ('len', 'I', 28),
        ('bom', 'I', BYTE_ORDER_MAGIC),
        ('v_major', 'H', PCAPNG_VERSION_MAJOR),
        ('v_minor', 'H', PCAPNG_VERSION_MINOR),
        ('sec_len', 'q', -1),  # section length, -1 = auto
        #( options, variable size )
        ('_len', 'I', 28)
    )

    def unpack(self, buf):
        self.unpack_options(buf)


class SectionHeaderBlockLE(SectionHeaderBlock):
    __byte_order__ = '<'


class InterfaceDescriptionBlock(PcapngBlock):
    """Interface Description block"""
    __hdr__ = (
        ('type', 'I', PCAPNG_BT_IDB),
        ('len', 'I', 20),
        ('linktype', 'H', DLT_EN10MB),
        ('_reserved', 'H', 0),
        ('snaplen', 'I', 1500),
        #( options, variable size )
        ('_len', 'I', 20)
    )

    def unpack(self, buf):
        self.unpack_options(buf)


class InterfaceDescriptionBlockLE(InterfaceDescriptionBlock):
    __byte_order__ = '<'


class EnhancedPacketBlock(PcapngBlock):
    """Enhanced Packet Block"""
    __hdr__ = (
        ('type', 'I', PCAPNG_BT_EPB),
        ('len', 'I', 64),
        ('iface_id', 'I', 0),
        ('ts_high', 'I', 0),  # timestamp high
        ('ts_low', 'I', 0),  # timestamp low
        ('caplen', 'I', 0),  # captured len, size of pkt_data
        ('pkt_len', 'I', 0),  # actual packet len
        #( pkt_data, variable size )
        #( options, variable size )
        ('_len', 'I', 64)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        if self.len > len(buf):
            raise dpkt.NeedData

        # packet data
        po = self.__hdr_len__ - 4  # offset of pkt_data
        self.pkt_data = buf[po:po + self.caplen]

        # skip padding between pkt_data and options
        opts_offset = po + _align32b(self.caplen)
        self._do_unpack_options(buf, opts_offset)

    def pack_hdr(self):
        self.caplen = self.pkt_len = len(self.pkt_data)

        opts_buf = self._do_pack_options()
        self.len = self._len = self.__hdr_len__ + _align32b(self.caplen) + len(opts_buf)

        hdr_buf = dpkt.Packet.pack_hdr(self)
        return hdr_buf[:-4] + _align32str(self.pkt_data) + opts_buf + hdr_buf[-4:]

    def __len__(self):
        opts_len = sum(len(o) for o in self.opts)
        return self.__hdr_len__ + _align32b(self.caplen) + opts_len


class EnhancedPacketBlockLE(EnhancedPacketBlock):
    __byte_order__ = '<'


class Writer(object):
    """Simple pcapng dumpfile writer."""

    def __init__(self, fileobj, snaplen=1500, linktype=DLT_EN10MB):
        self.__f = fileobj
        self.__le = sys.byteorder == 'little'
        if self.__le:
            shb = SectionHeaderBlockLE(bom=BYTE_ORDER_MAGIC_LE)
            idb = InterfaceDescriptionBlockLE(snaplen=snaplen, linktype=linktype)
        else:
            shb = SectionHeaderBlock()
            idb = InterfaceDescriptionBlock(snaplen=snaplen, linktype=linktype)
        self.__f.write(str(shb))
        self.__f.write(str(idb))

    def writepkt(self, pkt, ts=None):
        if ts is None:
            ts = time.time()
        ts *= 1E6  # to microseconds

        s = str(pkt)
        n = len(s)

        kls = EnhancedPacketBlockLE if self.__le else EnhancedPacketBlock
        epb = kls(ts_high=ts >> 32, ts_low=ts & 0xffffffff, caplen=n, pkt_len=n, pkt_data=s)
        self.__f.write(str(epb))

    def close(self):
        self.__f.close()


class Reader(object):
    """Simple pypcap-compatible pcapng file reader."""

    def __init__(self, fileobj):
        self.name = getattr(fileobj, 'name', '<{}>'.format(fileobj.__class__.__name__))
        self.__f = fileobj

        buf = self.__f.read(PcapngBlock.__hdr_len__)
        hdr = PcapngBlock(buf)

        if hdr.type != PCAPNG_BT_SHB:
            raise ValueError('invalid pcapng header')

        # determine the correct byte order and read full SHB
        if hdr.tail == BYTE_ORDER_MAGIC:
            self.__le = False
            buf += self.__f.read(hdr.len - hdr.__hdr_len__)
            shb = SectionHeaderBlock(buf)
        elif hdr.tail == BYTE_ORDER_MAGIC_LE:
            self.__le = True
            buf += self.__f.read(_swap32b(hdr.len) - hdr.__hdr_len__)
            shb = SectionHeaderBlockLE(buf)
        else:
            raise ValueError('unknown endianness')

        # check if this version is supported
        if shb.v_major != PCAPNG_VERSION_MAJOR:
            raise ValueError('unknown pcapng version {}.{}'.format(shb.v_major, shb.v_minor,))

        # look for a mandatory IDB
        idb = None
        while 1:
            buf = self.__f.read(PcapngBlock.__hdr_len__)
            if not buf:
                break

            blk = PcapngBlockLE(buf) if self.__le else PcapngBlock(buf)
            buf += self.__f.read(blk.len - blk.__hdr_len__)

            if blk.type == PCAPNG_BT_IDB:
                idb = (InterfaceDescriptionBlockLE(buf) if self.__le
                       else InterfaceDescriptionBlock(buf))
                break

            elif blk.type in (PCAPNG_BT_SPB, PCAPNG_BT_EPB, PCAPNG_BT_PB):
                raise ValueError('packet block before interface description block')
            # just skip other blocks

        if idb is None:
            raise ValueError('interface description block not found')

        # set timestamp resolution and offset
        self._divisor = 1E6  # defaults
        self._tsoffset = 0
        for opt in idb.opts:
            if opt.code == PCAPNG_OPT_IF_TSRESOL:
                # if MSB=0, the remaining bits is a neg power of 10 (e.g. 6 means microsecs)
                # if MSB=1, the remaining bits is a neg power of 2 (e.g. 10 means 1/1024 of second)
                opt_val = struct_unpack('b', opt.val)[0]
                pow_num = 2 if opt_val & 0b10000000 else 10
                self._divisor = pow_num ** (opt_val & 0b01111111)

            elif opt.code == PCAPNG_OPT_IF_TSOFFSET:
                # 64-bit int that specifies an offset (in seconds) that must be added to the
                # timestamp of each packet
                self._tsoffset = struct_unpack('<q' if self.__le else '>q', opt.val)[0]

        if idb.linktype in dltoff:
            self.dloff = dltoff[idb.linktype]
        else:
            self.dloff = 0

        self.idb = idb
        self.snaplen = idb.snaplen
        self.filter = ''
        self.__iter = iter(self)

    @property
    def fd(self):
        return self.__f.fileno()

    def fileno(self):
        return self.fd

    def datalink(self):
        return self.idb.linktype

    def setfilter(self, value, optimize=1):
        return NotImplementedError

    def readpkts(self):
        return list(self)

    def next(self):
        return self.__iter.next()

    def dispatch(self, cnt, callback, *args):
        """Collect and process packets with a user callback.

        Return the number of packets processed, or 0 for a savefile.

        Arguments:

        cnt      -- number of packets to process;
                    or 0 to process all packets until EOF
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        processed = 0
        if cnt > 0:
            for _ in range(cnt):
                try:
                    ts, pkt = self.next()
                except StopIteration:
                    break
                callback(ts, pkt, *args)
                processed += 1
        else:
            for ts, pkt in self:
                callback(ts, pkt, *args)
                processed += 1
        return processed

    def loop(self, callback, *args):
        self.dispatch(0, callback, *args)

    def __iter__(self):
        while 1:
            buf = self.__f.read(PcapngBlock.__hdr_len__)
            if not buf:
                break

            blk = PcapngBlockLE(buf) if self.__le else PcapngBlock(buf)
            if blk.type == PCAPNG_BT_EPB:
                buf += self.__f.read(blk.len - blk.__hdr_len__)
                epb = EnhancedPacketBlockLE(buf) if self.__le else EnhancedPacketBlock(buf)

                # calculate the timestamp
                ts = self._tsoffset + (((epb.ts_high << 32) | epb.ts_low) / float(self._divisor))
                yield (ts, epb.pkt_data)

            else:
                #print('skipping block type', blk.type)
                pass


def test_shb():
    """test SHB with options"""
    buf = (
        b'\x0a\x0d\x0d\x0a\x58\x00\x00\x00\x4d\x3c\x2b\x1a\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff'
        b'\xff\xff\x04\x00\x31\x00\x54\x53\x68\x61\x72\x6b\x20\x31\x2e\x31\x30\x2e\x30\x72\x63\x32'
        b'\x20\x28\x53\x56\x4e\x20\x52\x65\x76\x20\x34\x39\x35\x32\x36\x20\x66\x72\x6f\x6d\x20\x2f'
        b'\x74\x72\x75\x6e\x6b\x2d\x31\x2e\x31\x30\x29\x00\x00\x00\x00\x00\x00\x00\x58\x00\x00\x00')

    opt_buf = b'\x04\x00\x31\x00TShark 1.10.0rc2 (SVN Rev 49526 from /trunk-1.10)\x00\x00\x00'

    # block unpacking
    shb = SectionHeaderBlockLE(buf)
    assert shb.type == PCAPNG_BT_SHB
    assert shb.bom == BYTE_ORDER_MAGIC
    assert shb.v_major == 1
    assert shb.v_minor == 0
    assert shb.sec_len == -1
    assert shb.data == ''

    # options unpacking
    assert len(shb.opts) == 2
    assert shb.opts[0].code == PCAPNG_OPT_SHB_USERAPPL
    assert shb.opts[0].val == 'TShark 1.10.0rc2 (SVN Rev 49526 from /trunk-1.10)'
    assert shb.opts[0].len == len(shb.opts[0].val)
    assert shb.opts[0].data == ''

    assert shb.opts[1].code == PCAPNG_OPT_ENDOFOPT
    assert shb.opts[1].len == 0

    # option packing
    assert str(shb.opts[0]) == opt_buf
    assert len(shb.opts[0]) == len(opt_buf)
    assert str(shb.opts[1]) == b'\x00\x00\x00\x00'

    # block packing
    assert str(shb) == buf
    assert len(shb) == len(buf)


def test_idb():
    """test IDB with options"""
    buf = (
        b'\x01\x00\x00\x00\x20\x00\x00\x00\x01\x00\x00\x00\xff\xff\x00\x00\x09\x00\x01\x00\x06\x00'
        b'\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00')

    # block unpacking
    idb = InterfaceDescriptionBlockLE(buf)
    assert idb.type == PCAPNG_BT_IDB
    assert idb.linktype == DLT_EN10MB
    assert idb.snaplen == 0xffff
    assert idb.data == ''

    # options unpacking
    assert len(idb.opts) == 2
    assert idb.opts[0].code == PCAPNG_OPT_IF_TSRESOL
    assert idb.opts[0].len == 1
    assert idb.opts[0].val == b'\x06'
    assert idb.opts[0].data == ''

    assert idb.opts[1].code == PCAPNG_OPT_ENDOFOPT
    assert idb.opts[1].len == 0

    # option packing
    assert str(idb.opts[0]) == b'\x09\x00\x01\x00\x06\x00\x00\x00'
    assert len(idb.opts[0]) == 8
    assert str(idb.opts[1]) == b'\x00\x00\x00\x00'

    # block packing
    assert str(idb) == buf
    assert len(idb) == len(buf)


def test_epb():
    """test EPB with a non-ascii comment option"""
    buf = (
        b'\x06\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x73\xe6\x04\x00\xbe\x37\xe2\x19\x4a\x00'
        b'\x00\x00\x4a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x45\x00'
        b'\x00\x3c\x5d\xb3\x40\x00\x40\x06\xdf\x06\x7f\x00\x00\x01\x7f\x00\x00\x01\x98\x34\x11\x4e'
        b'\x95\xcb\x2d\x3a\x00\x00\x00\x00\xa0\x02\xaa\xaa\xfe\x30\x00\x00\x02\x04\xff\xd7\x04\x02'
        b'\x08\x0a\x05\x8f\x70\x89\x00\x00\x00\x00\x01\x03\x03\x07\x00\x00\x01\x00\x0a\x00\xd0\xbf'
        b'\xd0\xb0\xd0\xba\xd0\xb5\xd1\x82\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00')

    # block unpacking
    epb = EnhancedPacketBlockLE(buf)
    assert epb.type == PCAPNG_BT_EPB
    assert epb.caplen == len(epb.pkt_data)
    assert epb.pkt_len == len(epb.pkt_data)
    assert epb.caplen == 74
    assert epb.ts_high == 321139
    assert epb.ts_low == 434255806
    assert epb.data == ''

    # options unpacking
    assert len(epb.opts) == 2
    assert epb.opts[0].code == PCAPNG_OPT_COMMENT
    assert epb.opts[0].val == u'\u043f\u0430\u043a\u0435\u0442'

    assert epb.opts[1].code == PCAPNG_OPT_ENDOFOPT
    assert epb.opts[1].len == 0

    # option packing
    assert str(epb.opts[0]) == b'\x01\x00\x0a\x00\xd0\xbf\xd0\xb0\xd0\xba\xd0\xb5\xd1\x82\x00\x00'
    assert len(epb.opts[0]) == 16
    assert str(epb.opts[1]) == b'\x00\x00\x00\x00'

    # block packing
    assert str(epb) == buf
    assert len(epb) == len(buf)


if __name__ == '__main__':
    # TODO: big endian unit tests; could not find any examples..

    test_shb()
    test_idb()
    test_epb()

    print 'Tests Successful...'
