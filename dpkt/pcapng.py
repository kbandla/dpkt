"""
pcap Next Generation file format

"""
# Spec: http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html

# pylint: disable=no-member
# pylint: disable=attribute-defined-outside-init

import sys
from struct import pack as struct_pack, unpack as struct_unpack

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

# IDB Options
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
    return struct_unpack('<i', struct_pack('>i', num))[0]


def _aligned32b(num):
    """return the `num` aligned to the 32-bit boundary"""
    r = num % 4
    return num if not r else num + 4 - r


def _aligned32str(s):
    """return str `s` padded with zeroes to align to the 32-bit boundary"""
    return struct_pack('%ss' % _aligned32b(len(s)), s)


class PcapngOption(dpkt.Packet):
    """A single Option"""
    __hdr__ = (
        ('code', 'H', 0),
        ('len', 'H', 0),
        ('val', '0s', '')
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = ''

        # actual length of option value is aligned to 32 bits
        self.len = _aligned32b(self.len)
        self.val = buf[self.__hdr_len__:self.__hdr_len__ + self.len]


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
        oo = oo or self.__hdr_len__ - 4  # options offset
        ol = self.len - oo - 4  # length

        opts_buf = buf[oo:oo + ol]
        while opts_buf:
            opt = (PcapngOptionLE(opts_buf) if self.__byte_order__ == '<'
                   else PcapngOption(opts_buf))
            if opt.code == PCAPNG_OPT_ENDOFOPT:
                break
            self.opts.append(opt)
            opts_buf = opts_buf[opt.__hdr_len__ + opt.len:]

        # duplicate total length field
        self._len = struct_unpack(
            self.__byte_order__ + 'I', buf[oo + ol:oo + ol + 4])[0]
        if self._len != self.len:
            raise dpkt.UnpackError('length fields do not match')
        self.data = buf[oo + ol + 4:]


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
        opts_offset = po + _aligned32b(self.caplen)
        self._do_unpack_options(buf, opts_offset)


class EnhancedPacketBlockLE(EnhancedPacketBlock):
    __byte_order__ = '<'


class Writer(object):
    """Simple pcapng dumpfile writer."""
    # XXX - TODO
    pass


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
                opt_val = struct_unpack('<I' if self.__le else '>I', opt.val)[0]
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

            if blk.type == PCAPNG_BT_SHB:
                if blk.tail == BYTE_ORDER_MAGIC:
                    self.__le = False
                    buf += self.__f.read(blk.len - blk.__hdr_len__)
                    shb = SectionHeaderBlock(buf)
                elif blk.tail == BYTE_ORDER_MAGIC_LE:
                    self.__le = True
                    buf += self.__f.read(_swap32b(blk.len) - blk.__hdr_len__)
                    shb = SectionHeaderBlockLE(buf)
                else:
                    raise ValueError('unknown endianness')

                if shb.v_major != PCAPNG_VERSION_MAJOR:
                    raise ValueError('unknown SHB version {}.{}'.format(shb.v_major, shb.v_minor,))

            elif blk.type == PCAPNG_BT_EPB:
                buf += self.__f.read(blk.len - blk.__hdr_len__)
                epb = EnhancedPacketBlockLE(buf) if self.__le else EnhancedPacketBlock(buf)

                # calculate the timestamp
                ts = self._tsoffset + (((epb.ts_high << 32) | epb.ts_low) / float(self._divisor))
                yield (ts, epb.pkt_data)


if __name__ == '__main__':
    # XXX - TODO
    print 'Tests Successful...'
