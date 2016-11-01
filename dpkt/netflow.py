# $Id: netflow.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Cisco Netflow."""

import itertools
import struct
from . import dpkt


class NetflowBase(dpkt.Packet):
    """Base class for Cisco Netflow packets.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of NetflowBase.
        TODO.
    """

    __hdr__ = (
        ('version', 'H', 1),
        ('count', 'H', 0),
        ('sys_uptime', 'I', 0),
        ('unix_sec', 'I', 0),
        ('unix_nsec', 'I', 0)
    )

    def __len__(self):
        return self.__hdr_len__ + (len(self.data[0]) * self.count)

    def __str__(self):
        # for now, don't try to enforce any size limits
        self.count = len(self.data)
        return self.pack_hdr() + ''.join(map(str, self.data))

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        buf = self.data
        l = []
        while buf:
            flow = self.NetflowRecord(buf)
            l.append(flow)
            buf = buf[len(flow):]
        self.data = l

    class NetflowRecordBase(dpkt.Packet):
        """Base class for netflow v1-v7 netflow records.

        TODO: Longer class information....

        Attributes:
            __hdr__: Header fields of NetflowRecordBase.
            TODO.
        """

        # performance optimizations
        def __len__(self):
            # don't bother with data
            return self.__hdr_len__

        def __str__(self):
            # don't bother with data
            return self.pack_hdr()

        def unpack(self, buf):
            # don't bother with data
            for k, v in itertools.izip(self.__hdr_fields__,
                                       struct.unpack(self.__hdr_fmt__, buf[:self.__hdr_len__])):
                setattr(self, k, v)
            self.data = ""


class Netflow1(NetflowBase):
    """Netflow Version 1.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of Netflow Version 1.
        TODO.
    """

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v1 flow record.

        TODO: Longer class information....
    
        Attributes:
            __hdr__: Header fields of Netflow Version 1 flow record.
            TODO.
        """
        
        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('pad1', 'H', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('pad2', 'B', 0),
            ('pad3', 'H', 0),
            ('reserved', 'I', 0)
        )


# FYI, versions 2-4 don't appear to have ever seen the light of day.

class Netflow5(NetflowBase):
    """Netflow Version 5.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of Netflow Version 5.
        TODO.
    """
    
    __hdr__ = NetflowBase.__hdr__ + (
        ('flow_sequence', 'I', 0),
        ('engine_type', 'B', 0),
        ('engine_id', 'B', 0),
        ('reserved', 'H', 0),
    )

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v5 flow record.

        TODO: Longer class information....
    
        Attributes:
            __hdr__: Header fields of Netflow Version 5 flow record.
            TODO.
        """
        
        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('pad1', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('src_as', 'H', 0),
            ('dst_as', 'H', 0),
            ('src_mask', 'B', 0),
            ('dst_mask', 'B', 0),
            ('pad2', 'H', 0),
        )


class Netflow6(NetflowBase):    
    """Netflow Version 6.

    XXX - unsupported by Cisco, but may be found in the field.
    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of Netflow Version 6.
        TODO.
    """
    
    __hdr__ = Netflow5.__hdr__

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v6 flow record.

        TODO: Longer class information....
    
        Attributes:
            __hdr__: Header fields of Netflow Version 6 flow record.
            TODO.
        """
        
        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('pad1', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('src_as', 'H', 0),
            ('dst_as', 'H', 0),
            ('src_mask', 'B', 0),
            ('dst_mask', 'B', 0),
            ('in_encaps', 'B', 0),
            ('out_encaps', 'B', 0),
            ('peer_nexthop', 'I', 0),
        )


class Netflow7(NetflowBase):
    """Netflow Version 7.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of Netflow Version 7.
        TODO.
    """
    
    __hdr__ = NetflowBase.__hdr__ + (
        ('flow_sequence', 'I', 0),
        ('reserved', 'I', 0),
    )

    class NetflowRecord(NetflowBase.NetflowRecordBase):
        """Netflow v6 flow record.

        TODO: Longer class information....
    
        Attributes:
            __hdr__: Header fields of Netflow Version 6 flow record.
            TODO.
        """
        
        __hdr__ = (
            ('src_addr', 'I', 0),
            ('dst_addr', 'I', 0),
            ('next_hop', 'I', 0),
            ('input_iface', 'H', 0),
            ('output_iface', 'H', 0),
            ('pkts_sent', 'I', 0),
            ('bytes_sent', 'I', 0),
            ('start_time', 'I', 0),
            ('end_time', 'I', 0),
            ('src_port', 'H', 0),
            ('dst_port', 'H', 0),
            ('flags', 'B', 0),
            ('tcp_flags', 'B', 0),
            ('ip_proto', 'B', 0),
            ('tos', 'B', 0),
            ('src_as', 'H', 0),
            ('dst_as', 'H', 0),
            ('src_mask', 'B', 0),
            ('dst_mask', 'B', 0),
            ('pad2', 'H', 0),
            ('router_sc', 'I', 0),
        )

# No support for v8 or v9 yet.

__sample_v1 = "\x00\x01\x00\x18gza<B\x00\xfc\x1c$\x93\x08p\xac\x01 W\xc0\xa8c\xf7\n\x00\x02\x01\x00\x03\x00\n\x00\x00\x00\x01\x00\x00\x02(gz7,gz7,\\\x1b\x00P\xac\x01\x11,\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01\x18S\xac\x18\xd9\xaa\xc0\xa82\x02\x00\x03\x00\x19\x00\x00\x00\x01\x00\x00\x05\xdcgz7|gz7|\xd8\xe3\x00P\xac\x01\x06,\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01\x14\x18\xac\x18\x8d\xcd\xc0\xa82f\x00\x03\x00\x07\x00\x00\x00\x01\x00\x00\x05\xdcgz7\x90gz7\x90\x8a\x81\x17o\xac\x01\x066\x10\x00\x00\x00\x00\x04\x00\x03\xac\x0f'$\xac\x01\xe5\x1d\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x02(gz:8gz:8\xa3Q\x126\xac)\x06\xfd\x18\x00\x00\x00\x00\x04\x00\x1b\xac\x01\x16E\xac#\x17\x8e\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x02(gz:Lgz:L\xc9\xff\x00P\xac\x1f\x06\x86\x02\x00\x00\x00\x00\x03\x00\x1b\xac\r\t\xff\xac\x01\x99\x95\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:Xgz:X\xee9\x00\x17\xac\x01\x06\xde\x10\x00\x00\x00\x00\x04\x00\x03\xac\x0eJ\xd8\xac\x01\xae/\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:hgz:h\xb3n\x00\x15\xac\x01\x06\x81\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01#8\xac\x01\xd9*\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:tgz:t\x00\x00\x83P\xac!\x01\xab\x10\x00\x00\x00\x00\x03\x00\x1b\xac\n`7\xac*\x93J\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:tgz:t\x00\x00\x00\x00\xac\x012\xa9\x10\x00\x00\x00\x00\x04\x00\x07\xac\nG\x1f\xac\x01\xfdJ\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x00(gz:\x88gz:\x88!\x99i\x87\xac\x1e\x06~\x02\x00\x00\x00\x00\x03\x00\x1b\xac\x01(\xc9\xac\x01B\xc4\xc0\xa82\x02\x00\x03\x00\x19\x00\x00\x00\x01\x00\x00\x00(gz:\x88gz:\x88}6\x00P\xac\x01\x06\xfe\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x0b\x08\xe8\xac\x01F\xe2\xc0\xa82\x02\x00\x04\x00\x19\x00\x00\x00\x01\x00\x00\x05\xdcgz:\x9cgz:\x9c`ii\x87\xac\x01\x06;\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01\x1d$\xac<\xf0\xc3\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:\x9cgz:\x9cF2\x00\x14\xac\x01\x06s\x18\x00\x00\x00\x00\x04\x00\x03\xac\x0b\x11Q\xac\x01\xde\x06\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:\xb0gz:\xb0\xef#\x1a+\xac)\x06\xe9\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x0cR\xd9\xac\x01o\xe8\xc0\xa82\x02\x00\x04\x00\x19\x00\x00\x00\x01\x00\x00\x05\xdcgz:\xc4gz:\xc4\x13n\x00n\xac\x19\x06\xa8\x10\x00\x00\x00\x00\x03\x00\x19\xac\x01=\xdd\xac\x01}\xee\xc0\xa82f\x00\x03\x00\x07\x00\x00\x00\x01\x00\x00\x00(gz:\xc4gz:\xc4\x00\x00\xdc\xbb\xac\x01\x01\xd3\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x0f(\xd1\xac\x01\xcc\xa5\xc0\xa82\x06\x00\x04\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz:\xd8gz:\xd8\xc5s\x17o\xac\x19\x06#\x18\x00\x00\x00\x00\x03\x00\x07\xac\n\x85[\xc0\xa8cn\n\x00\x02\x01\x00\x04\x00\n\x00\x00\x00\x01\x00\x00\x05\xdcgz:\xe4gz:\xe4\xbfl\x00P\xac\x01\x06\xcf\x10\x00\x00\x00\x00\x04\x00\x07\xac\x010\x1f\xac\x18!E\xc0\xa82f\x00\x03\x00\x07\x00\x00\x00\x01\x00\x00\x05\xdcgz;\x00gz;\x00\x11\x95\x04\xbe\xc0\xa8\x06\xea\x10\x00\x00\x00\x00\x03\x00\n\xac\x010\xb6\xac\x1e\xf4\xaa\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz;4gz;4\x88d\x00\x17\xac\x01\x06\x1f\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01#_\xac\x1e\xb0\t\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x05\xdcgz;Hgz;H\x81S\x00P\xac \x06N\x10\x00\x00\x00\x00\x03\x00\x1b\xac\x01\x04\xd9\xac\x01\x94c\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x02(gz;\\gz;\\U\x10\x00P\xac\x01\x06P\x18\x00\x00\x00\x00\x04\x00\x1b\xac\x01<\xae\xac*\xac!\xc0\xa82\x06\x00\x03\x00\x1b\x00\x00\x00\x01\x00\x00\x00\xfagz;\x84gz;\x84\x0c\xe7\x00P\xac\x01\x11\xfd\x10\x00\x00\x00\x00\x04\x00\x1b\xac\x01\x1f\x1f\xac\x17\xedi\xc0\xa82\x02\x00\x03\x00\x19\x00\x00\x00\x01\x00\x00\x05\xdcgz;\x98gz;\x98\xba\x17\x00\x16\xac\x01\x06|\x10\x00\x00\x00\x00\x03\x00\x07"
__sample_v5 = '\x00\x05\x00\x1d\xb5\xfa\xc9\xd0:\x0bAB&Vw\xde\x9bsv1\x00\x01\x00\x00\xac\n\x86\xa6\xac\x01\xaa\xf7\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x02(\xb5\xfa\x81\x14\xb5\xfa\x81\x1452\x00P\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x91D\xac\x14C\xe4\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x00(\xb5\xfa\x9b\xbd\xb5\xfa\x9b\xbd\x00P\x85\xd7\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x17\xe2\xd7\xac\x01\x8cV\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfao\xb8\xb5\xfao\xb8v\xe8\x17o\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x0e\xf2\xe5\xac\x01\x91\xb2\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x00\xfa\xb5\xfa\x81\xee\xb5\xfa\x81\xee\xd0\xeb\x00\x15\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\nCj\xac)\xa7\t\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x02(\xb5\xfa\x85\x92\xb5\xfa\x85\x92\x8c\xb0\x005\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x96=\xac\x15\x1a\xa8\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x86\xe0\xb5\xfa\x86\xe0\xb4\xe7\x00\xc2\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01V\xd1\xac\x01\x86\x15\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa}:\xb5\xfa}:[Q\x00P\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac2\xf1\xb1\xac)\x19\xca\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x83\xc3\xb5\xfa\x83\xc3\x16,\x00\x15\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x0cA4\xac\x01\x9az\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x8d\xa7\xb5\xfa\x8d\xa7\x173\x00\x15\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x1e\xd2\x84\xac)\xd8\xd2\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x8e\x97\xb5\xfa\x8e\x977*\x17o\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x85J\xac \x11\xfc\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x02(\xb5\xfa\x884\xb5\xfa\x884\xf5\xdd\x00\x8f\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x04\x80\xac<[n\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x9dr\xb5\xfa\x9drs$\x00\x16\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\xb9J\xac"\xc9\xd7\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x00(\xb5\xfa\x90r\xb5\xfa\x90r\x0f\x8d\x00\xc2\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac*\xa3\x10\xac\x01\xb4\x19\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x00(\xb5\xfa\x92\x03\xb5\xfa\x92\x03pf\x00\x15\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\xabo\xac\x1e\x7fi\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x93\x7f\xb5\xfa\x93\x7f\x00P\x0b\x98\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x0c\n\xea\xac\x01\xa1\x15\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfay\xcf\xb5\xfay\xcf[3\x17\xe0\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\xbb\xb3\xac)u\x8c\n\x00\x02\x01\x00i\x00\xdb\x00\x00\x00\x01\x00\x00\x00\xfa\xb5\xfa\x943\xb5\xfa\x943\x00P\x1e\xca\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x0fJ`\xac\x01\xab\x94\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x02(\xb5\xfa\x87[\xb5\xfa\x87[\x9a\xd6/\xab\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac*\x0f\x93\xac\x01\xb8\xa3\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x00(\xb5\xfa\x89\xbb\xb5\xfa\x89\xbbn\xe1\x00P\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x93\xa1\xac\x16\x80\x0c\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x00(\xb5\xfa\x87&\xb5\xfa\x87&\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\x83Z\xac\x1fR\xcd\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x90\r\xb5\xfa\x90\r\xf7*\x00\x8a\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x0c\xe0\xad\xac\x01\xa8V\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x9c\xf6\xb5\xfa\x9c\xf6\xe5|\x1a+\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x1e\xccT\xac<x&\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x80\xea\xb5\xfa\x80\xea\x00\x00\x00\x00\x00\x00/\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\xbb\x18\xac\x01|z\xc0\xa82\x16\x00i\x02q\x00\x00\x00\x01\x00\x00\x00\xfa\xb5\xfa\x88p\xb5\xfa\x88p\x00P\x0b}\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x17\x0er\xac\x01\x8f\xdd\xc0\xa822\x02q\x00i\x00\x00\x00\x01\x00\x00\x02(\xb5\xfa\x89\xf7\xb5\xfa\x89\xf7\r\xf7\x00\x8a\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\n\xbb\x04\xac<\xb0\x15\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa\x90\xa9\xb5\xfa\x90\xa9\x9c\xd0\x00\x8f\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\nz?\xac)\x03\xc8\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfaue\xb5\xfaue\xee\xa6\x00P\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac\x01\xb5\x05\xc0\xa8c\x9f\n\x00\x02\x01\x00i\x00\xdb\x00\x00\x00\x01\x00\x00\x05\xdc\xb5\xfa{\xc7\xb5\xfa{\xc7\x00P\x86\xa9\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xac2\xa5\x1b\xac)0\xbf\n\x00\x02\x01\x02q\x00\xdb\x00\x00\x00\x01\x00\x00\x00\xfa\xb5\xfa\x9bZ\xb5\xfa\x9bZC\xf9\x17\xe0\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_net_flow_v1_pack(): pass


def test_net_flow_v1_unpack():
    nf = Netflow1(__sample_v1)
    assert len(nf.data) == 24
    # print repr(nfv1)


def test_net_flow_v5_pack(): pass


def test_net_flow_v5_unpack():
    nf = Netflow5(__sample_v5)
    assert len(nf.data) == 29
    # print repr(nfv5)


if __name__ == '__main__':
    test_net_flow_v1_pack()
    test_net_flow_v1_unpack()
    test_net_flow_v5_pack()
    test_net_flow_v5_unpack()
    print('Tests Successful...')
