# $Id: gre.py 75 2010-08-03 14:42:19Z jon.oberheide $
# -*- coding: utf-8 -*-
"""Generic Routing Encapsulation."""

import struct
from . import dpkt
from .decorators import deprecated

GRE_CP = 0x8000  # Checksum Present
GRE_RP = 0x4000  # Routing Present
GRE_KP = 0x2000  # Key Present
GRE_SP = 0x1000  # Sequence Present
GRE_SS = 0x0800  # Strict Source Route
GRE_AP = 0x0080  # Acknowledgment Present

GRE_opt_fields = (
    (GRE_CP | GRE_RP, 'sum', 'H'), (GRE_CP | GRE_RP, 'off', 'H'),
    (GRE_KP, 'key', 'I'), (GRE_SP, 'seq', 'I'), (GRE_AP, 'ack', 'I')
)


class GRE(dpkt.Packet):
    """Generic Routing Encapsulation.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of GRE.
        TODO.
    """
    
    __hdr__ = (
        ('flags', 'H', 0),
        ('p', 'H', 0x0800),  # ETH_TYPE_IP
    )
    _protosw = {}
    sre = ()

    @property
    def v(self):
        return self.flags & 0x7

    @v.setter
    def v(self, v):
        self.flags = (self.flags & ~0x7) | (v & 0x7)

    @property
    def recur(self):
        return (self.flags >> 5) & 0x7

    @recur.setter
    def recur(self, v):
        self.flags = (self.flags & ~0xe0) | ((v & 0x7) << 5)

    # Deprecated methods, will be removed in the future
    # =================================================
    @deprecated('v')
    def get_v(self): return self.v

    @deprecated('v')
    def set_v(self, v): self.v = v

    @deprecated('recur')
    def get_recur(self): return self.recur

    @deprecated('recur')
    def set_recur(self, v): self.recur = v
    # =================================================

    class SRE(dpkt.Packet):
        __hdr__ = [
            ('family', 'H', 0),
            ('off', 'B', 0),
            ('len', 'B', 0)
        ]

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            self.data = self.data[:self.len]

    def opt_fields_fmts(self):
        if self.v == 0:
            fields, fmts = [], []
            opt_fields = GRE_opt_fields
        else:
            fields, fmts = ['len', 'callid'], ['H', 'H']
            opt_fields = GRE_opt_fields[-2:]
        for flags, field, fmt in opt_fields:
            if self.flags & flags:
                fields.append(field)
                fmts.append(fmt)
        return fields, fmts

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        fields, fmts = self.opt_fields_fmts()
        if fields:
            fmt = ''.join(fmts)
            fmtlen = struct.calcsize(fmt)
            vals = struct.unpack("!" + fmt, self.data[:fmtlen])
            self.data = self.data[fmtlen:]
            self.__dict__.update(dict(zip(fields, vals)))
        if self.flags & GRE_RP:
            l = []
            while True:
                sre = self.SRE(self.data)
                self.data = self.data[len(sre):]
                l.append(sre)
                if not sre.len:
                    break
            self.sre = l
        try:
            self.data = ethernet.Ethernet._typesw[self.p](self.data)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            # data alrady set
            pass

    def __len__(self):
        opt_fmtlen = struct.calcsize(''.join(self.opt_fields_fmts()[1]))
        return self.__hdr_len__ + opt_fmtlen + sum(map(len, self.sre)) + len(self.data)

    def __str__(self):
        fields, fmts = self.opt_fields_fmts()
        if fields:
            vals = []
            for f in fields:
                vals.append(getattr(self, f))
            opt_s = struct.pack(''.join(fmts), *vals)
        else:
            opt_s = ''
        return self.pack_hdr() + opt_s + ''.join(map(str, self.sre)) + str(self.data)

# XXX - auto-load GRE dispatch table from Ethernet dispatch table
from . import ethernet

GRE._protosw.update(ethernet.Ethernet._typesw)


def test_gre_v1():
    # Runs all the test associated with this class/file
    s = "3081880a0067178000068fb100083a76".decode('hex') + "A" * 103
    g = GRE(s)

    assert g.v == 1
    assert g.p == 0x880a
    assert g.seq == 430001
    assert g.ack == 539254
    assert g.callid == 6016
    assert g.len == 103
    assert g.data == "A" * 103

    s = "3001880a00b2001100083ab8".decode('hex') + "A" * 178
    g = GRE(s)

    assert g.v == 1
    assert g.p == 0x880a
    assert g.seq == 539320
    assert g.callid == 17
    assert g.len == 178
    assert g.data == "A" * 178


if __name__ == '__main__':
    test_gre_v1()
