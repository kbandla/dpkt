"""IEEE 802.3br MAC Merge Packet, also known as Frame Preemption Protocol"""
from __future__ import print_function
from __future__ import absolute_import

import struct
from zlib import crc32

from . import dpkt
from . import ethernet
from .compat import isstr
from .utils import swap32b

PREAMBLE_DEFAULT = b"UUUUUUU\xd5"
PREAMBLE_LONG = b"UUUUUUU"
PREAMBLE_SHORT = b"UUUUUU"

class FPP(dpkt.Packet):
    __hdr__ = (
        ('preamble', '8s', b'UUUUUUU\xd5'),
        # ( body, variable size )
        ('crc', 'I', 0) # cyclic redundancy check
    )
    def __init__(self, *args, **kwargs):
        super(FPP, self).__init__(*args, **kwargs)

        # if data was given in kwargs, try to unpack it
        if self.data:
            if isstr(self.data) or isinstance(self.data, bytes):
                self._unpack_data(self.data)

    def _unpack_data(self, buf):
        try:
            self.data = ethernet.Ethernet(buf)
            self.ethernet = self.data
        except (KeyError, dpkt.UnpackError):
            self.data = buf

    def unpack(self, buf):
        if buf[0:7] == PREAMBLE_LONG:
            self.preamble = buf[0:8]
        elif buf[0:6] == PREAMBLE_SHORT:
            self.preamble = buf[0:7]
        else:
            raise dpkt.UnpackError("Invalid mPacket preamble")
        preamble_len = len(self.preamble)
        self.data = buf[preamble_len:-4]
        self.crc = buf[-4:]
        self._unpack_data(self.data)
    
    def __len__(self):
        return len(self.preamble) + len(self.data) + 4

    def __bytes__(self):
        mdata = bytes(self.data)
        if self.crc == b'':
            self.crc = struct.pack("<I", crc32(mdata))
        return bytes(self.preamble) + bytes(self.data) + self.crc
