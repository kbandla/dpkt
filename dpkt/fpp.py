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

buf_test = (
    b'UUUUUUU\xd5t\xd3\x89\x9d q\xdc\xd4j\xbc\x9a\xf9\x86\xdd`\x00\x00\x00\x00'
    b' \x06@\xfe\x80\x00\x00\x00\x00\x00\x00\xcd\xe3\xbb\xff\xe2r\xa2B\xfe\x80'
    b'\x00\x00\x00\x00\x00\x00\xeb\xa4\xbd|\x1d\xbc\x18x\x02w\xdd\xc6B\xc0B'
    b'\xd9\xde\xc6\xbe\xeb\x80\x10#9\xec\x1f\x00\x00\x01\x01\x08\n\x00:\xb3'
    b'\xe3\x189\xac\x93\xd2\x81\xa9%'
)
buf_short_preamble = (
    b'UUUUUU\xd5invalid\xd2\x81\xa9%'
)
buf_invalid_preamble = (
    b'UUUUU\xd5\xd2\x81\xa9%'
)

class TryExceptException:
    def __init__(self, exception_type, msg=''):
        self.exception_type = exception_type
        self.msg = msg

    def __call__(self, f, *args, **kwargs):
        def wrapper(*args, **kwargs):
            try:
                f()
            except self.exception_type as e:
                if self.msg:
                    assert str(e) == self.msg
            else:
                raise Exception("There should have been an Exception raised")
        return wrapper

@TryExceptException(Exception, msg='There should have been an Exception raised')
def test_TryExceptException():
    """Check that we can catch a function which does not throw an exception when it is supposed to"""
    @TryExceptException(NotImplementedError)
    def fun():
        pass

    try:
        fun()
    except Exception as e:
        raise e


def test_fpp():
    unpacked = FPP(buf_test)
    assert len(unpacked) == 98
    assert unpacked.preamble == b'UUUUUUU\xd5'
    assert unpacked.crc == b'\xd2\x81\xa9%'
    unpacked.crc = b''
    packed = bytes(unpacked)
    assert packed == buf_test

    # Test preamble variant and explicit data parameter
    unpacked = FPP(buf_short_preamble, data=b'invalid')
    assert unpacked.preamble == b'UUUUUU\xd5'
    assert unpacked.data == b'invalid'

@TryExceptException(dpkt.UnpackError, "Invalid mPacket preamble")
def test_invalid_preamble():
    FPP(buf_invalid_preamble)
