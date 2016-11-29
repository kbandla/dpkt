# $Id: sctp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Stream Control Transmission Protocol."""

import dpkt
import crc32c
import struct

# Stream Control Transmission Protocol
# http://tools.ietf.org/html/rfc4960

# Chunk Types
CHUNK_TYPE_DATA = 0
CHUNK_TYPE_INIT = 1
CHUNK_TYPE_INIT_ACK = 2
CHUNK_TYPE_SACK = 3
CHUNK_TYPE_HEARTBEAT = 4
CHUNK_TYPE_HEARTBEAT_ACK = 5
CHUNK_TYPE_ABORT = 6
CHUNK_TYPE_SHUTDOWN = 7
CHUNK_TYPE_SHUTDOWN_ACK = 8
CHUNK_TYPE_ERROR = 9
CHUNK_TYPE_COOKIE_ECHO = 10
CHUNK_TYPE_COOKIE_ACK = 11
CHUNK_TYPE_ECNE = 12
CHUNK_TYPE_CWR = 13
CHUNK_TYPE_SHUTDOWN_COMPLETE = 14

# Chunk Error Cause Codes
CHUNK_ERR_INVALID_ID = 1
CHUNK_ERR_MISS_MAND_PARAM = 2
CHUNK_ERR_STALE_COOKIE = 3
CHUNK_ERR_OUT_OF_RESOURCE = 4
CHUNK_ERR_UNRESOLV_ADDR = 5
CHUNK_ERR_UNRECOG_TYPE = 6
CHUNK_ERR_INVALID_MAND_PARAM = 7
CHUNK_ERR_UNRECOG_PARAM = 8
CHUNK_ERR_NO_USER_DATA = 9
CHUNK_ERR_COOKIE_WHILE_SHUT = 10
CHUNK_ERR_RESTART_ASSOC = 11
CHUNK_ERR_USER_INIT_ABORT = 12
CHUNK_ERR_PROTO_VIOLATION = 13


class SCTP(dpkt.Packet):
    """Stream Control Transmission Protocol.
    This Class handles only common header in SCTP.
    Upper layers should be handled by Chunk* Classes below.

    Attributes:
        __hdr__: Common Header fields of SCTP.
    """
    __hdr__ = (
        ('sport', 'H', 0),
        ('dport', 'H', 0),
        ('vtag', 'I', 0),
        ('sum', 'I', 0)
    )

    def get_chunktype(self, buf):
        dpkt.Packet.unpack(self, buf)
        return struct.unpack('B', self.data[0:1])[0]

    def unpack(self, buf):
        self.ctype = self.get_chunktype(buf)
        dpkt.Packet.unpack(self, buf)
        l = []
        while self.data:
            chunk = CHUNK_TYPES_DICT.get(self.ctype, Chunk)(self.data)
            l.append(chunk)
            self.data = self.data[len(chunk):]
        self.data = self.chunks = l

    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.data))

    def __str__(self):
        l = [str(x) for x in self.data]
        if self.sum == 0:
            s = crc32c.add(0xffffffffL, self.pack_hdr())
            for x in l:
                s = crc32c.add(s, x)
            self.sum = crc32c.done(s)
        return self.pack_hdr() + ''.join(l)


class Chunk(dpkt.Packet):
    """SCTP General Chunk.
    This Class is used as the SuperClass of all types of chunk and
    as the Class of some chunks whose type is unknown or not implemented.
    This only handles the three common part of Generic Chunk Headers;
     - Chunk type
     - Chunk flags
     - Chunk length

    Attributes:
        __hdr__: Generic Chunk Header fields common in all types.
    """
    __hdr__ = (
        ('type', 'B', CHUNK_TYPE_INIT),
        ('flags', 'B', 0),
        ('len', 'H', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = self.data[:self.len - self.__hdr_len__]


class ChunkData(Chunk):
    """SCTP DATA Chunk.
    This Class is to handle the 'DATA' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Transmission sequence number
     - Stream identifier
     - Stream sequence number
     - Payload protocol identifier

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr_spec__ = (
        ('tsn', 'I', 0),
        ('stream_id', 'H', 0),
        ('stream_seq', 'H', 0),
        ('proto_id', 'I', 0)
    )
    __hdr__ = Chunk.__hdr__ + __hdr_spec__

    @property
    def unordered_flag(self):
        return (self.flags >> 2) & 0x1

    @unordered_flag.setter
    def unordered_flag(self, u):
        self.flags = (flags & ~0x4) | ((u & 0x1) << 2)

    @property
    def beginning_flag(self):
        return (self.flags >> 1) & 0x1

    @beginning_flag.setter
    def beginning_flag(self, b):
        self.flags = (flags & ~0x2) | ((b & 0x1) << 1)

    @property
    def ending_flag(self):
        return self.flags & 0x1

    @ending_flag.setter
    def ending_flag(self, e):
        self.flags = (flags & ~0x1) | (e & 0x1)

    def unpack(self, buf):
        super(ChunkData, self).unpack(buf)
        self.data = self.data[:self.len - self.__hdr_len__]


class ChunkInit(Chunk):
    """SCTP INIT Chunk.
    This Class is to handle the 'INIT' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Initiate tag
     - Advertised receiver window credit
     - Number of outbound stream
     - Number of inbound stream
     - Initial TSN

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr_spec__ = (
        ('init_tag', 'I', 0),
        ('a_rwnd', 'I', 0),
        ('num_os', 'H', 0),
        ('num_is', 'H', 0),
        ('init_tsn', 'I', 0)
    )
    __hdr__ = Chunk.__hdr__ + __hdr_spec__

    def unpack(self, buf):
        super(ChunkInit, self).unpack(buf)
        self.data = self.optionals = self.data[:self.len - self.__hdr_len__]


class ChunkInitAck(Chunk):
    """SCTP INIT_ACK Chunk.
    This Class is to handle the 'INIT_ACK' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Initiate tag
     - Advertised receiver window credit
     - Number of outbound stream
     - Number of inbound stream
     - Initial TSN
     - State cookie parameter

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr_spec__ = (
        ('init_tag', 'I', 0),
        ('a_rwnd', 'I', 0),
        ('num_os', 'H', 0),
        ('num_is', 'H', 0),
        ('init_tsn', 'I', 0),
        ('cookie_param', 'H', 0),
        ('param_len', 'H', 0),
    )
    __hdr__ = Chunk.__hdr__ + __hdr_spec__

    def unpack(self, buf):
        super(ChunkInitAck, self).unpack(buf)
        self.state_cookie = self.data[:self.param_len]
        self.data = self.optionals = self.data[self.param_len:self.len]


class ChunkSack(Chunk):
    """SCTP SACK Chunk.
    This Class is to handle the 'SACK' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Cumulatice TSN ACK
     - Advertised receiver window credit
     - Number of gap acknowledgement blocks
     - Number of duplicated TSNs

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr_spec__ = (
        ('cum_tsn_ack', 'I', 0),
        ('a_rwnd', 'I', 0),
        ('num_gap_ack', 'H', 0),
        ('num_dup_tsn', 'H', 0)
    )
    __hdr__ = Chunk.__hdr__ + __hdr_spec__

    def unpack(self, buf):
        super(ChunkSack, self).unpack(buf)
        self.data = self.data[:self.len - self.__hdr_len__]


class ChunkHeartbeat(Chunk):
    """SCTP HEARTBEAT Chunk.
    This Class is to handle the 'HEARTBEAT' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Heartbeat info parameter
        - Heartbeat info parameter type
        - Heartbeat info parameter length
        - Heartbeat info parameter information

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr_spec__ = (
        ('hb_type', 'H', 0),
        ('hb_len', 'H', 0),
    )
    __hdr__ = Chunk.__hdr__ + __hdr_spec__

    def unpack(self, buf):
        super(ChunkHeartbeat, self).unpack(buf)
        self.data = self.hb_info = self.data[:self.len - self.__hdr_len__]


class ChunkHeartbeatAck(Chunk):
    """SCTP HEARTBEAT_ACK Chunk.
    This Class is to handle the 'HEARTBEAT_ACK' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Heartbeat info parameter
        - Heartbeat info parameter type
        - Heartbeat info parameter length
        - Heartbeat info parameter information

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr_spec__ = (
        ('hb_type', 'H', 0),
        ('hb_len', 'H', 0),
    )
    __hdr__ = Chunk.__hdr__ + __hdr_spec__

    def unpack(self, buf):
        super(ChunkHeartbeatAck, self).unpack(buf)
        self.data = self.hb_info = self.data[:self.len - self.__hdr_len__]


class ChunkAbort(Chunk):
    """SCTP ABORT Chunk.
    This Class is to handle the 'ABORT' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr__ = Chunk.__hdr__

    def unpack(self, buf):
        super(ChunkAbort, self).unpack(buf)
        self.data = self.data[:self.len - self.__hdr_len__]


class ChunkShutdown(Chunk):
    """SCTP SHUTDOWN Chunk.
    This Class is to handle the 'SHUTDOWN' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Cumulatice TSN ACK

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr_spec__ = (
        ('cum_tsn_ack', 'I', 0),
    )
    __hdr__ = Chunk.__hdr__ + __hdr_spec__

    def unpack(self, buf):
        super(ChunkShutdown, self).unpack(buf)
        self.data = self.data[:self.len - self.__hdr_len__]


class ChunkShutdownAck(Chunk):
    """SCTP SHUTDOWN_ACK Chunk.
    This Class is to handle the 'SHUTDOWN_ACK' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr__ = Chunk.__hdr__

    def unpack(self, buf):
        super(ChunkShutdownAck, self).unpack(buf)
        self.data = self.data[:self.len - self.__hdr_len__]


class ChunkError(Chunk):
    """SCTP ERROR Chunk.
    *** IMPLEMENTATION NOT COMPLETE ***
    This Class is to handle the 'ERROR' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Cause code
     - Cause length
     - Cause-specific information
        - Invalid Stream Identifier
        - Missing Mandatory Parameter
        - Stale Cookie Error
        - Out of Resource
        - Unresolvable Address
        - Unrecognized Chunk Type
        - Invalid Mandatory Parameter
        - Unrecognized Parameters
        - No User Data
        - Cookie Received While Shutting Down
        - Restart of an Association with New Addresses
        - User Initiated Abort
        - Protocol Violation

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr_spec__ = (
        ('cause_code', 'H', 0),
        ('cause_len', 'H', 0),
    )
    __hdr__ = Chunk.__hdr__ + __hdr_spec__


    def error_spec(self, data):
        if self.cause_code == CHUNK_ERR_INVALID_ID:
            self.invalid_id = data[:self.len - self.__hdr_len__ -6]
        elif self.cause_code == CHUNK_ERR_MISS_MAND_PARAM:
            self.num_miss_param = data[:4]
            self.miss_param_types = [data[4*i:4*i+2] for i in xrange(1, self.num_miss_param + 1)]
        elif self.cause_code == CHUNK_ERR_STALE_COOKIE:
            self.measure_stale = data[:self.len - self.__hdr_len__]
        elif self.cause_code == CHUNK_ERR_OUT_OF_RESOURCE:
            # This should be None as no value would be inserted here.
            self._out_of_resource = data[:self.len - self.__hdr_len__]
        elif self.cause_code == CHUNK_ERR_UNRESOLV_ADDR:
            self.unresolv_addr = data[:self.len - self.__hdr_len__]
        elif self.cause_code == CHUNK_ERR_UNRECOG_TYPE:
            self.unrecog_chunk = data[:self.len - self.__hdr_len__]
        elif self.cause_code == CHUNK_ERR_INVALID_MAND_PARAM:
            # This should be None as no value would be inserted here.
            self._invalid_param = data[:self.len - self.__hdr_len__]
        elif self.cause_code == CHUNK_ERR_UNRECOG_PARAM:
            self.unrecog_param = data[:self.len - self.__hdr_len__]
        elif self.cause_code == CHUNK_ERR_NO_USER_DATA:
            self.no_data_tsn = data[:self.len - self.__hdr_len__]
        elif self.cause_code == CHUNK_ERR_COOKIE_WHILE_SHUT:
            # This should be None as no value would be inserted here.
            self._cookie_while_shut = data[:self.len - self.__hdr_len__]
        elif self.cause_code == CHUNK_ERR_RESTART_ASSOC:
            self.new_addr_tlvs = data[:self.len - self.__hdr_len__]
        elif self.cause_code == CHUNK_ERR_USER_INIT_ABORT:
            self.abort_reason = data[:self.len - self.__hdr_len__]
        elif self.cause_code == CHUNK_ERR_PROTO_VIOLATION:
            self.additional_info = data[:self.len - self.__hdr_len__]
        else:
            raise NotImplementedError

    def unpack(self, buf):
        super(ChunkError, self).unpack(buf)
        self.data = self.data[:self.len - self.__hdr_len__]
        self.error_spec(self.data)


class ChunkCookieEcho(Chunk):
    """SCTP COOKIE_ECHO Chunk.
    This Class is to handle the 'COOKIE_ECHO' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Cookie

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr__ = Chunk.__hdr__

    def unpack(self, buf):
        super(ChunkCookieEcho, self).unpack(buf)
        self.data = self.cookie = self.data[:self.len - self.__hdr_len__]


class ChunkCookieAck(Chunk):
    """SCTP COOKIE_ACK Chunk.
    This Class is to handle the 'COOKIE_ACK' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr__ = Chunk.__hdr__

    def unpack(self, buf):
        super(ChunkCookieAck, self).unpack(buf)
        self.data = self.data[:self.len - self.__hdr_len__]


class ChunkECNE(Chunk):
    """SCTP ECNE(ECN-Echo) Chunk.
    This Class is to handle the 'ECNE' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Lowest TSN number

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr_spec__ = (
        ('lowest_tsn', 'I', 0),
    )
    __hdr__ = Chunk.__hdr__ + __hdr_spec__

    def unpack(self, buf):
        super(ChunkECNE, self).unpack(buf)
        self.data = self.data[:self.len - self.__hdr_len__]


class ChunkCWR(Chunk):
    """SCTP CWR(Congestion Window Reduced) Chunk.
    This Class is to handle the 'CWR' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length
     - Lowest TSN number

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr_spec__ = (
        ('lowest_tsn', 'I', 0),
    )
    __hdr__ = Chunk.__hdr__ + __hdr_spec__

    def unpack(self, buf):
        super(ChunkCWR, self).unpack(buf)
        self.data = self.data[:self.len - self.__hdr_len__]


class ChunkShutdownComplete(Chunk):
    """SCTP SHUTDOWN_COMPLETE Chunk.
    This Class is to handle the 'SHUTDOWN_COMPLETE' type of SCTP Chunk.
    Supported fields are;
     - Chunk type
     - Chunk flags
     - Chunk length

    Attributes:
        __hdr__: Generic Chunk Header fields of SCTP.
        __hdr_spec__: Type-specific Chunk Header fields of SCTP.
    """
    __hdr__ = Chunk.__hdr__

    def unpack(self, buf):
        super(ChunkShutdownComplete, self).unpack(buf)
        self.data = self.data[:self.len - self.__hdr_len__]


# Dictionary to call appropriate subclass from superclass.
CHUNK_TYPES_DICT = {
    CHUNK_TYPE_DATA: ChunkData,
    CHUNK_TYPE_INIT: ChunkInit,
    CHUNK_TYPE_INIT_ACK: ChunkInitAck,
    CHUNK_TYPE_SACK: ChunkSack,
    CHUNK_TYPE_HEARTBEAT: ChunkHeartbeat,
    CHUNK_TYPE_HEARTBEAT_ACK: ChunkHeartbeatAck,
    CHUNK_TYPE_ABORT: ChunkAbort,
    CHUNK_TYPE_SHUTDOWN: ChunkShutdown,
    CHUNK_TYPE_SHUTDOWN_ACK: ChunkShutdownAck,
    CHUNK_TYPE_ERROR: ChunkError,
    CHUNK_TYPE_COOKIE_ECHO: ChunkCookieEcho,
    CHUNK_TYPE_COOKIE_ACK: ChunkCookieAck,
    CHUNK_TYPE_ECNE: ChunkECNE,
    CHUNK_TYPE_CWR: ChunkCWR,
    CHUNK_TYPE_SHUTDOWN_COMPLETE: ChunkShutdownComplete
}


test_bytearr = {
    'DATA': b'\x0f\xe4\x0f\x1c\xceU\xce\x8f\xf5@\x8bv\x00\x03\x01\xcc\xbb{\x0f\x9c\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef',
    'INIT': b'\x0f\xe4\x0f\x1c\x00\x00\x00\x00\x9fx\xa7\x04\x01\x00\x00\x14\xbb{\x0f\x9c\x00\x00\xfa\x00\x00\n\x00\n\xbb{\x0f\x9c',
    'INIT_ACK': b'\x0f\x1c\x0f\xe4\xbb{\x0f\x9c\xf7\x06\xbds\x02\x00\x01\xc4\xceU\xce\x8f\x00\x00\xfa'
                 '\x00\x00\n\x00\n\xceU\xce\x8f\x00\x07\x01\xb0\xbb{\x0f\x9c\x00\x00\xfa\x00\x00\n\x00'
                 '\x00\xbb{\x0f\x9c\x00\x00\x00\x00\x0f\xe4\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x01'
                 '\x01\x01\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xceU\xce\x8f\x00\x00\xfa\x00\x00\n'
                 '\x00\x00\xceU\xce\x8f\x0f\x1c\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x01\x01\x01\x14'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                 '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00O9\xd8XO:\xc2\xb8',
    'SACK': b'\x0f\x1c\x0f\xe4\xbb{\x0f\x9cy\x94\x91)\x03\x00\x00\x10\xbb{\x0f\x9c\x00\x00\xfa\x00\x00\x00\x00\x00',
    'HEARTBEAT': b'\x0bY\x0bY\x00\x00\x0ePS\xc3\x05_\x04\x00\x00\x18\x00\x01\x00\x14@\xe4K\x92\n\x1c\x06,\x1bf\xaf~\xde\xad\x00\x00',
    'HEARTBEAT_ACK': b'\x0bY\x0bY\rS\xe6\xfe\x8c\x8e\x07F\x05\x00\x00\x18\x00\x01\x00\x14@\xe4K\x92\n\x1c\x06,\x1bf\xaf~\xbe\xef\x00\x00',
    'ABORT': b'0909\xbee\xa7\xef}\xc1\xb2\xfc\x06\x00\x00\x04',
    'COOKIE_ECHO': b'\x0f\xe4\x0f\x1c\xceU\xce\x8f\x99j\x08\xa6\n\x00\x01\xb0\xbb{\x0f\x9c\x00\x00\xfa\x00'
                    '\x00\n\x00\x00\xbb{\x0f\x9c\x00\x00\x00\x00\x0f\xe4\x00\x00\x01\x00\x00\x00\x04\x00'
                    '\x00\x00\x01\x01\x01\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\xceU\xce\x8f\x00\x00\xfa\x00\x00\n\x00\x00\xceU\xce\x8f\x0f\x1c\x00\x00\x01'
                    '\x00\x00\x00\x04\x00\x00\x00\x01\x01\x01\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00O9\xd8XO:\xc2\xb8',
    'COOKIE_ACK': b'\x0f\x1c\x0f\xe4\xbb{\x0f\x9c!B\xfaa\x0b\x00\x00\x04',
    'ERROR_01': b'0909\xde\xad\xbe\xef\xde\xad\xbe\xef\t\x00\x00\x10\x00\x01\x00\x08\x00\x99\x00\x00',
    'SHUTDOWN': b'\x0f\x1c\x0f\xe4\xbb{\x0f\x9ca\x1d\xedW\x07\x00\x00\x08\xbb{\x0f\x9d',
    'SHUTDOWN_ACK': b'\x0f\xe4\x0f\x1c\xceU\xce\x8f<\xd9\xc2\x82\x08\x00\x00\x04',
    'ECNE': b'0909\xde\xad\xbe\xef\xde\xad\xbe\xef\x0c\x00\x00\x08\xde\xad\xbe\xef',
    'CWR': b'0909\xde\xad\xbe\xef\xde\xad\xbe\xef\r\x00\x00\x08\xde\xad\xbe\xef',
    'SHUTDOWN_COMPLETE': b'\x0f\x1c\x0f\xe4\xbb{\x0f\x9cj\xd9\x9d\xc7\x0e\x00\x00\x04',
}


def test_sctp_pack():
    for k, v in test_bytearr.items():
        sctp = SCTP(v)
        assert (v == str(sctp))
        sctp.sum = 0
        print 'Successfully done packing %s' % k

def test_sctp_unpack():
    import binascii
    for k, v in test_bytearr.items():
        sctp = SCTP(v)
        sctpchunk = sctp.chunks[0]
        if isinstance(sctpchunk, ChunkData):
            assert (sctp.sport == 4068)
            assert (sctp.dport == 3868)
            assert (sctpchunk.type == 0)
            assert (sctpchunk.flags == 3)
            assert (sctpchunk.unordered_flag == 0)
            assert (sctpchunk.beginning_flag == 1)
            assert (sctpchunk.ending_flag == 1)
            assert (sctpchunk.len == 460)
            assert (sctpchunk.tsn == 3145404316)
            assert (sctpchunk.stream_id == 0)
            assert (sctpchunk.stream_seq == 0)
            assert (sctpchunk.proto_id == 0)
            assert (binascii.hexlify(sctpchunk.data) == 'deadbeef')
        elif isinstance(sctpchunk, ChunkInit):
            assert (sctp.sport == 4068)
            assert (sctp.dport == 3868)
            assert (sctpchunk.type == 1)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 20)
            assert (sctpchunk.init_tag == 3145404316)
            assert (sctpchunk.a_rwnd == 64000)
            assert (sctpchunk.num_os == 10)
            assert (sctpchunk.num_is == 10)
            assert (sctpchunk.init_tsn == 3145404316)
        elif isinstance(sctpchunk, ChunkInitAck):
            assert (sctp.sport == 3868)
            assert (sctp.dport == 4068)
            assert (sctpchunk.type == 2)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 452)
            assert (sctpchunk.init_tag == 3461729935)
            assert (sctpchunk.a_rwnd == 64000)
            assert (sctpchunk.num_os == 10)
            assert (sctpchunk.num_is == 10)
            assert (sctpchunk.init_tsn == 3461729935)
            assert (sctpchunk.cookie_param == 7)
            assert (sctpchunk.param_len == 432)
            assert (binascii.hexlify(sctpchunk.state_cookie) == (
                'bb7b0f9c0000fa00000a0000bb7b0f9c000000000fe4000001000000040000000101010a0000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '000000000000000000000000000000000000000000000000000000000000000000000000ce55ce8f00'
                '00fa00000a0000ce55ce8f0f1c00000100000004000000010101140000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '000000000000000000004f39d8584f3ac2b8'
                )
            )
        elif isinstance(sctpchunk, ChunkSack):
            assert (sctp.sport == 3868)
            assert (sctp.dport == 4068)
            assert (sctpchunk.type == 3)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 16)
            assert (sctpchunk.cum_tsn_ack == 3145404316)
            assert (sctpchunk.a_rwnd == 64000)
            assert (sctpchunk.num_gap_ack == 0)
            assert (sctpchunk.num_dup_tsn == 0)
        elif isinstance(sctpchunk, ChunkHeartbeat):
            assert (sctp.sport == 2905)
            assert (sctp.dport == 2905)
            assert (sctpchunk.type == 4)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 24)
            assert (sctpchunk.hb_type == 1)
            assert (sctpchunk.hb_len == 20)
            assert (binascii.hexlify(sctpchunk.hb_info) == '40e44b920a1c062c1b66af7edead0000')
        elif isinstance(sctpchunk, ChunkHeartbeatAck):
            assert (sctp.sport == 2905)
            assert (sctp.dport == 2905)
            assert (sctpchunk.type == 5)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 24)
            assert (sctpchunk.hb_type == 1)
            assert (sctpchunk.hb_len == 20)
            assert (binascii.hexlify(sctpchunk.hb_info) == '40e44b920a1c062c1b66af7ebeef0000')
        elif isinstance(sctpchunk, ChunkAbort):
            assert (sctp.sport == 12345)
            assert (sctp.dport == 12345)
            assert (sctpchunk.type == 6)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 4)
        elif isinstance(sctpchunk, ChunkShutdown):
            assert (sctp.sport == 3868)
            assert (sctp.dport == 4068)
            assert (sctpchunk.type == 7)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 8)
            assert (sctpchunk.cum_tsn_ack == 3145404317)
        elif isinstance(sctpchunk, ChunkShutdownAck):
            assert (sctp.sport == 4068)
            assert (sctp.dport == 3868)
            assert (sctpchunk.type == 8)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 4)
        elif isinstance(sctpchunk, ChunkError):
            assert (sctp.sport == 12345)
            assert (sctp.dport == 12345)
            assert (sctpchunk.type == 9)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 16)
            assert (sctpchunk.cause_code == 1)
            assert (sctpchunk.cause_len == 8)
            assert ((struct.unpack('H', sctpchunk.invalid_id)[0] >> 8) == 153)
        elif isinstance(sctpchunk, ChunkCookieEcho):
            assert (sctp.sport == 4068)
            assert (sctp.dport == 3868)
            assert (sctpchunk.type == 10)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 432)
            assert (binascii.hexlify(sctpchunk.cookie) == (
                'bb7b0f9c0000fa00000a0000bb7b0f9c000000000fe4000001000000040000000101010a0000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '000000000000000000000000000000000000000000000000000000000000000000000000ce55ce8f00'
                '00fa00000a0000ce55ce8f0f1c00000100000004000000010101140000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                '000000000000000000004f39d8584f3ac2b8'
                )
            )
        elif isinstance(sctpchunk, ChunkCookieAck):
            assert (sctp.sport == 3868)
            assert (sctp.dport == 4068)
            assert (sctpchunk.type == 11)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 4)
        elif isinstance(sctpchunk, ChunkECNE):
            assert (sctp.sport == 12345)
            assert (sctp.dport == 12345)
            assert (sctpchunk.type == 12)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 8)
            assert (sctpchunk.lowest_tsn == 3735928559)
        elif isinstance(sctpchunk, ChunkCWR):
            assert (sctp.sport == 12345)
            assert (sctp.dport == 12345)
            assert (sctpchunk.type == 13)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 8)
            assert (sctpchunk.lowest_tsn == 3735928559)
        elif isinstance(sctpchunk, ChunkShutdownComplete):
            assert (sctp.sport == 3868)
            assert (sctp.dport == 4068)
            assert (sctpchunk.type == 14)
            assert (sctpchunk.flags == 0)
            assert (sctpchunk.len == 4)
        print 'Successfully done unpacking %s' % k


if __name__ == '__main__':
    test_sctp_pack()
    test_sctp_unpack()
    print 'Tests Successful...'
