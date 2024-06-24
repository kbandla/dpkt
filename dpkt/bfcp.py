# $Id: bfcp.py amoxuk $
# -*- coding: utf-8 -*-
import struct
from binascii import unhexlify

import dpkt


######################
#     Primitive      #
######################
class Primitive:
    FloorRequest = 1
    FloorRelease = 2
    FloorRequestQuery = 3
    FloorRequestStatus = 4
    UserQuery = 5
    UserStatus = 6
    FloorQuery = 7
    FloorStatus = 8
    ChairAction = 9
    ChairActionAck = 10
    Hello = 11
    HelloAck = 12
    Error = 13
    FloorRequestStatusAck = 14
    FloorStatusAck = 15
    Goodbye = 16
    GoodbyeAck = 17


######################
#     Attribute      #
######################
class AttrType:
    BENEFICIARY_ID = 1
    FLOOR_ID = 2
    FLOOR_REQUEST_ID = 3
    PRIORITY = 4
    REQUEST_STATUS = 5
    ERROR_CODE = 6
    ERROR_INFO = 7
    PARTICIPANT_PROVIDED_INFO = 8
    STATUS_INFO = 9
    SUPPORTED_ATTRIBUTES = 10
    SUPPORTED_PRIMITIVES = 11
    USER_DISPLAY_NAME = 12
    USER_URI = 13
    BENEFICIARY_INFORMATION = 14
    FLOOR_REQUEST_INFORMATION = 15
    REQUESTED_BY_INFORMATION = 16
    FLOOR_REQUEST_STATUS = 17
    OVERALL_REQUEST_STATUS = 18
    SHOULD_LEN = {
        BENEFICIARY_ID: 4,
        FLOOR_ID: 4,
        FLOOR_REQUEST_ID: 4,
        PRIORITY: 4,
        REQUEST_STATUS: 4,
        PARTICIPANT_PROVIDED_INFO: 4,
        USER_DISPLAY_NAME: 4,
        USER_URI: 4,
        BENEFICIARY_INFORMATION: 4,
        FLOOR_REQUEST_INFORMATION: 4,
        REQUESTED_BY_INFORMATION: 4,
        FLOOR_REQUEST_STATUS: 4,
        OVERALL_REQUEST_STATUS: 4,
    }


class StatusCode:
    Pending = 1
    Accepted = 2
    Granted = 3
    Denied = 4
    Cancelled = 5
    Released = 6
    Revoked = 7


class PriorityCode:
    Lowest = 0
    Low = 1
    Normal = 2
    High = 3
    Highest = 4


class ErrorCode:
    """Error Code meaning
    Value	Meaning
    1	Conference Does Not Exist
    2	User Does Not Exist
    3	Unknown Primitive
    4	Unknown Mandatory Attribute
    5	Unauthorized Operation
    6	Invalid Floor ID
    7	Floor Request ID Does Not Exist
    8	You have Already Reached the Maximum Number of Ongoing Floor Requests for This Floor
    9	Use TLS
    10	Unable to Parse Message
    11	Use DTLS
    12	Unsupported Version
    13	Incorrect Message Length
    14	Generic Error
    """
    CONFERENCE_NOT_EXIST = 1
    USER_NOT_EXIST = 2
    UNKNOWN_PRIMITIVE = 3
    UNKNOWN_MANDATORY_ATTRIBUTE = 4
    UNAUTHORIZED_OPERATION = 5
    INVALID_FLOOR_ID = 6
    REQUEST_ID_NOT_EXIST = 7
    MAXIMUM_REQUESTS = 8
    USE_TLS = 9
    UNABLE_PARSE_MESSAGE = 10
    USE_DTLS = 11
    UNSUPPORTED_VERSION = 12
    INCORRECT_MESSAGE_LENGTH = 13
    GENERIC_ERROR = 14


DOUBLE_WORD_START_ATTR_TYPE = (
    AttrType.FLOOR_ID, AttrType.FLOOR_REQUEST_ID, AttrType.BENEFICIARY_ID, AttrType.FLOOR_REQUEST_STATUS,
    AttrType.OVERALL_REQUEST_STATUS, AttrType.REQUESTED_BY_INFORMATION, AttrType.FLOOR_REQUEST_INFORMATION,
    AttrType.BENEFICIARY_INFORMATION)


def get_should_len(length):
    return (length + (4 - 1)) & (~(4 - 1))


class BFCP(dpkt.Packet):
    """
    #######################################
    # BFCP:Binary Floor Control Protocol. #
    #######################################

    FIELD NAME                         DESCRIPTION					      TYPE						    VERSIONS
    bfcp.attribute_length              Attribute Length				      Unsigned integer, 2 bytes	    1.8.0 to 3.6.5
    bfcp.attribute_length.too_small    Attribute length is too small      Label						    1.12.0 to 3.6.5
    bfcp.attribute_type                Attribute Type				      Unsigned integer, 1 byte	    1.8.0 to 3.6.5
    bfcp.attribute_types_m_bit         Mandatory bit(M)				      Boolean					    1.10.0 to 3.6.5
    bfcp.beneficiary_id                BENEFICIARY-ID				      Unsigned integer, 2 bytes	    1.10.0 to 3.6.5
    bfcp.conference_id                 Conference ID				      Unsigned integer, 4 bytes	    1.8.0 to 3.6.5
    bfcp.error_code                    Error Code					      Unsigned integer, 1 byte	    1.10.0 to 3.6.5
    bfcp.error_info_text               Text							      Character string			    1.10.0 to 3.6.5
    bfcp.error_specific_details        Error Specific Details		      Sequence of bytes			    2.0.0 to 3.6.5
    bfcp.floor_id                      FLOOR-ID						      Unsigned integer, 2 bytes	    1.10.0 to 3.6.5
    bfcp.floorrequest_id               FLOOR-REQUEST-ID				      Unsigned integer, 2 bytes	    1.10.0 to 3.6.5
    bfcp.hdr_f_bit                     Fragmentation (F)			      Boolean					    1.10.0 to 3.6.5
    bfcp.hdr_r_bit                     Transaction Responder (R)	      Boolean					    1.10.0 to 3.6.5
    bfcp.padding                       Padding						      Sequence of bytes			    2.0.0 to 3.6.5
    bfcp.part_prov_info_text           Text							      Character string			    1.10.0 to 3.6.5
    bfcp.payload                       Payload						      Sequence of bytes			    1.8.0 to 3.6.5
    bfcp.payload_length                Payload Length				      Unsigned integer, 2 bytes	    1.8.0 to 3.6.5
    bfcp.primitive                     Primitive					      Unsigned integer, 1 byte	    1.8.0 to 3.6.5
    bfcp.priority                      FLOOR-REQUEST-ID				      Unsigned integer, 2 bytes	    1.10.0 to 3.6.5
    bfcp.queue_pos                     Queue Position				      Unsigned integer, 1 byte	    1.10.0 to 3.6.5
    bfcp.req_by_i                      Requested-by ID				      Unsigned integer, 2 bytes	    1.10.0 to 3.6.5
    bfcp.request_status                Request Status				      Unsigned integer, 1 byte	    1.8.0 to 3.6.5
    bfcp.status_info_text              Text							      Character string			    1.10.0 to 3.6.5
    bfcp.supp_attr                     Supported Attribute			      Unsigned integer, 1 byte	    1.10.0 to 3.6.5
    bfcp.supp_primitive                Supported Primitive			      Unsigned integer, 1 byte	    1.10.0 to 3.6.5
    bfcp.transaction_id                Transaction ID				      Unsigned integer, 2 bytes	    1.8.0 to 3.6.5
    bfcp.transaction_initiator         Transaction Initiator		      Boolean					    1.8.0 to 1.8.15
    bfcp.user_disp_name                Name							      Character string			    1.10.0 to 3.6.5
    bfcp.user_id                       User ID						      Unsigned integer, 2 bytes	    1.8.0 to 3.6.5
    bfcp.user_uri                      URI							      Character string			    1.10.0 to 3.6.5
    bfcp.ver                           Version(ver)					      Unsigned integer, 1 byte	    1.10.0 to 3.6.5
    """

    __hdr__ = (
        ('_v_f_r', 'B', 0x20),
        ('primitive', 'B', 0),
        ('len', 'H', 0),
        ('conf', 'I', 0),
        ('trans', 'H', 0),
        ('user', 'H', 0),
    )
    __bit_fields__ = {
        '_v_f_r': (
            ('ver', 3),
            ('r', 1),
            ('f', 1),
            ('res', 3),
        )
    }

    def __init__(self, *args, **kwargs):
        self.attrs = []
        super(BFCP, self).__init__(*args, **kwargs)
        if not args and 'len' not in kwargs:
            self.len = self.__len__()

    def __len__(self):
        return int(len(self.data) / 4)

    def __eq__(self, other):
        key = ['ver', 'r', 'f', 'res', 'primitive', 'len', 'conf', 'trans', 'user', 'attrs']
        return all(getattr(self, k) == getattr(other, k) for k in key)

    def __bytes__(self):
        data = b''
        if self.f:
            # todo https://www.rfc-editor.org/rfc/rfc8855.html#name-packet-format
            data += b'\x00' * 4
        if isinstance(self.attrs, list) and len(self.attrs) > 0:
            data += b''.join(bytes(attr) for attr in self.attrs)
        elif isinstance(self.attrs, BFCPAttr):
            data += bytes(self.attrs)
        self.len = int(len(data) / 4)
        return self.pack_hdr() + data

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        l_ = []
        if self.f:
            pass
        length = int(len(self.data) / 4)
        if length != struct.unpack('!H', buf[2:4])[0]:
            raise dpkt.UnpackError('invalid header length')
        if length:
            start = 0
            while start < len(self.data):
                # read sub attr len with padding
                length = get_should_len(self.data[start + 1])  # 1: attr len index
                attr = self.data[start:start + length]
                start += length
                attr = BFCPAttr(attr)  # only this attr len data
                l_.append(attr)
        self.data = self.attrs = l_[0] if len(l_) == 1 else l_
        self.len = struct.unpack('!H', buf[2:4])[0]


class BFCPAttr(dpkt.Packet):
    """
      +------+---------------------------+---------------+
      | Type | Attribute                 | Format        |
      +------+---------------------------+---------------+
      |   1  | BENEFICIARY-ID            | Unsigned16    |
      |   2  | FLOOR-ID                  | Unsigned16    |
      |   3  | FLOOR-REQUEST-ID          | Unsigned16    |
      |   4  | PRIORITY                  | OctetString16 |
      |   5  | REQUEST-STATUS            | OctetString16 |
      |   6  | ERROR-CODE                | OctetString   |
      |   7  | ERROR-INFO                | OctetString   |
      |   8  | PARTICIPANT-PROVIDED-INFO | OctetString   |
      |   9  | STATUS-INFO               | OctetString   |
      |  10  | SUPPORTED-ATTRIBUTES      | OctetString   |
      |  11  | SUPPORTED-PRIMITIVES      | OctetString   |
      |  12  | USER-DISPLAY-NAME         | OctetString   |
      |  13  | USER-URI                  | OctetString   |
      |  14  | BENEFICIARY-INFORMATION   | Grouped       |
      |  15  | FLOOR-REQUEST-INFORMATION | Grouped       |
      |  16  | REQUESTED-BY-INFORMATION  | Grouped       |
      |  17  | FLOOR-REQUEST-STATUS      | Grouped       |
      |  18  | OVERALL-REQUEST-STATUS    | Grouped       |
      +------+---------------------------+---------------+
    """
    __hdr__ = (
        ('_attr', 'B', 1),
        ('len', 'B', 0)
    )
    __bit_fields__ = {
        '_attr': (
            ('type', 7),
            ('mandatory', 1)
        )
    }

    def __init__(self, *args, **kwargs):
        self.value = 0
        self.child = []
        self.real_len = 4
        super().__init__(*args, **kwargs)
        if not args and 'len' not in kwargs:
            self.len = 4
        if 'value' in kwargs:
            self.value = kwargs['value']
        if 'child' in kwargs:
            self.child = kwargs['child']
        # if hasattr(self, 'data'):
        #     del self.data

    def __eq__(self, other):
        key = ['len', 'type', 'mandatory', 'value', 'child']
        if isinstance(self, BFCPAttr) and isinstance(other, BFCPAttr):
            return all(getattr(self, k) == getattr(other, k) for k in key)
        else:
            return False

    def __bytes__(self):
        data = b''
        if self.type in DOUBLE_WORD_START_ATTR_TYPE:
            if isinstance(self.value, list):
                data += struct.pack('!H', self.value[0])
                data += b''.join(bytes(attr) for attr in self.value[1:])
            else:
                data += struct.pack('!H', self.value)
        elif self.type in (AttrType.SUPPORTED_PRIMITIVES, AttrType.SUPPORTED_ATTRIBUTES, AttrType.REQUEST_STATUS,
                           AttrType.PRIORITY):
            if AttrType.SUPPORTED_ATTRIBUTES == self.type:
                self.value = [d << 1 for d in self.value]
            data += struct.pack(f'!{len(self.value)}B', *self.value)
        elif self.type in (AttrType.STATUS_INFO, AttrType.ERROR_INFO):
            if isinstance(self.value, str):
                data = self.value.encode()
            else:
                data = b''
        elif self.type == AttrType.ERROR_CODE:
            # code=4, v = [code, [type,r],[type,r],[type,r]] ,r=0
            # code!=4, v= [code,] or v=code
            if isinstance(self.value, int):
                data = struct.pack('!B', self.value)
            else:
                data = struct.pack('!B', self.value[0])
                unknown_type = [u[0] << 1 for u in self.value[1:]]
                data += struct.pack(f'!{len(unknown_type)}B', *unknown_type)
        else:
            data += struct.pack(f'!{len(self.value)}B', *self.value)
        length = self.__hdr_len__ + len(data)
        length = get_should_len(length) - length
        child = self.child if isinstance(self.child, list) else [self.child, ]
        child = b''.join(bytes(child) for child in child)
        return self.pack_hdr() + data + b'\x00' * length + child

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        current = 0
        value = 0
        if self.type == AttrType.SUPPORTED_PRIMITIVES:
            self.real_len = buf[1]
        elif self.type == AttrType.SUPPORTED_ATTRIBUTES:
            self.real_len = buf[1]
        elif self.type in AttrType.SHOULD_LEN:
            self.real_len = 4
        elif self.type in (AttrType.STATUS_INFO, AttrType.ERROR_INFO):
            # with none child
            self.real_len = buf[1]
        elif self.type == AttrType.ERROR_CODE:
            self.real_len = buf[1]
        # if get_should_len(self.real_len) == len(buf):
        data = self.data[0:self.real_len - self.__hdr_len__]
        if self.type == AttrType.SUPPORTED_PRIMITIVES:
            value = [sp for sp in data]
        elif self.type == AttrType.SUPPORTED_ATTRIBUTES:
            value = [sp >> 1 for sp in data]
        elif self.type in DOUBLE_WORD_START_ATTR_TYPE:
            value = struct.unpack('!H', data)[0]
        elif self.type == AttrType.REQUEST_STATUS:
            value = list(struct.unpack('!2B', data))
        elif self.type in (AttrType.STATUS_INFO, AttrType.ERROR_INFO):
            # with none child
            value = data.decode()
        elif self.type == AttrType.ERROR_CODE:
            value = list(struct.unpack(f'!{len(data)}B', data))  # code
            if value[0] != 4:
                value = value[0]
            else:
                value = value[0:1] + [[u >> 1, 0] for u in value[1:]]
        if get_should_len(self.real_len) != len(buf):
            current = get_should_len(self.real_len)
            pos = 0
            buf = buf[current:]
            length = len(buf)
            while pos < length:
                start = pos + get_should_len(buf[pos + 1])
                self.child.append(BFCPAttr(buf[pos:start]))
                pos = start
            if len(self.child) == 1:
                self.child = self.child[0]
        self.data = b''
        self.value = value


def test_hello():
    s = unhexlify(
        '200b'
        '0000'
        '01030227'
        '5B39'
        '0228'
    )
    b = BFCP()
    b.primitive = Primitive.Hello
    b.conf = 16974375
    b.trans = 23353
    b.user = 552
    assert bytes(b) == s
    b = BFCP(s)
    assert b.ver == 1
    assert b.r == 0
    assert b.f == 0
    assert b.primitive == Primitive.Hello
    assert b.conf == 16974375
    assert b.trans == 23353
    assert b.user == 552
    assert b.attrs == []


def test_attr_floor_id():
    s = unhexlify(
        '05'
        '04'  # FloorRequest
        '0001'  # payload length
    )
    attr = BFCPAttr(type=AttrType.FLOOR_ID, mandatory=1, value=1)
    assert bytes(attr) == s

    b = BFCPAttr(s)
    assert b.type == AttrType.FLOOR_ID
    assert b.mandatory == 1
    assert b.value == 1


def test_hello_ack():
    s = unhexlify(
        '200c'
        '000a'
        '01030227'
        '5B39'
        '0228'
        '17'
        '13'  # attr primitives
        '0102030405060708090a0b0c0d0e0f101100'
        '15'
        '14'
        '020406080a0c0e10121416181a1c1e202224'
    )
    b = BFCP()
    b.primitive = Primitive.HelloAck
    b.conf = 16974375
    b.trans = 23353
    b.user = 552
    b.attrs = [
        BFCPAttr(type=AttrType.SUPPORTED_PRIMITIVES, len=19, mandatory=1,
                 value=[Primitive.FloorRequest, Primitive.FloorRelease, Primitive.FloorRequestQuery,
                        Primitive.FloorRequestStatus, Primitive.UserQuery, Primitive.UserStatus, Primitive.FloorQuery,
                        Primitive.FloorStatus, Primitive.ChairAction, Primitive.ChairActionAck, Primitive.Hello,
                        Primitive.HelloAck, Primitive.Error, Primitive.FloorRequestStatusAck, Primitive.FloorStatusAck,
                        Primitive.Goodbye, Primitive.GoodbyeAck]),
        BFCPAttr(type=AttrType.SUPPORTED_ATTRIBUTES, len=20, mandatory=1,
                 value=[AttrType.BENEFICIARY_ID, AttrType.FLOOR_ID, AttrType.FLOOR_REQUEST_ID,
                        AttrType.PRIORITY, AttrType.REQUEST_STATUS, AttrType.ERROR_CODE,
                        AttrType.ERROR_INFO, AttrType.PARTICIPANT_PROVIDED_INFO,
                        AttrType.STATUS_INFO, AttrType.SUPPORTED_ATTRIBUTES,
                        AttrType.SUPPORTED_PRIMITIVES, AttrType.USER_DISPLAY_NAME,
                        AttrType.USER_URI, AttrType.BENEFICIARY_INFORMATION,
                        AttrType.FLOOR_REQUEST_INFORMATION,
                        AttrType.REQUESTED_BY_INFORMATION, AttrType.FLOOR_REQUEST_STATUS,
                        AttrType.OVERALL_REQUEST_STATUS])
    ]
    assert bytes(b) == s
    b = BFCP(s)
    assert b.ver == 1
    assert b.r == 0
    assert b.f == 0
    assert b.primitive == Primitive.HelloAck
    assert b.conf == 16974375
    assert b.trans == 23353
    assert b.user == 552
    assert b.attrs[0] == BFCPAttr(type=AttrType.SUPPORTED_PRIMITIVES, len=19, mandatory=1,
                                  value=[Primitive.FloorRequest, Primitive.FloorRelease, Primitive.FloorRequestQuery,
                                         Primitive.FloorRequestStatus, Primitive.UserQuery, Primitive.UserStatus,
                                         Primitive.FloorQuery,
                                         Primitive.FloorStatus, Primitive.ChairAction, Primitive.ChairActionAck,
                                         Primitive.Hello,
                                         Primitive.HelloAck, Primitive.Error, Primitive.FloorRequestStatusAck,
                                         Primitive.FloorStatusAck,
                                         Primitive.Goodbye, Primitive.GoodbyeAck])

    assert b.attrs[1] == BFCPAttr(type=AttrType.SUPPORTED_ATTRIBUTES, len=20, mandatory=1,
                                  value=[AttrType.BENEFICIARY_ID, AttrType.FLOOR_ID,
                                         AttrType.FLOOR_REQUEST_ID,
                                         AttrType.PRIORITY, AttrType.REQUEST_STATUS, AttrType.ERROR_CODE,
                                         AttrType.ERROR_INFO, AttrType.PARTICIPANT_PROVIDED_INFO,
                                         AttrType.STATUS_INFO, AttrType.SUPPORTED_ATTRIBUTES,
                                         AttrType.SUPPORTED_PRIMITIVES, AttrType.USER_DISPLAY_NAME,
                                         AttrType.USER_URI, AttrType.BENEFICIARY_INFORMATION,
                                         AttrType.FLOOR_REQUEST_INFORMATION,
                                         AttrType.REQUESTED_BY_INFORMATION, AttrType.FLOOR_REQUEST_STATUS,
                                         AttrType.OVERALL_REQUEST_STATUS])


def test_floor_request():
    s = unhexlify(
        '20'
        '01'  # FloorRequest
        '0001'  # payload length
        '01030227'  # conf
        '5B39'  # trans
        '0228'  # user
        '05'  # attr type 
        '04'  # attr length 
        '0001'  # floor id
    )
    b = BFCP()
    b.conf = 16974375
    b.len = 1
    b.trans = 23353
    b.user = 552
    b.primitive = Primitive.FloorRequest
    b.attrs = BFCPAttr(type=AttrType.FLOOR_ID, mandatory=1, value=1)
    assert bytes(b) == s


def test_floor_request_unpack():
    s = unhexlify(
        '20'
        '01'  # FloorRequest
        '0001'  # payload length
        '01030227'  # conf
        '5B39'  # trans
        '0228'  # user
        '05'  # attr type 
        '04'  # attr length 
        '0001'  # floor id
    )
    p = BFCP(s)
    assert p.conf == 16974375
    assert p.len == 1
    assert p.trans == 23353
    assert p.user == 552
    assert p.primitive == Primitive.FloorRequest
    assert p.attrs == BFCPAttr(type=AttrType.FLOOR_ID, mandatory=1, value=1)


def test_floor_request_status():
    s = unhexlify(
        '30'
        '04'  # FloorRequestStatus
        '0004'  # payload length
        '01030227'  # conf
        '5B39'  # trans
        '0228'  # user
        '1f'  # attr type mandatory
        '10'  # attr length 
        '0000'  # floor id
        '25'  # attr type mandatory
        '0c'  # attr length 
        '0000'  # floor id
        '0b'  # attr type mandatory
        '04'  # attr length 
        '0300'  # floor id
        '23'  # attr type mandatory
        '04'  # attr length 
        '0001'  # floor id
    )
    p = BFCP(s)
    assert p.ver == 1
    assert p.f == 0
    assert p.r == 1
    assert p.primitive == Primitive.FloorRequestStatus
    assert p.conf == 16974375
    assert p.len == 4
    assert p.trans == 23353
    assert p.user == 552
    assert p.attrs == BFCPAttr(type=AttrType.FLOOR_REQUEST_INFORMATION, mandatory=1, len=16, value=0,
                               child=BFCPAttr(type=AttrType.OVERALL_REQUEST_STATUS, mandatory=1, len=12, value=0,  # 4
                                              child=[
                                                  BFCPAttr(type=AttrType.REQUEST_STATUS, mandatory=1, len=4,  # 4
                                                           value=[StatusCode.Granted, 0]),
                                                  BFCPAttr(type=AttrType.FLOOR_REQUEST_STATUS, mandatory=1, len=4,  # 4
                                                           value=1)
                                              ]))
    # def test_floor_request_status_unpack():
    p = BFCP()
    p.ver = 1
    p.f = 0
    p.r = 1
    p.primitive = Primitive.FloorRequestStatus
    p.conf = 16974375
    p.len = 4
    p.trans = 23353
    p.user = 552
    p.attrs = BFCPAttr(type=AttrType.FLOOR_REQUEST_INFORMATION, mandatory=1, len=16,
                       value=[0,
                              BFCPAttr(type=AttrType.OVERALL_REQUEST_STATUS, mandatory=1, len=12,
                                       value=[0,
                                              BFCPAttr(type=AttrType.REQUEST_STATUS, mandatory=1, len=4,
                                                       value=[StatusCode.Granted, 0]),
                                              BFCPAttr(type=AttrType.FLOOR_REQUEST_STATUS, mandatory=1, len=4,
                                                       value=1)
                                              ])])
    assert bytes(p) == s


def test_status_info():
    s = unhexlify(
        '30'
        '04'  # FloorRequestStatus
        '0009'  # payload length
        '01030227'  # conf
        '5B39'  # trans
        '0228'  # user
        '1f'  # attr type mandatory
        '24'  # attr length 
        '0000'  # floor id
        '25'  # attr type mandatory
        '1c'  # attr length 
        '0001'  # floor id
        '0b'  # attr type mandatory
        '04'  # attr length 
        '0300'  # floor id
        '13'  # attr type mandatory 
        '12'  # attr length     
        '73746174757320696e666f20746578740000'  # status info text  16+2
        '23'  # attr type mandatory
        '04'  # attr length 
        '0002'  # floor id
    )
    p = BFCP(s)
    assert p.ver == 1
    assert p.f == 0
    assert p.r == 1
    assert p.primitive == Primitive.FloorRequestStatus
    assert p.conf == 16974375
    assert p.len == 9
    assert p.trans == 23353
    assert p.user == 552
    assert p.attrs == BFCPAttr(type=AttrType.FLOOR_REQUEST_INFORMATION, mandatory=1, len=36, value=0,  # 4
                               child=[BFCPAttr(type=AttrType.OVERALL_REQUEST_STATUS, mandatory=1, len=28, value=1,  # 4
                                               child=[
                                                   BFCPAttr(type=AttrType.REQUEST_STATUS, mandatory=1, len=4,
                                                            value=[StatusCode.Granted, 0]),  # 4
                                                   BFCPAttr(type=AttrType.STATUS_INFO, mandatory=1, len=18,  # 20
                                                            value='status info text')
                                               ]),
                                      BFCPAttr(type=AttrType.FLOOR_REQUEST_STATUS, mandatory=1, len=4, value=2),  # 4
                                      ])


def test_user_uri():
    pass


def test_user_display_name():
    pass


def test_participant_provided_info():
    pass


def test_error_info():
    s = unhexlify('0f'
                  '25'
                  '746869732069732061205041525449434950414e545f50524f56494445445f494e464f'
                  '000000')
    p = BFCPAttr(type=AttrType.ERROR_INFO, mandatory=1, len=37,
                 value='this is a PARTICIPANT_PROVIDED_INFO')  # 35
    assert bytes(p) == s
    b = BFCPAttr(s)
    assert b.value == 'this is a PARTICIPANT_PROVIDED_INFO'
    assert b.type == AttrType.ERROR_INFO
    assert b.len == 37
    s = unhexlify('0d'  # attr type mandatory
                  '14'  # attr length 
                  '0200'  # error type 2
                  '0f'  # attr type mandatory 
                  '10'  # attr length     
                  '75736572'
                  '206e6f74'
                  '20657869'
                  '7374'  # user not exist
                  )
    p = BFCPAttr(type=AttrType.ERROR_CODE, mandatory=1, len=20,
                 value=2,
                 child=BFCPAttr(type=AttrType.ERROR_INFO, mandatory=1, len=16, value='user not exist'))
    assert bytes(p) == s


def test_error_code():
    s = unhexlify('0d'
                  '04'
                  '01'
                  '00')

    p = BFCPAttr(type=AttrType.ERROR_CODE, mandatory=1, len=4,
                 value=1)
    assert bytes(p) == s
    b = BFCPAttr(s)
    assert b.type == AttrType.ERROR_CODE
    assert b.mandatory == 1
    assert b.len == 4
    assert b.value == 1


def test_error_code_four():
    s = unhexlify('0d'
                  '0a'
                  '04'
                  '02'  # unknown type. R
                  '04'  # unknown type. R
                  '06'  # unknown type. R
                  '08'  # unknown type. R
                  '0a'  # unknown type. R
                  '0c'  # unknown type. R
                  '0e'  # unknown type. R
                  '00'  # padding
                  '00'  # padding
                  )
    p = BFCPAttr(type=AttrType.ERROR_CODE, mandatory=1, len=10,
                 value=[4, [1, 0], [2, 0], [3, 0], [4, 0], [5, 0], [6, 0], [7, 0]])
    assert bytes(p) == s
    b = BFCPAttr(s)
    assert b.type == AttrType.ERROR_CODE
    assert b.mandatory == 1
    assert b.len == 10
    assert b.value == [4, [1, 0], [2, 0], [3, 0], [4, 0], [5, 0], [6, 0], [7, 0]]


def test_error():
    s = unhexlify(
        '30'
        '0d'  # error
        '0006'  # payload length
        '01030227'  # conf
        '5B39'  # trans
        '0228'  # user
        '0d'  # attr type mandatory
        '18'  # attr length 
        '0200'  # error type 2
        '0f'  # attr type mandatory 
        '11'  # attr length 17     
        'e794a8e6'
        '88b7e4b8'
        '8de5ad98'
        'e59ca8'
        '000000'  # 用户不存在
    )
    p = BFCP()
    p.ver = 1
    p.f = 0
    p.r = 1
    p.primitive = Primitive.Error
    p.conf = 16974375
    p.len = 5
    p.trans = 23353
    p.user = 552
    p.attrs = BFCPAttr(type=AttrType.ERROR_CODE, mandatory=1, len=24, value=2,
                       child=BFCPAttr(type=AttrType.ERROR_INFO, mandatory=1, len=17, value='用户不存在'))
    assert bytes(p) == s
