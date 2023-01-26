# $Id: rtcp.py 23 2023-01-22 11:22:33Z pajarom $
# -*- coding: utf-8 -*-
# RFC3550 and RFC3611

"""RTP Control Protocol."""
from __future__ import absolute_import

from . import dpkt
from .dpkt import Packet
import math

#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    RC   |   PT=SR=200   |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         SSRC of sender                        |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# sender |              NTP timestamp, most significant word             |
# info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |             NTP timestamp, least significant word             |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         RTP timestamp                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                     sender's packet count                     |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                      sender's octet count                     |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_1 (SSRC of first source)                 |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   1    | fraction lost |       cumulative number of packets lost       |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |           extended highest sequence number received           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                      interarrival jitter                      |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         last SR (LSR)                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                   delay since last SR (DLSR)                  |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_2 (SSRC of second source)                |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   2    :                               ...                             :
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#        |                  profile-specific extensions                  |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
class SRInfo(dpkt.Packet):
    """RTCP Sender Info"""

    __hdr__ = (
        ('ssrc', 'I', 0),
        ('ntp_ts_msw', 'I', 0),
        ('ntp_ts_lsw', 'I', 0),
        ('rtp_ts', 'I', 0),
        ('pkts', 'I', 0),
        ('octs', 'I', 0)
    )
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = b''

#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    RC   |   PT=RR=201   |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                     SSRC of packet sender                     |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_1 (SSRC of first source)                 |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   1    | fraction lost |       cumulative number of packets lost       |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |           extended highest sequence number received           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                      interarrival jitter                      |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         last SR (LSR)                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                   delay since last SR (DLSR)                  |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_2 (SSRC of second source)                |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   2    :                               ...                             :
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#        |                  profile-specific extensions                  |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class RRInfo(dpkt.Packet):
    """RTCP Receiver Info"""

    __hdr__ = (
        ('ssrc', 'I', 0),
    )
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = b''

class Report(dpkt.Packet):
    """RTCP Report Sender"""

    __hdr__ = (
        ('ssrc', 'I', 0),
        ('_lossfrac_losscumm', 'I', 0),
        ('seq', 'I', 0),
        ('jitter', 'I', 0),
        ('lsr', 'I', 0),
        ('dlsr', 'I', 0)
    )
    __bit_fields__ = {
        '_lossfrac_losscumm': (
            ('lossfrac', 8),   # first byte
            ('losscumm', 24),  # lower 3 bytes
        ),
    }
    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = b''

    def __bytes__(self):
        return self.pack_hdr()

#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    SC   |  PT=SDES=202  |             length            |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# chunk  |                          SSRC/CSRC_1                          |
#   1    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                           SDES items                          |
#        |                              ...                              |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# chunk  |                          SSRC/CSRC_2                          |
#   2    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                           SDES items                          |
#        |                              ...                              |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    SC   |   PT=BYE=203  |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                           SSRC/CSRC                           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        :                              ...                              :
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# (opt)  |     length    |               reason for leaving            ...
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# header +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |V=2|P| subtype |   PT=APP=204  |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                           SSRC/CSRC                           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                          name (ASCII)                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                   application-dependent data                ...
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |V=2|P|reserved |   PT=XR=207   |             length            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                              SSRC                             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    :                         report blocks                         :
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

BT_LOSS = 1  # Loss RLE Report Block
BT_DUPL = 2  # Duplicate RLE Report Block
BT_RCVT = 3  # Packet Receipt Times Report Block
BT_RCVR = 4  # Receiver Reference Time Report Block
BT_DLRR = 5  # DLRR Report Block
BT_STAT = 6  # Statistics Summary Report Block
BT_VOIP = 7  # VoIP Metrics Report Block

class XBlockLoss(dpkt.Packet):
    """RTCP Extended Loss RLE Report Block"""
    __hdr__ = (
        ('ssrc', 'I', 0),
    )
    # def unpack(self, buf):
    #     super(XBlockLoss, self).unpack(buf)
    #     self.data = buf[self.__hdr_len_:]

class XBlockDupl(dpkt.Packet):
    """RTCP Extended Duplicate RLE Report Block"""
    __hdr__ = (
        ('ssrc', 'I', 0),
    )
    # def unpack(self, buf):
    #     super(XBlockDupl, self).unpack(buf)
    #     self.data = buf[self.__hdr_len_:]

class XBlockRcvt(dpkt.Packet):
    """RTCP Extended Packet Receipt Times Report Block"""
    __hdr__ = (
        ('ssrc', 'I', 0),
    )
    # def unpack(self, buf):
    #     super(XBlockRcvt, self).unpack(buf)
    #     self.data = buf[self.__hdr_len_:]

class XBlockRcvr(dpkt.Packet):
    """RTCP Extended Receiver Reference Time Report Block"""
    __hdr__ = (
        ('ntp_ts_msw', 'I', 0),
        ('ntp_ts_lsw', 'I', 0)
    )

class XBlockDlrr(dpkt.Packet):
    """RTCP Extended DLRR Report Block"""
    __hdr__ = (
    )
    def unpack(self, buf):
        self.data = buf

class XBlockStat(dpkt.Packet):
    """RTCP Extended Statistics Summary Report Block"""
    __hdr__ = (
        ('ssrc', 'I', 0),
        ('beg_seq', 'H', 0),
        ('end_seq', 'H', 0),
        ('loss', 'I', 0),
        ('dupl', 'I', 0),
        ('min_jitter', 'I', 0),
        ('max_jitter', 'I', 0),
        ('avg_jitter', 'I', 0),
        ('dev_jitter', 'I', 0),
        ('min_ttl_or_hl', 'B', 0),
        ('max_ttl_or_hl', 'B', 0),
        ('mean_ttl_or_hl', 'B', 0),
        ('dev_ttl_or_hl', 'B', 0)
    )

class XBlockVoip(dpkt.Packet):
    """RTCP Extended Info"""
    __hdr__ = (
        ('ssrc', 'I', 0),
        ('loss_rate', 'B', 0),
        ('disc_rate', 'B', 0),
        ('burst_density', 'B', 0),
        ('gap_density', 'B', 0),
        ('burst_duration', 'H', 0),
        ('gap_duration', 'H', 0),
        ('rtt', 'H', 0),
        ('end_sys_delay', 'H', 0),
        ('signal_level', 'B', 0),
        ('noise_level', 'B', 0),
        ('RERL', 'B', 0),
        ('Gmin', 'B', 0),
        ('RFactor', 'B', 0),
        ('ext_RFactor', 'B', 0),
        ('MOS_LQ', 'B', 0),
        ('MOS_CQ', 'B', 0),
        ('RX_config', 'B', 0),
        ('reserved', 'B', 0),
        ('nominal_jitter', 'H', 0),
        ('max_jitter', 'H', 0),
        ('abs_max_jitter', 'H', 0)
    )

class XReportBlock(dpkt.Packet):
    """RTCP Extended VoIP Metrics Report Block"""
    __hdr__ = (
        ('type', 'B', 0),
        ('spec', 'B', 0),
        ('len', 'H', 0)
    )

    def setBlock(self, block):
        self.block = block
        if isinstance(block, XBlockLoss):
            self.type = BT_LOSS
        elif isinstance(block, XBlockDupl):
            self.type = BT_DUPL
        elif isinstance(block, XBlockRcvt):
            self.type = BT_RCVT
        elif isinstance(block, XBlockRcvr):
            self.type = BT_RCVR
        elif isinstance(block, XBlockDlrr):
            self.type = BT_DLRR
        elif isinstance(block, XBlockStat):
            self.type = BT_STAT
        elif isinstance(block, XBlockVoip):
            self.type = BT_VOIP
        else:
            raise ValueError("Invalid Block Type.")
        self.len = math.ceil((block.__hdr_len__ + len(block.data))/4)

    def unpack(self, buf):
        super(XReportBlock, self).unpack(buf)
        self.block = None
        buf = self.data
        if self.type == BT_LOSS:
            self.block = XBlockLoss(buf[0:self.len * 4])
        elif self.type == BT_DUPL:
            self.block = XBlockDupl(buf[0: self.len * 4])
        elif self.type == BT_RCVT:
            self.block = XBlockRcvt(buf[0: self.len * 4])
        elif self.type == BT_RCVR :
            self.block = XBlockRcvr(buf[0: self.len * 4])
        elif self.type == BT_DLRR:
            self.block = XBlockDlrr(buf[0: self.len * 4])
        elif self.type == BT_STAT:
            self.block = XBlockStat(buf[0: self.len * 4])
        elif self.type == BT_VOIP:
            self.block = XBlockVoip(buf[0: self.len * 4])
        else:
            raise ValueError("Invalid Block Type.")
        self.data = b''

class XReport(dpkt.Packet):
    """RTCP Extended Info"""
    __hdr__ = (
    )

    def __init__(self, *args, **kwargs):
        self.blocks=[]
        super(XReport, self).__init__(*args, **kwargs)

    def addBlock(self, block):
        self.blocks.append(block)

    def unpack(self, buf):
        super(XReport, self).unpack(buf)
        buf = self.data
        self.data = b''
        try:
            ll = 0 
            while ll < len(buf):
                blck = XReportBlock(buf[ll:])
                ll = ll + blck.__hdr_len__ + blck.len * 4
                self.blocks.append(blck)
        except ValueError:
            if len(self.blocks)==0: # At least one block must be present...
                raise ValueError("Invalid Block Type.")

    def __len__(self):
        ll = 0 
        for _ in range(len(self.blocks)):
            ll = ll + self.blocks[_].__hdr_len__ + self.blocks[_].len * 4
        return ll

    def __bytes__(self):
        bb = b'' # No data at this level by default
        if len(self.blocks)>0:
            for _ in range(len(self.blocks)):
                bb = bb + self.blocks[_].pack_hdr() + self.blocks[_].block.pack_hdr() + self.blocks[_].block.data
        return  bb 


VERSION = 2

PT_SR = 200
PT_RR = 201
PT_SDES = 202
PT_BYE = 203
PT_APP = 204
PT_XR = 207

# START TODO...
SDES_CNAME = 1
SDES_NAME = 2
SDES_EMAIL = 3
SDES_PHONE = 4
SDES_LOC = 5
SDES_TOOL = 6
SDES_NOTE = 7
SDES_PRIV = 8
# END TODO...

class RTCP(Packet):
    """Real-Time Transport Protocol.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of RTCP.
        TODO.
    """

    __hdr__ = (
        ('_version_p_cc_pt', 'H', 0x8000),
        ('len', 'H', 0)
    )

    __bit_fields__ = {
        '_version_p_cc_pt': (
            ('version', 2),   # version 1100 0000 0000 0000 ! 0xC000  14
            ('p', 1),         # p       0010 0000 0000 0000 ! 0x2000  13
            ('cc', 5),        # cc      0001 1111 0000 0000 ! 0x1F00   8
            ('pt', 8),        # pt      0000 0000 1111 1111 ! 0x00FF   0
        ),
    }

    def addInfo(self, info):
        if not ( self.pt in (PT_SR, PT_RR, PT_XR) ):
            raise ValueError("Info property not supported.")
        self.info = info
        ll = self.__hdr_len__ + self.info.__hdr_len__ + len(self.data)
        # Only valid for PT_SR and PT_RR
        if len(self.reports)>0:
            if ( self.pt in (PT_SR, PT_RR) ):
                ll = ll + 24 * self.cc
            else:
                ll = ll + len(self.reports[0])
        self.len = math.ceil((ll-4)/4)

    def addReport(self, report):
        if not ( self.pt in (PT_SR, PT_RR, PT_XR) ):
            raise ValueError("Report property not supported.")
        self.reports.append(report)
        self.cc = len(self.reports)
        ll = self.__hdr_len__ + len(self.data)
        if self.info:
            ll = ll + self.info.__hdr_len__ 
        # Only valid for PT_SR and PT_RR
        if ( self.pt in (PT_SR, PT_RR) ):
            ll = ll + 24 * self.cc
        else:
            ll = ll + len(self.reports[0])
        self.len = math.ceil((ll-4)/4)

    def addData(self, data):
        if (self.pt in (PT_RR, PT_XR)):
            raise ValueError("Data property not supported.")
        self.data = data
        ll = self.__hdr_len__ + len(self.data)
        if self.info:
            ll = ll + self.info.__hdr_len__ 
        if self.pt in (PT_SR, PT_RR):
            # Only valid for PT_SR and PT_RR
            ll = ll + 24 * self.cc 
        self.len = math.ceil((ll-4)/4)

    def unpack(self, buf):
        super(RTCP, self).unpack(buf)
        if not self.version == VERSION or not self.p == 0:
            raise dpkt.UnpackError('invalid %s: %r' %
                                  (self.__class__.__name__, buf))
        # self.csrc = buf[self.__hdr_len__:self.__hdr_len__ + 4]
        buf = self.data
        if  self.pt == PT_SR:
            self.info = SRInfo(buf)
            buf = buf[self.info.__hdr_len__:]
            for _ in range(self.cc):
                sr = Report(buf)
                buf = buf[sr.__hdr_len__:]
                self.reports.append(sr)
            self.data = buf[0:len(self) - self.__hdr_len__ - self.info.__hdr_len__ - self.cc * 24]
        elif  self.pt == PT_RR:
            self.info = RRInfo(buf)
            buf = buf[self.info.__hdr_len__:]
            self.reports = []
            for _ in range(self.cc):
                rr = Report(buf)
                buf = buf[rr.__hdr_len__:]
                self.reports.append(rr)
            self.data = b''
        elif  self.pt == PT_SDES:
            # TODO
            self.data = buf[0:len(self) - self.__hdr_len__ ]
        elif  self.pt == PT_BYE:
            # TODO
            self.data = buf[0:len(self) - self.__hdr_len__ ]
        elif  self.pt == PT_APP:
            # TODO
            self.data = buf[0:len(self) - self.__hdr_len__ ]
        elif  self.pt == PT_XR:
            self.info = RRInfo(buf) # Only cssr in info...
            buf = buf[self.info.__hdr_len__:]
            xr = XReport(buf[0:len(self)-self.info.__hdr_len__]) # Limiting buffer length is important in this case to determine the number of blocks.
            self.reports.append(xr)
            self.data = b''
        else:
            raise dpkt.UnpackError('invalid %s: %r' %
                                  (self.__class__.__name__, buf))

    def __init__(self, *args, **kwargs):
        self.info = None
        self.reports = []
        self.data = b''
        super(RTCP, self).__init__(*args, **kwargs)

    def __len__(self):
        return self.len * 4 + 4

    def __bytes__(self):
        bb = self.pack_hdr()
        if self.info:
            bb = bb + self.info.pack_hdr()
        if len(self.reports)>0:
            for _ in range(self.cc):
                bb = bb + bytes(self.reports[_])
        return  bb + self.data
                                  
def test_RTCP_SR():
    RTCP_SR = RTCP(
        b'\x81\xc8\x00\x0c\x28\xaa\x34\x78\xe6\xa2\x5f\xa9\x29\x03\xd3\x2f'
        b'\x00\x00\x87\x00\x00\x00\x00\x09\x00\x00\x00\xd2\x58\xfe\xf5\x57'
        b'\x00\x00\x00\x00\x00\x00\x3a\xb4\x00\x00\x03\x11\x5f\xa8\x87\x09'
        b'\x00\x00\x6b\x75'
    )
    assert (RTCP_SR.version == 2)
    assert (RTCP_SR.p == 0)
    assert (RTCP_SR.cc == 1)
    assert (RTCP_SR.pt == PT_SR)
    assert (RTCP_SR.len == 12)
    assert (len(RTCP_SR) == 52)
    assert (RTCP_SR.info)
    assert (RTCP_SR.info.ssrc == 0x28aa3478)
    assert (RTCP_SR.info.ntp_ts_msw == 3869401001)
    assert (RTCP_SR.info.ntp_ts_lsw == 688116527 )
    assert (RTCP_SR.info.rtp_ts == 34560)
    assert (RTCP_SR.info.pkts == 9)
    assert (RTCP_SR.info.octs == 210)
    assert (len(RTCP_SR.reports)==1)
    assert (RTCP_SR.reports[0].ssrc==0x58fef557)
    assert (RTCP_SR.reports[0].lossfrac==0)
    assert (RTCP_SR.reports[0].losscumm==0)
    assert (RTCP_SR.reports[0].seq==15028)
    assert (RTCP_SR.reports[0].jitter==785)
    assert (RTCP_SR.reports[0].lsr==1604880137)
    assert (RTCP_SR.reports[0].dlsr==27509)
    assert (RTCP_SR.data==b'')
    assert (bytes(RTCP_SR) == (
        b'\x81\xc8\x00\x0c\x28\xaa\x34\x78\xe6\xa2\x5f\xa9\x29\x03\xd3\x2f'
        b'\x00\x00\x87\x00\x00\x00\x00\x09\x00\x00\x00\xd2\x58\xfe\xf5\x57'
        b'\x00\x00\x00\x00\x00\x00\x3a\xb4\x00\x00\x03\x11\x5f\xa8\x87\x09'
        b'\x00\x00\x6b\x75'
    ))

def test_build_RTCP_SR():
    RTCP_SR = RTCP(pt = PT_SR)
    RTCP_SR.addInfo( 
        SRInfo( 
            ssrc = 0x28aa3478,
            ntp_ts_msw = 3869401001,
            ntp_ts_lsw = 688116527,
            rtp_ts = 34560,
            pkts = 9,
            octs = 210
        )
    )
    RTCP_SR.addReport(
        Report(
            ssrc = 0x58fef557,
            lossfrac=0,
            losscumm=0,
            seq=15028,
            jitter=785,
            lsr=1604880137,
            dlsr=27509
        )
    )
    assert (len(RTCP_SR.reports)==1)
    assert (bytes(RTCP_SR) == (
        b'\x81\xc8\x00\x0c\x28\xaa\x34\x78\xe6\xa2\x5f\xa9\x29\x03\xd3\x2f'
        b'\x00\x00\x87\x00\x00\x00\x00\x09\x00\x00\x00\xd2\x58\xfe\xf5\x57'
        b'\x00\x00\x00\x00\x00\x00\x3a\xb4\x00\x00\x03\x11\x5f\xa8\x87\x09'
        b'\x00\x00\x6b\x75'
    ))

def test_RTCP_RR():
    RTCP_RR = RTCP(
        b'\x81\xc9\x00\x07\x28\xaa\x34\x78\x58\xfe\xf5\x57\x00\x00\x00\x00'
        b'\x00\x00\x3a\xaa\x00\x00\x00\x00\x5f\xa8\x0b\xa7\x00\x00\x50\x37'
    )
    assert (RTCP_RR.version == 2)
    assert (RTCP_RR.p == 0)
    assert (RTCP_RR.cc == 1)
    assert (RTCP_RR.pt == PT_RR)
    assert (RTCP_RR.len == 7)
    assert (len(RTCP_RR) == 32)
    assert (RTCP_RR.info)
    assert (RTCP_RR.info.ssrc == 0x28aa3478)
    assert (len(RTCP_RR.reports)==1)
    assert (RTCP_RR.reports[0].ssrc==0x58fef557)
    assert (RTCP_RR.reports[0].lossfrac==0)
    assert (RTCP_RR.reports[0].losscumm==0)
    assert (RTCP_RR.reports[0].seq==15018)
    assert (RTCP_RR.reports[0].jitter==0)
    assert (RTCP_RR.reports[0].lsr==1604848551)
    assert (RTCP_RR.reports[0].dlsr==20535)
    assert (RTCP_RR.data==b'')
    assert (bytes(RTCP_RR) == (
        b'\x81\xc9\x00\x07\x28\xaa\x34\x78\x58\xfe\xf5\x57\x00\x00\x00\x00'
        b'\x00\x00\x3a\xaa\x00\x00\x00\x00\x5f\xa8\x0b\xa7\x00\x00\x50\x37'
    ))

def test_build_RTCP_RR():
    RTCP_RR = RTCP( pt = PT_RR )
    RTCP_RR.addInfo( 
        RRInfo( 
            ssrc = 0x28aa3478
        )
    )
    RTCP_RR.addReport(
        Report(
            ssrc = 0x58fef557,
            lossfrac=0,
            losscumm=0,
            seq=15018,
            jitter=0,
            lsr=1604848551,
            dlsr=20535
        )
    )
    assert (len(RTCP_RR.reports)==1)
    assert (bytes(RTCP_RR) == (
        b'\x81\xc9\x00\x07\x28\xaa\x34\x78\x58\xfe\xf5\x57\x00\x00\x00\x00'
        b'\x00\x00\x3a\xaa\x00\x00\x00\x00\x5f\xa8\x0b\xa7\x00\x00\x50\x37'
    ))

def test_RTCP_SDES():
    RTCP_SDES = RTCP(
        b'\x81\xca\x00\x06\x28\xaa\x34\x78\x01\x10\x35\x36\x38\x30\x65\x39'
        b'\x30\x61\x36\x62\x37\x63\x38\x34\x36\x37\x00\x00'
    )
    assert (RTCP_SDES.version == 2)
    assert (RTCP_SDES.p == 0)
    assert (RTCP_SDES.cc == 1)
    assert (RTCP_SDES.pt == PT_SDES)
    assert (RTCP_SDES.len == 6)
    assert (len(RTCP_SDES) == 28)
    assert (not RTCP_SDES.info)
    assert (len(RTCP_SDES.reports)==0)
    assert (RTCP_SDES.data==(
        b'\x28\xaa\x34\x78\x01\x10\x35\x36\x38\x30\x65\x39'
        b'\x30\x61\x36\x62\x37\x63\x38\x34\x36\x37\x00\x00'
    ))
    assert (bytes(RTCP_SDES) == (
        b'\x81\xca\x00\x06\x28\xaa\x34\x78\x01\x10\x35\x36\x38\x30\x65\x39'
        b'\x30\x61\x36\x62\x37\x63\x38\x34\x36\x37\x00\x00'
    ))

def test_build_RTCP_SDES():
    RTCP_SDES = RTCP(
        pt = PT_SDES,
        cc = 1 # Chunck decoding not implemented need to hardcode count.
    )
    RTCP_SDES.addData(
        (
            b'\x28\xaa\x34\x78\x01\x10\x35\x36\x38\x30\x65\x39'
            b'\x30\x61\x36\x62\x37\x63\x38\x34\x36\x37\x00\x00'
        ))
    assert (not RTCP_SDES.info)
    assert (len(RTCP_SDES.reports)==0)
    assert (bytes(RTCP_SDES) == (
        b'\x81\xca\x00\x06\x28\xaa\x34\x78\x01\x10\x35\x36\x38\x30\x65\x39'
        b'\x30\x61\x36\x62\x37\x63\x38\x34\x36\x37\x00\x00'
    ))


def test_RTCP_XR():
    RTCP_XR = RTCP(
        b'\x81\xcf\x00\x1b\x58\xfe\xf5\x57\x04\x00\x00\x02\xe6\xa2\x5f\xaa'
        b'\x71\x4e\x01\xaf\x05\x00\x00\x03\x28\xaa\x34\x78\x5f\xa9\x29\x04'
        b'\x00\x01\x69\x35\x06\xe0\x00\x09\x28\xaa\x34\x78\x2a\x13\x2a\x1a'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x51\x00\x00\x02\xff'
        b'\x00\x00\x01\xbf\x00\x00\x00\xdd\x00\x00\x00\x00\x07\x00\x00\x08'
        b'\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x01\xaa'
        b'\x7f\x7f\x7f\x10\x7f\x7f\x7f\x7f\xb7\x00\x00\x78\x00\x78\x05\xdc'
    )
    assert (RTCP_XR.version == 2)
    assert (RTCP_XR.p == 0)
    assert (RTCP_XR.cc == 1)
    assert (RTCP_XR.pt == PT_XR)
    assert (RTCP_XR.len == 27)
    assert (len(RTCP_XR) == 112)
    assert (RTCP_XR.info)
    assert (RTCP_XR.info.ssrc == 0x58fef557)
    assert (len(RTCP_XR.reports)==1)
    assert (len(RTCP_XR.reports[0].blocks)==4)
    assert (RTCP_XR.reports[0].blocks[0].type == BT_RCVR)
    assert (RTCP_XR.reports[0].blocks[0].spec == 0)
    assert (RTCP_XR.reports[0].blocks[0].len == 2)
    assert (RTCP_XR.reports[0].blocks[0].block.ntp_ts_msw == 0xe6a25faa)
    assert (RTCP_XR.reports[0].blocks[0].block.ntp_ts_lsw == 0x714e01af)
    assert (RTCP_XR.reports[0].blocks[1].type == BT_DLRR)
    assert (RTCP_XR.reports[0].blocks[1].spec == 0)
    assert (RTCP_XR.reports[0].blocks[1].len == 3)
    assert (RTCP_XR.reports[0].blocks[1].block.data == b'\x28\xaa\x34\x78\x5f\xa9\x29\x04\x00\x01\x69\x35')
    assert (RTCP_XR.reports[0].blocks[2].type == BT_STAT)
    assert (RTCP_XR.reports[0].blocks[2].spec == 0xe0)
    assert (RTCP_XR.reports[0].blocks[2].len == 9 )
    assert (RTCP_XR.reports[0].blocks[2].block.ssrc == 0x28aa3478)
    assert (RTCP_XR.reports[0].blocks[2].block.beg_seq == 10771)
    assert (RTCP_XR.reports[0].blocks[2].block.end_seq == 10778)
    assert (RTCP_XR.reports[0].blocks[2].block.loss == 0)
    assert (RTCP_XR.reports[0].blocks[2].block.dupl == 0)
    assert (RTCP_XR.reports[0].blocks[2].block.min_jitter == 81)
    assert (RTCP_XR.reports[0].blocks[2].block.max_jitter == 767)
    assert (RTCP_XR.reports[0].blocks[2].block.avg_jitter == 447)
    assert (RTCP_XR.reports[0].blocks[2].block.dev_jitter == 221)
    assert (RTCP_XR.reports[0].blocks[2].block.min_ttl_or_hl == 0)
    assert (RTCP_XR.reports[0].blocks[2].block.max_ttl_or_hl == 0)
    assert (RTCP_XR.reports[0].blocks[2].block.mean_ttl_or_hl == 0)
    assert (RTCP_XR.reports[0].blocks[2].block.dev_ttl_or_hl == 0)
    assert (RTCP_XR.reports[0].blocks[3].type == BT_VOIP)
    assert (RTCP_XR.reports[0].blocks[3].spec == 0)
    assert (RTCP_XR.reports[0].blocks[3].len == 8 )
    assert (RTCP_XR.reports[0].blocks[3].block.ssrc == 0x28aa3478 )
    assert (RTCP_XR.reports[0].blocks[3].block.loss_rate == 0 )
    assert (RTCP_XR.reports[0].blocks[3].block.disc_rate == 0 )
    assert (RTCP_XR.reports[0].blocks[3].block.burst_density == 0 )
    assert (RTCP_XR.reports[0].blocks[3].block.gap_density == 0 )
    assert (RTCP_XR.reports[0].blocks[3].block.burst_duration == 0 )
    assert (RTCP_XR.reports[0].blocks[3].block.gap_duration == 0 )
    assert (RTCP_XR.reports[0].blocks[3].block.rtt == 72 )
    assert (RTCP_XR.reports[0].blocks[3].block.end_sys_delay == 426 )
    assert (RTCP_XR.reports[0].blocks[3].block.signal_level == 127 )
    assert (RTCP_XR.reports[0].blocks[3].block.noise_level == 127 )
    assert (RTCP_XR.reports[0].blocks[3].block.RERL == 127 )
    assert (RTCP_XR.reports[0].blocks[3].block.Gmin == 16 )
    assert (RTCP_XR.reports[0].blocks[3].block.RFactor == 127 )
    assert (RTCP_XR.reports[0].blocks[3].block.ext_RFactor == 127 )
    assert (RTCP_XR.reports[0].blocks[3].block.MOS_LQ == 127 )
    assert (RTCP_XR.reports[0].blocks[3].block.MOS_CQ == 127 )
    assert (RTCP_XR.reports[0].blocks[3].block.RX_config == 0xb7 )
    assert (RTCP_XR.reports[0].blocks[3].block.reserved == 0 )
    assert (RTCP_XR.reports[0].blocks[3].block.nominal_jitter == 120 )
    assert (RTCP_XR.reports[0].blocks[3].block.max_jitter == 120 )
    assert (RTCP_XR.reports[0].blocks[3].block.abs_max_jitter == 1500 )
    assert (bytes(RTCP_XR) == (
        b'\x81\xcf\x00\x1b\x58\xfe\xf5\x57\x04\x00\x00\x02\xe6\xa2\x5f\xaa'
        b'\x71\x4e\x01\xaf\x05\x00\x00\x03\x28\xaa\x34\x78\x5f\xa9\x29\x04'
        b'\x00\x01\x69\x35\x06\xe0\x00\x09\x28\xaa\x34\x78\x2a\x13\x2a\x1a'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x51\x00\x00\x02\xff'
        b'\x00\x00\x01\xbf\x00\x00\x00\xdd\x00\x00\x00\x00\x07\x00\x00\x08'
        b'\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x01\xaa'
        b'\x7f\x7f\x7f\x10\x7f\x7f\x7f\x7f\xb7\x00\x00\x78\x00\x78\x05\xdc'
    ))

def test_build_RTCP_XR():
    RTCP_XR = RTCP(pt = PT_XR)
    RTCP_XR.addInfo( 
        RRInfo( 
            ssrc = 0x58fef557
        )
    )
    xr = XReport()
    blk = XReportBlock()
    blk.setBlock(XBlockRcvr(ntp_ts_msw = 0xe6a25faa,ntp_ts_lsw = 0x714e01af))
    xr.addBlock(blk) 
    blk = XReportBlock()
    blk.setBlock(XBlockDlrr(data = b'\x28\xaa\x34\x78\x5f\xa9\x29\x04\x00\x01\x69\x35'))
    xr.addBlock(blk) 
    blk = XReportBlock(spec=0xe0)
    blk.setBlock(
        XBlockStat( 
            ssrc = 0x28aa3478,
            beg_seq = 10771,
            end_seq = 10778,
            loss = 0,
            dupl = 0,
            min_jitter = 81,
            max_jitter = 767,
            avg_jitter = 447,
            dev_jitter = 221,
            min_ttl_or_hl = 0,
            max_ttl_or_hl = 0,
            mean_ttl_or_hl = 0,
            dev_ttl_or_hl = 0
        )
    )
    xr.addBlock(blk) 
    blk = XReportBlock()
    blk.setBlock(
        XBlockVoip( 
            ssrc = 0x28aa3478,
            loss_rate = 0,
            disc_rate = 0,
            burst_density = 0,
            gap_density = 0,
            burst_duration = 0,
            gap_duration = 0,
            rtt = 72,
            end_sys_delay = 426,
            signal_level = 127,
            noise_level = 127,
            RERL = 127,
            Gmin = 16,
            RFactor = 127,
            ext_RFactor = 127,
            MOS_LQ = 127,
            MOS_CQ = 127,
            RX_config = 0xb7,
            nominal_jitter = 120,
            max_jitter = 120,
            abs_max_jitter = 1500
        )
    )
    xr.addBlock(blk) 
    RTCP_XR.addReport(xr)
    assert (len(RTCP_XR.reports)==1)
    assert (len(RTCP_XR.reports[0].blocks)==4)
    assert (bytes(RTCP_XR) == (
        b'\x81\xcf\x00\x1b\x58\xfe\xf5\x57\x04\x00\x00\x02\xe6\xa2\x5f\xaa'
        b'\x71\x4e\x01\xaf\x05\x00\x00\x03\x28\xaa\x34\x78\x5f\xa9\x29\x04'
        b'\x00\x01\x69\x35\x06\xe0\x00\x09\x28\xaa\x34\x78\x2a\x13\x2a\x1a'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x51\x00\x00\x02\xff'
        b'\x00\x00\x01\xbf\x00\x00\x00\xdd\x00\x00\x00\x00\x07\x00\x00\x08'
        b'\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x01\xaa'
        b'\x7f\x7f\x7f\x10\x7f\x7f\x7f\x7f\xb7\x00\x00\x78\x00\x78\x05\xdc'
    ))


def test_build_RTCP_XR_Blocks():
    blk = XReportBlock()
    blk.setBlock(XBlockLoss())
    assert(blk.type == BT_LOSS)
    blk.setBlock(XBlockDupl())
    assert(blk.type == BT_DUPL)
    blk.setBlock(XBlockRcvt())
    assert(blk.type == BT_RCVT)
    try:
        assert( blk.setBlock(XReportBlock()) and False )
    except ValueError:
        pass

    blk = XReportBlock(b'\x01\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00')
    assert(isinstance(blk.block, XBlockLoss))
    blk = XReportBlock(b'\x02\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00')
    assert(isinstance(blk.block, XBlockDupl))
    blk = XReportBlock(b'\x03\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00')
    assert(isinstance(blk.block, XBlockRcvt))
    try:
        assert( XReportBlock(b'\x22\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00') and False )
    except ValueError:
        pass

def test_build_RTCP_XR_Report():
    try:
        assert(XReport(b'\x22\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00') and False)
    except ValueError:
        pass

    buf = ( 
            b'\x03\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x22\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00' 
        )
    xr = XReport(buf)        
    assert(len(xr.blocks)==1)
    assert(buf[len(xr):] == b'\x22\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00')

def test_build_RTCP_addInfo():
    RTCP_SDES = RTCP( pt = PT_SDES )
    try:
        assert(
            RTCP_SDES.addInfo( 
                RRInfo( 
                    ssrc = 0x28aa3478
                )
            ) and False )
    except ValueError:
        pass

    RTCP_BYE = RTCP( pt = PT_BYE )
    try:
        assert (
            RTCP_BYE.addInfo( 
                RRInfo( 
                    ssrc = 0x28aa3478
                )
            ) and False
        )
    except ValueError:
        pass

    RTCP_APP = RTCP( pt = PT_APP )
    try:
        assert(
            RTCP_APP.addInfo( 
                RRInfo( 
                    ssrc = 0x28aa3478
                )
            ) and False
        )
    except ValueError:
        pass

    RTCP_SR = RTCP(pt = PT_SR)
    RTCP_SR.addReport(
        Report(
            ssrc = 0x58fef557,
            lossfrac=0,
            losscumm=0,
            seq=15028,
            jitter=785,
            lsr=1604880137,
            dlsr=27509
        )
    )
    assert (len(RTCP_SR.reports)==1)
    RTCP_SR.addInfo( 
        SRInfo( 
            ssrc = 0x28aa3478,
            ntp_ts_msw = 3869401001,
            ntp_ts_lsw = 688116527,
            rtp_ts = 34560,
            pkts = 9,
            octs = 210
        )
    )
    assert (bytes(RTCP_SR) == (
        b'\x81\xc8\x00\x0c\x28\xaa\x34\x78\xe6\xa2\x5f\xa9\x29\x03\xd3\x2f'
        b'\x00\x00\x87\x00\x00\x00\x00\x09\x00\x00\x00\xd2\x58\xfe\xf5\x57'
        b'\x00\x00\x00\x00\x00\x00\x3a\xb4\x00\x00\x03\x11\x5f\xa8\x87\x09'
        b'\x00\x00\x6b\x75'
    ))
    RTCP_XR = RTCP(pt = PT_XR)
    xr = XReport()
    blk = XReportBlock()
    blk.setBlock(XBlockRcvr(ntp_ts_msw = 0xe6a25faa,ntp_ts_lsw = 0x714e01af))
    xr.addBlock(blk) 
    blk = XReportBlock()
    blk.setBlock(XBlockDlrr(data = b'\x28\xaa\x34\x78\x5f\xa9\x29\x04\x00\x01\x69\x35'))
    xr.addBlock(blk) 
    blk = XReportBlock(spec=0xe0)
    blk.setBlock(
        XBlockStat( 
            ssrc = 0x28aa3478,
            beg_seq = 10771,
            end_seq = 10778,
            loss = 0,
            dupl = 0,
            min_jitter = 81,
            max_jitter = 767,
            avg_jitter = 447,
            dev_jitter = 221,
            min_ttl_or_hl = 0,
            max_ttl_or_hl = 0,
            mean_ttl_or_hl = 0,
            dev_ttl_or_hl = 0
        )
    )
    xr.addBlock(blk) 
    blk = XReportBlock()
    blk.setBlock(
        XBlockVoip( 
            ssrc = 0x28aa3478,
            loss_rate = 0,
            disc_rate = 0,
            burst_density = 0,
            gap_density = 0,
            burst_duration = 0,
            gap_duration = 0,
            rtt = 72,
            end_sys_delay = 426,
            signal_level = 127,
            noise_level = 127,
            RERL = 127,
            Gmin = 16,
            RFactor = 127,
            ext_RFactor = 127,
            MOS_LQ = 127,
            MOS_CQ = 127,
            RX_config = 0xb7,
            nominal_jitter = 120,
            max_jitter = 120,
            abs_max_jitter = 1500
        )
    )
    xr.addBlock(blk) 
    RTCP_XR.addReport(xr)
    assert (len(RTCP_XR.reports)==1)
    assert (len(RTCP_XR.reports[0].blocks)==4)
    RTCP_XR.addInfo( 
        RRInfo( 
            ssrc = 0x58fef557
        )
    )
    assert (bytes(RTCP_XR) == (
        b'\x81\xcf\x00\x1b\x58\xfe\xf5\x57\x04\x00\x00\x02\xe6\xa2\x5f\xaa'
        b'\x71\x4e\x01\xaf\x05\x00\x00\x03\x28\xaa\x34\x78\x5f\xa9\x29\x04'
        b'\x00\x01\x69\x35\x06\xe0\x00\x09\x28\xaa\x34\x78\x2a\x13\x2a\x1a'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x51\x00\x00\x02\xff'
        b'\x00\x00\x01\xbf\x00\x00\x00\xdd\x00\x00\x00\x00\x07\x00\x00\x08'
        b'\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x01\xaa'
        b'\x7f\x7f\x7f\x10\x7f\x7f\x7f\x7f\xb7\x00\x00\x78\x00\x78\x05\xdc'
    ))

def test_build_RTCP_addReport():
    RTCP_SDES = RTCP( pt = PT_SDES )
    try:
        assert(RTCP_SDES.addReport(Report()) and False)
    except ValueError:
        pass

    RTCP_BYE = RTCP( pt = PT_BYE )
    try:
        assert(RTCP_BYE.addReport(Report()) and False)
    except ValueError:
        pass

    RTCP_APP = RTCP( pt = PT_APP )
    try:
        assert(RTCP_APP.addReport(Report()) and False)
    except ValueError:
        pass


def test_build_RTCP_addData():
    RTCP_RR = RTCP( pt = PT_RR )
    try:
        assert(RTCP_RR.addData(b'\x22\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00') and False)
    except ValueError:
        pass

    RTCP_XR = RTCP( pt = PT_XR )
    try:
        assert(RTCP_XR.addData(b'\x22\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00') and False)
    except ValueError:
        pass

    RTCP_SR = RTCP(pt = PT_SR)
    RTCP_SR.addReport(
        Report(
            ssrc = 0x58fef557,
            lossfrac=0,
            losscumm=0,
            seq=15028,
            jitter=785,
            lsr=1604880137,
            dlsr=27509
        )
    )
    assert (len(RTCP_SR.reports)==1)
    RTCP_SR.addInfo( 
        SRInfo( 
            ssrc = 0x28aa3478,
            ntp_ts_msw = 3869401001,
            ntp_ts_lsw = 688116527,
            rtp_ts = 34560,
            pkts = 9,
            octs = 210
        )
    )
    RTCP_SR.addData(b'\x22\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00')
    assert (bytes(RTCP_SR) == (
        b'\x81\xc8\x00\x10\x28\xaa\x34\x78\xe6\xa2\x5f\xa9\x29\x03\xd3\x2f'
        b'\x00\x00\x87\x00\x00\x00\x00\x09\x00\x00\x00\xd2\x58\xfe\xf5\x57'
        b'\x00\x00\x00\x00\x00\x00\x3a\xb4\x00\x00\x03\x11\x5f\xa8\x87\x09'
        b'\x00\x00\x6b\x75'
        b'\x22\x00\x00\x03\x28\xaa\x34\x78\x00\x00\x00\x00\x00\x00\x00\x00'
    ))

def test_RTCP_version_padding():
    try:
        assert(
            RTCP(
                b'\x41\xca\x00\x06\x28\xaa\x34\x78\x01\x10\x35\x36\x38\x30\x65\x39'
                b'\x30\x61\x36\x62\x37\x63\x38\x34\x36\x37\x00\x00'
            ) and False
        )
    except dpkt.UnpackError:
        pass
    try:
        assert(
            RTCP(
                b'\xa1\xca\x00\x06\x28\xaa\x34\x78\x01\x10\x35\x36\x38\x30\x65\x39'
                b'\x30\x61\x36\x62\x37\x63\x38\x34\x36\x37\x00\x00'
            ) and False
        )
    except dpkt.UnpackError:
        pass


def test_RTCP_BYE():
    RTCP_BYE = RTCP(
        b'\x81\xcb\x00\x01\x58\xfe\xf5\x57'
    )
    assert (RTCP_BYE.version == 2)
    assert (RTCP_BYE.p == 0)
    assert (RTCP_BYE.cc == 1)
    assert (RTCP_BYE.pt == PT_BYE)
    assert (RTCP_BYE.len == 1)
    assert (len(RTCP_BYE) == 8)
    assert (not RTCP_BYE.info)
    assert (len(RTCP_BYE.reports)==0)
    assert (RTCP_BYE.data==(
        b'\x58\xfe\xf5\x57'
    ))
    assert (bytes(RTCP_BYE) == (
        b'\x81\xcb\x00\x01\x58\xfe\xf5\x57'
    ))


def test_RTCP_APP():
    RTCP_APP = RTCP(
        b'\x81\xcc\x00\x01\x58\xfe\xf5\x57'
    )
    assert (RTCP_APP.version == 2)
    assert (RTCP_APP.p == 0)
    assert (RTCP_APP.cc == 1)
    assert (RTCP_APP.pt == PT_APP)
    assert (RTCP_APP.len == 1)
    assert (len(RTCP_APP) == 8)
    assert (not RTCP_APP.info)
    assert (len(RTCP_APP.reports)==0)
    assert (RTCP_APP.data==(
        b'\x58\xfe\xf5\x57'
    ))
    assert (bytes(RTCP_APP) == (
        b'\x81\xcc\x00\x01\x58\xfe\xf5\x57'
    ))

def test_RTCP_FF():
    try:
        assert( RTCP(b'\x81\xff\x00\x01\x58\xfe\xf5\x57') and False)
    except dpkt.UnpackError:
        pass