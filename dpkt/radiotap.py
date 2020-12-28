# -*- coding: utf-8 -*-
"""Radiotap"""
from __future__ import print_function
from __future__ import absolute_import

from . import dpkt
from . import ieee80211

# Ref: http://www.radiotap.org
# Fields Ref: http://www.radiotap.org/defined-fields/all

# Present flags
_TSFT_SHIFT = 0
_FLAGS_SHIFT = 1
_RATE_SHIFT = 2
_CHANNEL_SHIFT = 3
_FHSS_SHIFT = 4
_ANT_SIG_SHIFT = 5
_ANT_NOISE_SHIFT = 6
_LOCK_QUAL_SHIFT = 7
_TX_ATTN_SHIFT = 8
_DB_TX_ATTN_SHIFT = 9
_DBM_TX_POWER_SHIFT = 10
_ANTENNA_SHIFT = 11
_DB_ANT_SIG_SHIFT = 12
_DB_ANT_NOISE_SHIFT = 13
_RX_FLAGS_SHIFT = 14
_CHANNELPLUS_SHIFT = 18
_EXT_SHIFT = 31

# Flags elements
_FLAGS_SIZE = 2
_CFP_FLAG_SHIFT = 0
_PREAMBLE_SHIFT = 1
_WEP_SHIFT = 2
_FRAG_SHIFT = 3
_FCS_SHIFT = 4
_DATA_PAD_SHIFT = 5
_BAD_FCS_SHIFT = 6
_SHORT_GI_SHIFT = 7

# Channel type
_CHAN_TYPE_SIZE = 4
_CHANNEL_TYPE_SHIFT = 4
_CCK_SHIFT = 5
_OFDM_SHIFT = 6
_TWO_GHZ_SHIFT = 7
_FIVE_GHZ_SHIFT = 8
_PASSIVE_SHIFT = 9
_DYN_CCK_OFDM_SHIFT = 10
_GFSK_SHIFT = 11
_GSM_SHIFT = 12
_STATIC_TURBO_SHIFT = 13
_HALF_RATE_SHIFT = 14
_QUARTER_RATE_SHIFT = 15

# Flags offsets and masks
_FCS_SHIFT = 1
_FCS_MASK = 0x10


class Radiotap(dpkt.Packet):
    """Radiotap.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of Radiotap.
        TODO.
    """

    __hdr__ = (
        ('version', 'B', 0),
        ('pad', 'B', 0),
        ('length', 'H', 0),
    )

    __byte_order__ = '<'

    def is_present(self, bit):
        index = bit // 8
        mask = 1 << (bit % 8)
        return self.present_flags[index] & mask

    @property
    def tsft_present(self):
        return self.is_present(_TSFT_SHIFT)

    @tsft_present.setter
    def tsft_present(self, val):
        self.present_flags |= val << _TSFT_SHIFT

    @property
    def flags_present(self):
        return self.is_present(_FLAGS_SHIFT)

    @flags_present.setter
    def flags_present(self, val):
        self.present_flags |= val << _FLAGS_SHIFT

    @property
    def rate_present(self):
        return self.is_present(_RATE_SHIFT)

    @rate_present.setter
    def rate_present(self, val):
        self.present_flags |= val << _RATE_SHIFT

    @property
    def channel_present(self):
        return self.is_present(_CHANNEL_SHIFT)

    @channel_present.setter
    def channel_present(self, val):
        self.present_flags |= val << _CHANNEL_SHIFT

    @property
    def fhss_present(self):
        return self.is_present(_FHSS_SHIFT)

    @fhss_present.setter
    def fhss_present(self, val):
        self.present_flags |= val << _FHSS_SHIFT

    @property
    def ant_sig_present(self):
        return self.is_present(_ANT_SIG_SHIFT)

    @ant_sig_present.setter
    def ant_sig_present(self, val):
        self.present_flags |= val << _ANT_SIG_SHIFT

    @property
    def ant_noise_present(self):
        return self.is_present(_ANT_NOISE_SHIFT)

    @ant_noise_present.setter
    def ant_noise_present(self, val):
        self.present_flags |= val << _ANT_NOISE_SHIFT

    @property
    def lock_qual_present(self):
        return self.is_present(_LOCK_QUAL_SHIFT)

    @lock_qual_present.setter
    def lock_qual_present(self, val):
        self.present_flags |= val << _LOCK_QUAL_SHIFT

    @property
    def tx_attn_present(self):
        return self.is_present(_TX_ATTN_SHIFT)

    @tx_attn_present.setter
    def tx_attn_present(self, val):
        self.present_flags |= val << _TX_ATTN_SHIFT

    @property
    def db_tx_attn_present(self):
        return self.is_present(_DB_TX_ATTN_SHIFT)

    @db_tx_attn_present.setter
    def db_tx_attn_present(self, val):
        self.present_flags |= val << _DB_TX_ATTN_SHIFT

    @property
    def dbm_tx_power_present(self):
        return self.is_present(_DBM_TX_POWER_SHIFT)

    @dbm_tx_power_present.setter
    def dbm_tx_power_present(self, val):
        self.present_flags |= val << _DBM_TX_POWER_SHIFT

    @property
    def ant_present(self):
        return self.is_present(_ANTENNA_SHIFT)

    @ant_present.setter
    def ant_present(self, val):
        self.present_flags |= val << _ANTENNA_SHIFT

    @property
    def db_ant_sig_present(self):
        return self.is_present(_DB_ANT_SIG_SHIFT)

    @db_ant_sig_present.setter
    def db_ant_sig_present(self, val):
        self.present_flags |= val << _DB_ANT_SIG_SHIFT

    @property
    def db_ant_noise_present(self):
        return self.is_present(_DB_ANT_NOISE_SHIFT)

    @db_ant_noise_present.setter
    def db_ant_noise_present(self, val):
        self.present_flags |= val << _DB_ANT_NOISE_SHIFT

    @property
    def rx_flags_present(self):
        return self.is_present(_RX_FLAGS_SHIFT)

    @rx_flags_present.setter
    def rx_flags_present(self, val):
        self.present_flags |= val << _RX_FLAGS_SHIFT

    @property
    def chanplus_present(self):
        return self.is_present(_CHANNELPLUS_SHIFT)

    @chanplus_present.setter
    def chanplus_present(self, val):
        self.present_flags |= val << _CHANNELPLUS_SHIFT

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.data = buf[self.length:]
        
        self.fields = []
        buf = buf[self.__hdr_len__:]

        self.present_flags = bytearray(buf[:4])
        buf = buf[4:]
        ext_bit = _EXT_SHIFT
        while self.is_present(ext_bit):
            self.present_flags = self.present_flags + bytearray(buf[:4])
            buf = buf[4:]
            ext_bit += 32

        # decode each field into self.<name> (eg. self.tsft) as well as append it self.fields list
        field_decoder = [
            ('tsft', self.tsft_present, self.TSFT),
            ('flags', self.flags_present, self.Flags),
            ('rate', self.rate_present, self.Rate),
            ('channel', self.channel_present, self.Channel),
            ('fhss', self.fhss_present, self.FHSS),
            ('ant_sig', self.ant_sig_present, self.AntennaSignal),
            ('ant_noise', self.ant_noise_present, self.AntennaNoise),
            ('lock_qual', self.lock_qual_present, self.LockQuality),
            ('tx_attn', self.tx_attn_present, self.TxAttenuation),
            ('db_tx_attn', self.db_tx_attn_present, self.DbTxAttenuation),
            ('dbm_tx_power', self.dbm_tx_power_present, self.DbmTxPower),
            ('ant', self.ant_present, self.Antenna),
            ('db_ant_sig', self.db_ant_sig_present, self.DbAntennaSignal),
            ('db_ant_noise', self.db_ant_noise_present, self.DbAntennaNoise),
            ('rx_flags', self.rx_flags_present, self.RxFlags)
        ]

        offset = self.__hdr_len__ + len(self.present_flags)

        for name, present_bit, parser in field_decoder:
            if present_bit:
                if parser.__alignment__ > 1:
                    padding = offset % parser.__alignment__
                    buf = buf[padding:]
                    offset += padding
                field = parser(buf)
                field.data = b''
                setattr(self, name, field)
                self.fields.append(field)
                buf = buf[len(field):]

        if len(self.data) > 0:
            if self.flags_present and self.flags.fcs:
                self.data = ieee80211.IEEE80211(self.data, fcs=self.flags.fcs)
            else:
                self.data = ieee80211.IEEE80211(self.data)

    class RadiotapField(dpkt.Packet):
        __alignment__ = 1
        __byte_order__ = '<'

    class Antenna(RadiotapField):
        __hdr__ = (
            ('index', 'B', 0),
        )

    class AntennaNoise(RadiotapField):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class AntennaSignal(RadiotapField):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class Channel(RadiotapField):
        __alignment__ = 2
        __hdr__ = (
            ('freq', 'H', 0),
            ('flags', 'H', 0),
        )

    class FHSS(RadiotapField):
        __hdr__ = (
            ('set', 'B', 0),
            ('pattern', 'B', 0),
        )

    class Flags(RadiotapField):
        __hdr__ = (
            ('val', 'B', 0),
        )

        @property
        def fcs(self): return (self.val & _FCS_MASK) >> _FCS_SHIFT

        # TODO statement seems to have no effect
        @fcs.setter
        def fcs(self, v): (v << _FCS_SHIFT) | (self.val & ~_FCS_MASK)


    class LockQuality(RadiotapField):
        __alignment__ = 2
        __hdr__ = (
            ('val', 'H', 0),
        )

    class RxFlags(RadiotapField):
        __alignment__ = 2
        __hdr__ = (
            ('val', 'H', 0),
        )

    class Rate(RadiotapField):
        __hdr__ = (
            ('val', 'B', 0),
        )

    class TSFT(RadiotapField):
        __alignment__ = 8
        __hdr__ = (
            ('usecs', 'Q', 0),
        )

    class TxAttenuation(RadiotapField):
        __alignment__ = 2
        __hdr__ = (
            ('val', 'H', 0),
        )

    class DbTxAttenuation(RadiotapField):
        __alignment__ = 2
        __hdr__ = (
            ('db', 'H', 0),
        )

    class DbAntennaNoise(RadiotapField):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class DbAntennaSignal(RadiotapField):
        __hdr__ = (
            ('db', 'B', 0),
        )

    class DbmTxPower(RadiotapField):
        __hdr__ = (
            ('dbm', 'B', 0),
        )

    class ChannelPlus(RadiotapField):
        __alignment__ = 4
        __hdr__ = (
            ('flags', 'I', 0),
            ('freq', 'H', 0),
            ('channel', 'B', 0),
            ('maxpower', 'B', 0),
        )


def test_Radiotap():
    s = bytearray.fromhex('000030002f4000a0200800a0200800a020080000000000000884bdac2800000010028509a000a5000000a1009f01a102')
    rad = Radiotap(s)
    assert(rad.version == 0)
    assert(rad.present_flags == bytearray.fromhex('2f4000a0200800a0200800a020080000'))
    assert(rad.tsft_present)
    assert(rad.flags_present)
    assert(rad.rate_present)
    assert(rad.channel_present)
    assert(not rad.fhss_present)
    assert(rad.ant_sig_present)
    assert(not rad.ant_noise_present)
    assert(not rad.lock_qual_present)
    assert(not rad.db_tx_attn_present)
    assert(not rad.dbm_tx_power_present)
    assert(not rad.ant_present)
    assert(not rad.db_ant_sig_present)
    assert(not rad.db_ant_noise_present)
    assert(rad.rx_flags_present)
    assert(rad.channel.freq == 2437)
    assert(rad.channel.flags == 0x00a0)
    assert(len(rad.fields) == 6)
    assert(rad.flags_present)
    assert(rad.flags.fcs)


if __name__ == '__main__':
    test_Radiotap()
    print('Tests Successful...')
