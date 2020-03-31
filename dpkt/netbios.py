# $Id: netbios.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Network Basic Input/Output System."""
from __future__ import absolute_import

import struct

from . import dpkt
from . import dns
from .compat import compat_ord


def encode_name(name):
    """Return the NetBIOS first-level encoded name.

    Args:
        name (str): name to encode, 1 to 16 ASCII characters

    Returns:
        bytes: 32 bytes long encoded name
    """
    # add spaces if needed to make the name exactly 16 chars
    while len(name) < 16:
        name += '\x20'

    encoded_name = bytearray()
    for c in name:
        c = ord(c)
        encoded_name.append((c >> 4) + 0x41)
        encoded_name.append((c & 0x0f) + 0x41)
    return bytes(encoded_name)


def decode_name(nbname):
    """Return the NetBIOS first-level decoded nbname.

    Args:
        nbname (bytes): 32 bytes long first-level encoded name

    Returns:
        str: decoded name
    """
    if len(nbname) != 32:
        return nbname

    decoded_name = bytearray()
    for i in range(0, len(nbname), 2):
        decoded_name.append(
            ((compat_ord(nbname[i]) - 0x41) << 4) |
            ((compat_ord(nbname[i + 1]) - 0x41) & 0x0f))
    return (decoded_name.split(b'\x00', 1)[0]).decode('ascii')


# RR types
NS_A = 0x01  # IP address
NS_NS = 0x02  # Name Server
NS_NULL = 0x0A  # NULL
NS_NB = 0x20  # NetBIOS general Name Service
NS_NBSTAT = 0x21  # NetBIOS NODE STATUS

# RR classes
NS_IN = 1

# NBSTAT name flags
NS_NAME_G = 0x8000  # group name (as opposed to unique)
NS_NAME_DRG = 0x1000  # deregister
NS_NAME_CNF = 0x0800  # conflict
NS_NAME_ACT = 0x0400  # active
NS_NAME_PRM = 0x0200  # permanent

# NBSTAT service names
nbstat_svcs = {
    # (service, unique): list of ordered (name prefix, service name) tuples
    (0x00, 0): [('', 'Domain Name')],
    (0x00, 1): [('IS~', 'IIS'), ('', 'Workstation Service')],
    (0x01, 0): [('__MSBROWSE__', 'Master Browser')],
    (0x01, 1): [('', 'Messenger Service')],
    (0x03, 1): [('', 'Messenger Service')],
    (0x06, 1): [('', 'RAS Server Service')],
    (0x1B, 1): [('', 'Domain Master Browser')],
    (0x1C, 0): [('INet~Services', 'IIS'), ('', 'Domain Controllers')],
    (0x1D, 1): [('', 'Master Browser')],
    (0x1E, 0): [('', 'Browser Service Elections')],
    (0x1F, 1): [('', 'NetDDE Service')],
    (0x20, 1): [('Forte_$ND800ZA', 'DCA IrmaLan Gateway Server Service'),
                ('', 'File Server Service')],
    (0x21, 1): [('', 'RAS Client Service')],
    (0x22, 1): [('', 'Microsoft Exchange Interchange(MSMail Connector)')],
    (0x23, 1): [('', 'Microsoft Exchange Store')],
    (0x24, 1): [('', 'Microsoft Exchange Directory')],
    (0x2B, 1): [('', 'Lotus Notes Server Service')],
    (0x2F, 0): [('IRISMULTICAST', 'Lotus Notes')],
    (0x30, 1): [('', 'Modem Sharing Server Service')],
    (0x31, 1): [('', 'Modem Sharing Client Service')],
    (0x33, 0): [('IRISNAMESERVER', 'Lotus Notes')],
    (0x43, 1): [('', 'SMS Clients Remote Control')],
    (0x44, 1): [('', 'SMS Administrators Remote Control Tool')],
    (0x45, 1): [('', 'SMS Clients Remote Chat')],
    (0x46, 1): [('', 'SMS Clients Remote Transfer')],
    (0x4C, 1): [('', 'DEC Pathworks TCPIP service on Windows NT')],
    (0x52, 1): [('', 'DEC Pathworks TCPIP service on Windows NT')],
    (0x87, 1): [('', 'Microsoft Exchange MTA')],
    (0x6A, 1): [('', 'Microsoft Exchange IMC')],
    (0xBE, 1): [('', 'Network Monitor Agent')],
    (0xBF, 1): [('', 'Network Monitor Application')]
}


def node_to_service_name(name_service_flags):
    name, service, flags = name_service_flags
    try:
        unique = int(flags & NS_NAME_G == 0)
        for namepfx, svcname in nbstat_svcs[(service, unique)]:
            if name.startswith(namepfx):
                return svcname
    except KeyError:
        pass
    return ''


class NS(dns.DNS):
    """NetBIOS Name Service."""

    class Q(dns.DNS.Q):
        pass

    class RR(dns.DNS.RR):
        """NetBIOS resource record."""

        def unpack_rdata(self, buf, off):
            if self.type == NS_A:
                self.ip = self.rdata
            elif self.type == NS_NBSTAT:
                num = ord(self.rdata[0])
                off = 1
                l = []
                for i in range(num):
                    name = self.rdata[off:off + 15].split(None, 1)[0].split('\x00', 1)[0]
                    service = ord(self.rdata[off + 15])
                    off += 16
                    flags = struct.unpack('>H', self.rdata[off:off + 2])[0]
                    off += 2
                    l.append((name, service, flags))
                self.nodenames = l
                # XXX - skip stats

    # FIXME: dns.DNS.pack_name does not exist; dns.pack_name has a different signature
    def pack_name(self, buf, name):
        return dns.DNS.pack_name(self, buf, encode_name(name))

    # FIXME: dns.DNS.unpack_name does not exist; dns.unpack_name?
    def unpack_name(self, buf, off):
        name, off = dns.DNS.unpack_name(self, buf, off)
        return decode_name(name), off


class Session(dpkt.Packet):
    """NetBIOS Session Service."""
    __hdr__ = (
        ('type', 'B', 0),
        ('flags', 'B', 0),
        ('len', 'H', 0)
    )


SSN_MESSAGE = 0
SSN_REQUEST = 1
SSN_POSITIVE = 2
SSN_NEGATIVE = 3
SSN_RETARGET = 4
SSN_KEEPALIVE = 5


class Datagram(dpkt.Packet):
    """NetBIOS Datagram Service."""
    __hdr__ = (
        ('type', 'B', 0),
        ('flags', 'B', 0),
        ('id', 'H', 0),
        ('src', 'I', 0),
        ('sport', 'H', 0),
        ('len', 'H', 0),
        ('off', 'H', 0)
    )


DGRAM_UNIQUE = 0x10
DGRAM_GROUP = 0x11
DGRAM_BROADCAST = 0x12
DGRAM_ERROR = 0x13
DGRAM_QUERY = 0x14
DGRAM_POSITIVE = 0x15
DGRAM_NEGATIVE = 0x16


def test_encode_name():
    assert encode_name('The NetBIOS name') == b'FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF'
    assert encode_name('FRED') == b'EGFCEFEECACACACACACACACACACACACA'


def test_decode_name():
    assert decode_name(b'FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF') == 'The NetBIOS name'
    # original botched example from rfc1001
    assert decode_name(b'FEGHGFCAEOGFHEECEJEPFDCAHEGBGNGF') == 'Tge NetBIOS tame'


if __name__ == '__main__':
    test_encode_name()
    test_decode_name()
    print('Tests Successful...')
