"""Various Utility Functions"""
import socket
from .compat import compat_ord


def mac_to_str(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def test_utils():
    """Test the utility methods"""

    print(mac_to_str(b'\x01\x02\x03\x04\x05\x06'))
    assert mac_to_str(b'\x01\x02\x03\x04\x05\x06') == '01:02:03:04:05:06'
    print(inet_to_str(b'\x91\xfe\xa0\xed'))
    assert inet_to_str(b'\x91\xfe\xa0\xed') == '145.254.160.237'
    ipv6_inet = b' \x01\r\xb8\x85\xa3\x00\x00\x00\x00\x8a.\x03ps4'
    assert inet_to_str(ipv6_inet) == '2001:db8:85a3::8a2e:370:7334'
    print('Success!')
