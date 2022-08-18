# Changelog

## 1.9.8
**[2022-08-17]**
- Fixed endianness issues in PCAPNG, Loopback
- Improved MPLS unpacking to include IPv6
- Fixed unpacking of multiple records in TLS messages
- Updated docstrings for multiples modules
- Fixed a long-standing issue where serializing IP would change its length
- Fixed IEEE 802.11 Beacon byte ordering
- Graceful handling of PCAPNG option comment UTF-8 decoding errors
- Added support for PCAPNG Packet Block
- Added modpcap reader support

## 1.9.7.2
**[2021-08-16]**
- Fixed performance regression (https://github.com/kbandla/dpkt/issues/611)

## 1.9.7
**[2021-08-16]**
- Moved the project documentation from Read the Docs(RST) to github.io(MarkDown)
- Added a new mechanism for creating bit-sized field definitions in the protocol parsers (Packet.\_\_bit_fields\_\_)
- Added pretty printing capability aka Packet.pprint(), Packet.\_\_pprint_funcs\_\_
- Added documentation on developing protocol parsers in dpkt (creating_parsers.md)
- Added a universal pcap+pcapng reader (dpkt.pcap.UniversalReader)
- Improved TLS ClientHello and ServerHello parsing: return an "Unknown" ciphersuite instead of raising an exception, add codes for rfc8701, GREASE ciphersutes
- Added function to get IP protocol name
- Modified Packet.\_\_getitem\_\_() and added Packet.\_\_contains\_\_() to address the nested protocol layers
- Fixed payload length interpretation in AH decoder
- Improved handling of invalid chunks in HTTP and SCTP
- Fixed decoding of IPv6 fragments after the 1st fragment
- Support rfc3540 nonce sum flag in TCP

## 1.9.6
**[2021-05-21]**
- Added in the TLS 1.3 Cipher Suite from the RFC 8446 dated August 2018
- Added support for Linux cooked capture v2, SLL2.

## 1.9.5
**[2021-02-07]** 

- New example showing how to process truncated DNS packets (examples/print_dns_truncated.py).
- Corrected typo in BGP.notification attribute.
- BGP.Update.Attribute.MPReachNLRI.SNPA now inherits from dpkt.Packet.
- Byteorder is now specified when packing GRE optional fields.
- \#517: Improvement to Radiotap class, supporting multi-byte and misaligned flags fields. Endianness is now enforced.
- Github issue template added for bug reporting.
- Compliance with flake8 formatting.
- asn1.py::utctime method now returns time in UTC, instead of local.
- Allow multiple InterfaceDescriptionBlocks with pcapng.Writer.
- SCTP decoder DATA chunk padding aligned to 4-bytes, and improved handling of .data field.
- IEEE80211 DELBA frame now works on big and little-endian architectures.
- Introduce compat.ntole which converts from network byte order to little-endian byte order, regardless of host endianness.
- Ethernet class now attempts to unpack the padding and trailer if present.
- Added anonymous property to cipher suites, which returns True if the cipher suite starts with 'anon'.
- Added pfs (Perfect Forward Secrecy) and aead (Authenticated Encryption with Additional Data) properties to cipher suites.
- Added old CHACHA20-POLY1305 related cipher suites to TLS CipherSuite list.
- Remove redundant num_compression_methods from TLSClientHello
- Testing improved from 90% coverage to over 99%.
