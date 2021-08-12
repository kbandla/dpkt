# Changelog

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