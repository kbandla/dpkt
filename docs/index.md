
# dpkt

The dpkt project is a python module for fast, simple packet parsing, with definitions for the basic TCP/IP protocols.

### Installation
```
pip install dpkt
```

### Documentation

<https://kbandla.github.io/dpkt/>

### Recent Stuff 

**[2021-02-07]** 
Released 1.9.5, thanks a bunch to all contributors but mostly to @crocogorical for doing most of the work :)

1.9.5 Changelog:

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

## About
This code is based on [dpkt code](https://code.google.com/p/dpkt/) lead by Dug Song and is now being maintained and improved by an extended set of 
[contributors](https://dpkt.readthedocs.org/en/latest/authors.html) and [developers] (https://github.com/kbandla/dpkt/graphs/contributors)

## LICENSE

BSD 3-Clause
