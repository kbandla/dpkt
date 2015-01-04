dpkt
====

fast, simple packet creation / parsing, with definitions for the basic
TCP/IP protocols

[![docs](https://readthedocs.org/projects/dpkt/badge/?style=flat)](https://readthedocs.org/projects/dpkt)
[![travis](http://img.shields.io/travis/kbandla/dpkt/master.png?style=flat)](https://travis-ci.org/kbandla/dpkt)
[![coveralls](http://img.shields.io/coveralls/kbandla/dpkt/master.png?style=flat)](https://coveralls.io/r/kbandla/dpkt)
[![landscape](https://landscape.io/github/kbandla/dpkt/master/landscape.svg?style=flat)](https://landscape.io/github/kbandla/dpkt/master)
[![version](http://img.shields.io/pypi/v/dpkt.png?style=flat)](https://pypi.python.org/pypi/dpkt)

[![downloads](http://img.shields.io/pypi/dm/dpkt.png?style=flat)](https://pypi.python.org/pypi/dpkt)
[![wheel](https://pypip.in/wheel/dpkt/badge.png?style=flat)](https://pypi.python.org/pypi/dpkt)
[![supported-versions](https://pypip.in/py_versions/dpkt/badge.png?style=flat)](https://pypi.python.org/pypi/dpkt)
[![supported-implementations](https://pypip.in/implementation/dpkt/badge.png?style=flat)](https://pypi.python.org/pypi/dpkt)


Installation
------------

    pip install dpkt

Documentation
-------------

<https://dpkt.readthedocs.org/>

Development
-----------

To run the all tests run:

    tox

### Deviations from upstream

This code is based on [dpkt code](https://code.google.com/p/dpkt/) lead
by Dug Song.

At this point, this is not the exact [upstream
version](https://code.google.com/p/dpkt/). If you are looking for the
latest stock dpkt, please get it from the above link.

Almost all of the upstream changes are pulled. However, some modules are
not. Here is a list of the changes:

-   [dpkt/dpkt.py](https://github.com/kbandla/dpkt/commit/336fe02b0e2f00b382d91cd42558a69eec16d6c7):
    decouple dnet from dpkt
-   [dpkt/dns.py](https://github.com/kbandla/dpkt/commit/2bf3cde213144391fd90488d12f9ccce51b5fbca)
    : parse some more DNS flags

#### Examples

[@jonoberheide's](<https://twitter.com/jonoberheide>) old examples still
apply:

-   [dpkt Tutorial \#1: ICMP
    Echo](https://jon.oberheide.org/blog/2008/08/25/dpkt-tutorial-1-icmp-echo/)
-   [dpkt Tutorial \#2: Parsing a PCAP
    File](https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/)
-   [dpkt Tutorial \#3: dns
    spoofing](https://jon.oberheide.org/blog/2008/12/20/dpkt-tutorial-3-dns-spoofing/)
-   [dpkt Tutorial \#4: AS Paths from
    MRT/BGP](https://jon.oberheide.org/blog/2009/03/25/dpkt-tutorial-4-as-paths-from-mrt-bgp/)

[Jeff Silverman](https://github.com/jeffsilverm) has some
[code](https://github.com/jeffsilverm/dpkt_doc) and
[documentation](http://www.commercialventvac.com/dpkt.html).

#### LICENSE

BSD 3-Clause License, as the upstream project
