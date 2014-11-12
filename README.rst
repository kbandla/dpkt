dpkt
====

"fast, simple packet creation / parsing, with definitions for the basic
TCP/IP protocols"

Deviations from upstream
~~~~~~~~~~~~~~~~~~~~~~~~

This code is based on Kiran Bandia's `dpkt
fork <https://github.com/kbandla/dpkt>`__ which is of course based on
the original `dpkt code <https://code.google.com/p/dpkt/>`__ lead by Dug
Song.

At this point, this is not the exact `upstream
version <https://code.google.com/p/dpkt/>`__. If you are looking for the
latest stock dpkt, please get it from the above link.

Almost all of the upstream changes are pulled. However, some modules are
not. Here is a list of the changes:

-  `dpkt/dpkt.py <https://github.com/kbandla/dpkt/commit/336fe02b0e2f00b382d91cd42558a69eec16d6c7>`__:
   decouple dnet from dpkt
-  `dpkt/dns.py <https://github.com/kbandla/dpkt/commit/2bf3cde213144391fd90488d12f9ccce51b5fbca>`__
   : parse some more DNS flags

Examples
--------

[@jonoberheide's](https://twitter.com/jonoberheide) old examples still
apply:

-  `dpkt Tutorial #1: ICMP
   Echo <https://jon.oberheide.org/blog/2008/08/25/dpkt-tutorial-1-icmp-echo/>`__
-  `dpkt Tutorial #2: Parsing a PCAP
   File <https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/>`__
-  `dpkt Tutorial #3: dns
   spoofing <https://jon.oberheide.org/blog/2008/12/20/dpkt-tutorial-3-dns-spoofing/>`__
-  `dpkt Tutorial #4: AS Paths from
   MRT/BGP <https://jon.oberheide.org/blog/2009/03/25/dpkt-tutorial-4-as-paths-from-mrt-bgp/>`__

`Jeff Silverman <https://github.com/jeffsilverm>`__ has some
`code <https://github.com/jeffsilverm/dpkt_doc>`__ and
`documentation <http://www.commercialventvac.com/dpkt.html>`__.

LICENSE
-------

BSD 3-Clause License, as the upstream project
