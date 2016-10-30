from __future__ import absolute_import

import sys

if sys.version_info < (3,):
    def compat_ord(char):
        return ord(char)
else:
    def compat_ord(char):
        return char

try:
    from itertools import izip
    compat_izip = izip
except ImportError:
    compat_izip = zip
