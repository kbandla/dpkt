import sys

if sys.version_info < (3,):
    compat_ord = ord
else:
    def compat_ord(char):
        return char
