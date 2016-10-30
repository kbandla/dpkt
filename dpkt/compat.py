import sys

if sys.version_info < (3,):
    def compat_ord(char):
        return ord(char)
else:
    def compat_ord(char):
        return char