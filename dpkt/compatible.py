import sys

if sys.version_info < (3,):
    def compatible_ord(char):
        return ord(char)
else:
    def compatible_ord(char):
        return char