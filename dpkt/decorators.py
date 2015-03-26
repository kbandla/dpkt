# -*- coding: utf-8 -*-
import warnings


def deprecated_method_decorator(deprecated_method):
    def wrapper(*args, **kwargs):
        # Print only the first occurrence of the DeprecationWarning, regardless of location
        warnings.simplefilter('once', DeprecationWarning)
        # Display the deprecation warning message
        warnings.warn("Call to deprecated method %s" % deprecated_method.__name__,
                      category=DeprecationWarning, stacklevel=2)
        return deprecated_method(*args, **kwargs)  # actually call the method

    return wrapper


class TestDeprecatedMethodDecorator:
    @deprecated_method_decorator
    def deprecated_method_decorator(self): return

    def test_deprecated_method_decorator(self):
        import sys
        from StringIO import StringIO

        saved_stderr = sys.stderr
        try:
            out = StringIO()
            sys.stderr = out
            self.deprecated_method_decorator()
            assert('DeprecationWarning: Call to deprecated method deprecated_method_decorator' in out.getvalue())
            # 'in' because message contains the filename, line, etc
        finally:
            sys.stderr = saved_stderr


if __name__ == '__main__':
    a = TestDeprecatedMethodDecorator()
    a.test_deprecated_method_decorator()
    print 'Tests Successful...'