# -*- coding: utf-8 -*-
import warnings


def deprecated_method_decorator(deprecated_method):
    def wrapper(*args, **kwargs):
        warnings.simplefilter('always', DeprecationWarning)  # turn off filter
        warnings.warn("Call to deprecated method %s" % deprecated_method.__name__,
                      category=DeprecationWarning, stacklevel=2)
        warnings.simplefilter('default', DeprecationWarning)  # reset filter
        return deprecated_method(*args, **kwargs)

    return wrapper