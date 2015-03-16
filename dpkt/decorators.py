# -*- coding: utf-8 -*-
import warnings


def deprecated_method_decorator(deprecated_method):
    def wrapper(*args, **kwargs):
        warnings.simplefilter('always', DeprecationWarning)  # turn off filter
        if str(deprecated_method.__name__).startswith("_get_"):  # getter method
            warnings.warn("Call to deprecated method '{}'. Use '{}' instead".format(deprecated_method.__name__,
                          str(deprecated_method.__name__)[5:]), category=DeprecationWarning, stacklevel=2)
        elif str(deprecated_method.__name__).startswith("_set_"):
            warnings.warn("Call to deprecated method '{}'. Use '{}' = 'value' instead".format(deprecated_method.__name__,
                          str(deprecated_method.__name__)[5:]), category=DeprecationWarning, stacklevel=2)
        else:
            warnings.warn("Call to deprecated method %s." % deprecated_method.__name__,
                          category=DeprecationWarning, stacklevel=2)
        warnings.simplefilter('default', DeprecationWarning)  # reset filter
        return deprecated_method(*args, **kwargs)

    return wrapper