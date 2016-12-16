from .compat import PY2


class UnicodeMixin(object):
    u"""
    Mixin class to handle defining the proper __str__/__unicode__
    methods in Python 2 or 3.
    """

    if PY2:
        def __str__(self):
            return self.__unicode__().encode('utf8')
    else:  # Python 2
        def __str__(self):
            return self.__unicode__()
