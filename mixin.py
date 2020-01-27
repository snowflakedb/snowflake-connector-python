class UnicodeMixin(object):
    u"""
    Mixin class to handle defining the proper __str__/__unicode__
    methods in Python 2 or 3.
    """

    def __str__(self):
        return self.__unicode__()
