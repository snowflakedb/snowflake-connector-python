#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
from base64 import b16decode, b16encode, standard_b64encode

from .errors import InternalError

# Converts a Snowflake binary value into a "bytes" object.
binary_to_python = b16decode


def binary_to_snowflake(binary_value):
    """
    Encodes a "bytes" object for passing to Snowflake.
    """
    result = b16encode(binary_value)

    if isinstance(binary_value, bytearray):
        return bytearray(result)
    return result


class SnowflakeBinaryFormat(object):
    """
    Formats binary values ("bytes" objects) in hex or base64.
    """

    def __init__(self, name):
        name = name.upper()
        if name == u'HEX':
            self._encode = b16encode
        elif name == u'BASE64':
            self._encode = standard_b64encode
        else:
            raise InternalError(
                u'Unrecognized binary format {}'.format(name))

    def format(self, binary_value):
        """
        Formats a "bytes" object, returning a string.
        """
        return self._encode(binary_value).decode('ascii')
