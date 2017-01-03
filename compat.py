#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import decimal
import sys

import os

NUM_DATA_TYPES = []
try:
    import numpy

    NUM_DATA_TYPES = [numpy.int8, numpy.int16, numpy.int32, numpy.int64,
                      numpy.float16, numpy.float32, numpy.float64,
                      numpy.uint8, numpy.uint16, numpy.uint32, numpy.uint64]
except:
    numpy = None

from snowflake.connector.constants import UTF8

PY2 = sys.version_info[0] == 2

if PY2:
    BASE_EXCEPTION_CLASS = StandardError
    GET_CWD = os.getcwdu
    TO_UNICODE = unicode
    BYTE_DATA_TYPE = str
    STR_DATA_TYPE = basestring
    UNICODE_DATA_TYPE = unicode
    NUM_DATA_TYPES += [int, float, long, decimal.Decimal]
    PKCS5_UNPAD = lambda v: v[0:-ord(v[-1])]
    PKCS5_OFFSET = lambda v: ord(v[-1])
    IS_BINARY = lambda v: isinstance(v, bytearray)
    from urlparse import urlsplit, urlunsplit
    from urllib import urlencode
else:
    BASE_EXCEPTION_CLASS = Exception
    GET_CWD = os.getcwd
    TO_UNICODE = str
    BYTE_DATA_TYPE = bytes
    STR_DATA_TYPE = str
    UNICODE_DATA_TYPE = str
    NUM_DATA_TYPES += [int, float, decimal.Decimal]
    PKCS5_UNPAD = lambda v: v[0:-v[-1]]
    PKCS5_OFFSET = lambda v: v[-1]
    IS_BINARY = lambda v: isinstance(v, (bytes, bytearray))
    from urllib.parse import urlsplit, urlunsplit, urlencode

IS_BYTES = lambda v: isinstance(v, BYTE_DATA_TYPE)
IS_STR = lambda v: isinstance(v, STR_DATA_TYPE)
IS_UNICODE = lambda v: isinstance(v, UNICODE_DATA_TYPE)
IS_NUMERIC = lambda v: isinstance(v, tuple(NUM_DATA_TYPES))
URL_SPLIT = urlsplit
URL_UNSPLIT = urlunsplit
URL_ENCODE = urlencode


def PKCS5_PAD(value, block_size):
    return b"".join(
        [value, (block_size - len(value) % block_size) * chr(
            block_size - len(value) % block_size).encode(UTF8)])


def PRINT(msg):
    if PY2:
        if isinstance(msg, unicode):
            print(msg.encode(UTF8))
        else:
            print(msg)
    else:
        print(msg)


def INPUT(prompt):
    if PY2:
        return raw_input(prompt).decode(UTF8)
    else:
        return input(prompt)


def IS_OLD_PYTHON():
    u"""
    Is old Python
    """
    return PY2 and sys.hexversion < 0x02070900 or \
           not PY2 and sys.hexversion < 0x03040300
