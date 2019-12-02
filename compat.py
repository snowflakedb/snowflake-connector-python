#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import decimal
import os
import platform
import sys

from six import string_types, text_type, binary_type, PY2

from snowflake.connector.constants import UTF8

IS_LINUX = platform.system() == 'Linux'
IS_WINDOWS = platform.system() == 'Windows'

NUM_DATA_TYPES = []
try:
    import numpy

    NUM_DATA_TYPES = [numpy.int8, numpy.int16, numpy.int32, numpy.int64,
                      numpy.float16, numpy.float32, numpy.float64,
                      numpy.uint8, numpy.uint16, numpy.uint32, numpy.uint64, numpy.bool_]
except:
    numpy = None

STR_DATA_TYPE = string_types
UNICODE_DATA_TYPE = text_type
BYTE_DATA_TYPE = binary_type
if PY2:
    import urlparse
    import urllib
    import httplib
    import Queue
    from HTMLParser import HTMLParser
    import collections

    GET_CWD = os.getcwdu
    BASE_EXCEPTION_CLASS = StandardError  # noqa: F821
    TO_UNICODE = unicode  # noqa: F821
    ITERATOR = collections.Iterator
    MAPPING = collections.Mapping

    urlsplit = urlparse.urlsplit
    urlunsplit = urlparse.urlunsplit
    parse_qs = urlparse.parse_qs
    urlparse = urlparse.urlparse

    NUM_DATA_TYPES += [int, float, long, decimal.Decimal]  # noqa: F821
    PKCS5_UNPAD = lambda v: v[0:-ord(v[-1])]
    PKCS5_OFFSET = lambda v: ord(v[-1])
    IS_BINARY = lambda v: isinstance(v, bytearray)

    METHOD_NOT_ALLOWED = httplib.METHOD_NOT_ALLOWED
    BAD_GATEWAY = httplib.BAD_GATEWAY
    BAD_REQUEST = httplib.BAD_REQUEST
    REQUEST_TIMEOUT = httplib.REQUEST_TIMEOUT
    SERVICE_UNAVAILABLE = httplib.SERVICE_UNAVAILABLE
    GATEWAY_TIMEOUT = httplib.GATEWAY_TIMEOUT
    FORBIDDEN = httplib.FORBIDDEN
    UNAUTHORIZED = httplib.UNAUTHORIZED
    INTERNAL_SERVER_ERROR = httplib.INTERNAL_SERVER_ERROR
    IncompleteRead = httplib.IncompleteRead
    OK = httplib.OK
    BadStatusLine = httplib.BadStatusLine

    urlencode = urllib.urlencode
    unquote = urllib.unquote
    unescape = HTMLParser().unescape

    EmptyQueue = Queue.Empty
    Queue = Queue.Queue


else:
    import urllib.parse
    import http.client
    import urllib.request
    import queue
    import html
    import collections.abc

    GET_CWD = os.getcwd
    BASE_EXCEPTION_CLASS = Exception
    TO_UNICODE = str
    ITERATOR = collections.abc.Iterator
    MAPPING = collections.abc.Mapping

    urlsplit = urllib.parse.urlsplit
    urlunsplit = urllib.parse.urlunsplit
    parse_qs = urllib.parse.parse_qs
    urlparse = urllib.parse.urlparse

    NUM_DATA_TYPES += [int, float, decimal.Decimal]
    PKCS5_UNPAD = lambda v: v[0:-v[-1]]
    PKCS5_OFFSET = lambda v: v[-1]
    IS_BINARY = lambda v: isinstance(v, (bytes, bytearray))

    METHOD_NOT_ALLOWED = http.client.METHOD_NOT_ALLOWED
    BAD_GATEWAY = http.client.BAD_GATEWAY
    BAD_REQUEST = http.client.BAD_REQUEST
    REQUEST_TIMEOUT = http.client.REQUEST_TIMEOUT
    SERVICE_UNAVAILABLE = http.client.SERVICE_UNAVAILABLE
    GATEWAY_TIMEOUT = http.client.GATEWAY_TIMEOUT
    FORBIDDEN = http.client.FORBIDDEN
    UNAUTHORIZED = http.client.UNAUTHORIZED
    INTERNAL_SERVER_ERROR = http.client.INTERNAL_SERVER_ERROR
    IncompleteRead = http.client.IncompleteRead
    OK = http.client.OK
    BadStatusLine = http.client.BadStatusLine

    urlencode = urllib.parse.urlencode
    unquote = urllib.parse.unquote
    unescape = html.unescape

    EmptyQueue = queue.Empty
    Queue = queue.Queue

IS_BYTES = lambda v: isinstance(v, BYTE_DATA_TYPE)
IS_STR = lambda v: isinstance(v, STR_DATA_TYPE)
IS_UNICODE = lambda v: isinstance(v, UNICODE_DATA_TYPE)
IS_NUMERIC = lambda v: isinstance(v, tuple(NUM_DATA_TYPES))

# Some tests don't need to run on Python34, because SnowSQL specific.
# SnowSQL runs on Python 3.5+
PY34_EXACT = sys.version_info[0:2] == (3, 4)


def PKCS5_PAD(value, block_size):
    return b"".join(
        [value, (block_size - len(value) % block_size) * chr(
            block_size - len(value) % block_size).encode(UTF8)])


def PRINT(msg):
    if PY2:
        if isinstance(msg, unicode):  # noqa: F821
            print(msg.encode(UTF8))
        else:
            print(msg)
    else:
        print(msg)


def INPUT(prompt):
    if PY2:
        return raw_input(prompt).decode(UTF8)  # noqa: F821
    else:
        return input(prompt)


def IS_OLD_PYTHON():
    """
    Is old Python
    """
    return PY2 and sys.hexversion < 0x02070900 or \
           not PY2 and sys.hexversion < 0x03040300


try:
    from inspect import getfullargspec as _get_args
except ImportError:
    from inspect import getargspec as _get_args


get_args = _get_args


"""
Is Python 3.5.0
This is to check if a workaround for http://bugs.python.org/issue23517
is required or not. 3.6.0 already has the fix.
No RC or dev version will be checked.
"""
PY_ISSUE_23517 = 0x03040300 <= sys.hexversion < 0x03040400 or \
                 0x03050000 <= sys.hexversion < 0x03050100
