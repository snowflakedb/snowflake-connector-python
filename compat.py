#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import decimal
import os
import platform
import sys
import urllib.parse
import http.client
import urllib.request
import queue
import html
import collections.abc
from snowflake.connector.constants import UTF8

IS_LINUX = platform.system() == 'Linux'
IS_WINDOWS = platform.system() == 'Windows'
IS_MACOS = platform.system() == 'Darwin'

NUM_DATA_TYPES = []
try:
    import numpy

    NUM_DATA_TYPES = [numpy.int8, numpy.int16, numpy.int32, numpy.int64,
                      numpy.float16, numpy.float32, numpy.float64,
                      numpy.uint8, numpy.uint16, numpy.uint32, numpy.uint64, numpy.bool_]
except Exception:
    numpy = None

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

IS_BYTES = lambda v: isinstance(v, bytes)
IS_STR = IS_UNICODE = lambda v: isinstance(v, str)
IS_NUMERIC = lambda v: isinstance(v, tuple(NUM_DATA_TYPES))


def PKCS5_PAD(value, block_size):
    return b"".join(
        [value, (block_size - len(value) % block_size) * chr(
            block_size - len(value) % block_size).encode(UTF8)])


def PRINT(msg):
    print(msg)


def INPUT(prompt):
    return input(prompt)


"""
Is Python 3.5.0
This is to check if a workaround for http://bugs.python.org/issue23517
is required or not. 3.6.0 already has the fix.
No RC or dev version will be checked.
"""
PY_ISSUE_23517 = 0x03040300 <= sys.hexversion < 0x03040400 or \
                 0x03050000 <= sys.hexversion < 0x03050100
