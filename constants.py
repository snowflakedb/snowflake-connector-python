#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
"""
Various constants
"""

from collections import defaultdict

from six import PY2

DBAPI_TYPE_STRING = 0
DBAPI_TYPE_BINARY = 1
DBAPI_TYPE_NUMBER = 2
DBAPI_TYPE_TIMESTAMP = 3

FIELD_TYPES = [
    {'name': 'FIXED', 'dbapi_type': [DBAPI_TYPE_NUMBER]},
    {'name': 'REAL', 'dbapi_type': [DBAPI_TYPE_NUMBER]},
    {'name': 'TEXT', 'dbapi_type': [DBAPI_TYPE_STRING]},
    {'name': 'DATE', 'dbapi_type': [DBAPI_TYPE_TIMESTAMP]},
    {'name': 'TIMESTAMP', 'dbapi_type': [DBAPI_TYPE_TIMESTAMP]},
    {'name': 'VARIANT', 'dbapi_type': [DBAPI_TYPE_BINARY]},
    {'name': 'TIMESTAMP_LTZ', 'dbapi_type': [DBAPI_TYPE_TIMESTAMP]},
    {'name': 'TIMESTAMP_TZ', 'dbapi_type': [DBAPI_TYPE_TIMESTAMP]},
    {'name': 'TIMESTAMP_NTZ', 'dbapi_type': [DBAPI_TYPE_TIMESTAMP]},
    {'name': 'OBJECT', 'dbapi_type': [DBAPI_TYPE_BINARY]},
    {'name': 'ARRAY', 'dbapi_type': [DBAPI_TYPE_BINARY]},
    {'name': 'BINARY', 'dbapi_type': [DBAPI_TYPE_BINARY]},
    {'name': 'TIME', 'dbapi_type': [DBAPI_TYPE_TIMESTAMP]},
    {'name': 'BOOLEAN', 'dbapi_type': []},
]

FIELD_NAME_TO_ID = defaultdict(int)
FIELD_ID_TO_NAME = defaultdict(unicode if PY2 else str)

__binary_types = []
__binary_type_names = []
__string_types = []
__string_type_names = []
__number_types = []
__number_type_names = []
__timestamp_types = []
__timestamp_type_names = []

for idx, type in enumerate(FIELD_TYPES):
    FIELD_ID_TO_NAME[idx] = type['name']
    FIELD_NAME_TO_ID[type['name']] = idx

    dbapi_types = type['dbapi_type']
    for dbapi_type in dbapi_types:
        if dbapi_type == DBAPI_TYPE_BINARY:
            __binary_types.append(idx)
            __binary_type_names.append(type['name'])
        elif dbapi_type == DBAPI_TYPE_TIMESTAMP:
            __timestamp_types.append(idx)
            __timestamp_type_names.append(type['name'])
        elif dbapi_type == DBAPI_TYPE_NUMBER:
            __number_types.append(idx)
            __number_type_names.append(type['name'])
        elif dbapi_type == DBAPI_TYPE_STRING:
            __string_types.append(idx)
            __string_type_names.append(type['name'])


def get_binary_types():
    return __binary_types


def is_binary_type_name(type_name):
    return type_name in __binary_type_names


def get_string_types():
    return __string_types


def is_string_type_name(type_name):
    return type_name in __string_type_names


def get_number_types():
    return __number_types


def is_number_type_name(type_name):
    return type_name in __number_type_names


def get_timestamp_types():
    return __timestamp_types


def is_timestamp_type_name(type_name):
    return type_name in __timestamp_type_names


# Log format
LOG_FORMAT = (u'%(asctime)s - %(filename)s:%(lineno)d - '
              u'%(funcName)s() - %(levelname)s - %(message)s')

# String literals
UTF8 = u'utf-8'
CONTENT_LENGTH = u'Content-Length'
AMZ_MATDESC = u"x-amz-matdesc"
AMZ_KEY = u"x-amz-key"
AMZ_IV = u"x-amz-iv"
SFC_DIGEST = u'sfc-digest'
SHA256_DIGEST = u'sha256_digest'
