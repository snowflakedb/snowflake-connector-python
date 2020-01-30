#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
"""
Various constants
"""

from collections import defaultdict, namedtuple
from enum import Enum

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
FIELD_ID_TO_NAME = defaultdict(str)

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


def is_date_type_name(type_name):
    return type_name == u'DATE'


# Log format
LOG_FORMAT = (u'%(asctime)s - %(filename)s:%(lineno)d - '
              u'%(funcName)s() - %(levelname)s - %(message)s')

# String literals
UTF8 = u'utf-8'
SHA256_DIGEST = u'sha256_digest'


class ResultStatus(Enum):
    ERROR = u'ERROR'
    UPLOADED = u'UPLOADED'
    DOWNLOADED = u'DOWNLOADED'
    COLLISION = u'COLLISION'
    SKIPPED = u'SKIPPED'
    RENEW_TOKEN = u'RENEW_TOKEN'
    RENEW_PRESIGNED_URL = u'RENEW_PRESIGNED_URL'
    NOT_FOUND_FILE = u'NOT_FOUND_FILE'
    NEED_RETRY = u'NEED_RETRY'
    NEED_RETRY_WITH_LOWER_CONCURRENCY = u'NEED_RETRY_WITH_LOWER_CONCURRENCY'


FileHeader = namedtuple(
    "FileReader", [
        "digest",
        "content_length",
        "encryption_metadata"
    ]
)

PARAMETER_AUTOCOMMIT = u'AUTOCOMMIT'
PARAMETER_CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY = u'CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY'
PARAMETER_CLIENT_SESSION_KEEP_ALIVE = u'CLIENT_SESSION_KEEP_ALIVE'
PARAMETER_CLIENT_PREFETCH_THREADS = u'CLIENT_PREFETCH_THREADS'
PARAMETER_CLIENT_TELEMETRY_ENABLED = u'CLIENT_TELEMETRY_ENABLED'
PARAMETER_CLIENT_TELEMETRY_OOB_ENABLED = u'CLIENT_OUT_OF_BAND_TELEMETRY_ENABLED'
PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL = u'CLIENT_STORE_TEMPORARY_CREDENTIAL'
PARAMETER_CLIENT_USE_SECURE_STORAGE_FOR_TEMPORARY_CREDENTIAL = \
    u'CLIENT_USE_SECURE_STORAGE_FOR_TEMPORARY_CREDENTAIL'
PARAMETER_TIMEZONE = u'TIMEZONE'
PARAMETER_SERVICE_NAME = u'SERVICE_NAME'
PARAMETER_CLIENT_VALIDATE_DEFAULT_PARAMETERS = u'CLIENT_VALIDATE_DEFAULT_PARAMETERS'
PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT = u'PYTHON_CONNECTOR_QUERY_RESULT_FORMAT'

HTTP_HEADER_CONTENT_TYPE = u'Content-Type'
HTTP_HEADER_CONTENT_ENCODING = u'Content-Encoding'
HTTP_HEADER_ACCEPT_ENCODING = u'Accept-Encoding'
HTTP_HEADER_ACCEPT = u"accept"
HTTP_HEADER_USER_AGENT = u"User-Agent"
HTTP_HEADER_SERVICE_NAME = u'X-Snowflake-Service'

HTTP_HEADER_VALUE_OCTET_STREAM = u'application/octet-stream'


class OCSPMode(Enum):
    """
    OCSP Mode
    """
    FAIL_CLOSED = u'FAIL_CLOSED'
    FAIL_OPEN = u'FAIL_OPEN'
    INSECURE = u'INSECURE'
