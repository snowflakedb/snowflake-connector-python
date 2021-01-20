#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from collections import defaultdict, namedtuple
from enum import Enum, unique

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
    return type_name == 'DATE'


# Log format
LOG_FORMAT = ('%(asctime)s - %(filename)s:%(lineno)d - '
              '%(funcName)s() - %(levelname)s - %(message)s')

# String literals
UTF8 = 'utf-8'
SHA256_DIGEST = 'sha256_digest'


class ResultStatus(Enum):
    ERROR = 'ERROR'
    UPLOADED = 'UPLOADED'
    DOWNLOADED = 'DOWNLOADED'
    COLLISION = 'COLLISION'
    SKIPPED = 'SKIPPED'
    RENEW_TOKEN = 'RENEW_TOKEN'
    RENEW_PRESIGNED_URL = 'RENEW_PRESIGNED_URL'
    NOT_FOUND_FILE = 'NOT_FOUND_FILE'
    NEED_RETRY = 'NEED_RETRY'
    NEED_RETRY_WITH_LOWER_CONCURRENCY = 'NEED_RETRY_WITH_LOWER_CONCURRENCY'


FileHeader = namedtuple(
    "FileReader", [
        "digest",
        "content_length",
        "encryption_metadata"
    ]
)

PARAMETER_AUTOCOMMIT = 'AUTOCOMMIT'
PARAMETER_CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY = 'CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY'
PARAMETER_CLIENT_SESSION_KEEP_ALIVE = 'CLIENT_SESSION_KEEP_ALIVE'
PARAMETER_CLIENT_PREFETCH_THREADS = 'CLIENT_PREFETCH_THREADS'
PARAMETER_CLIENT_TELEMETRY_ENABLED = 'CLIENT_TELEMETRY_ENABLED'
PARAMETER_CLIENT_TELEMETRY_OOB_ENABLED = 'CLIENT_OUT_OF_BAND_TELEMETRY_ENABLED'
PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL = 'CLIENT_STORE_TEMPORARY_CREDENTIAL'
PARAMETER_CLIENT_REQUEST_MFA_TOKEN = 'CLIENT_REQUEST_MFA_TOKEN'
PARAMETER_CLIENT_USE_SECURE_STORAGE_FOR_TEMPORARY_CREDENTIAL = \
    'CLIENT_USE_SECURE_STORAGE_FOR_TEMPORARY_CREDENTAIL'
PARAMETER_TIMEZONE = 'TIMEZONE'
PARAMETER_SERVICE_NAME = 'SERVICE_NAME'
PARAMETER_CLIENT_VALIDATE_DEFAULT_PARAMETERS = 'CLIENT_VALIDATE_DEFAULT_PARAMETERS'
PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT = 'PYTHON_CONNECTOR_QUERY_RESULT_FORMAT'

HTTP_HEADER_CONTENT_TYPE = 'Content-Type'
HTTP_HEADER_CONTENT_ENCODING = 'Content-Encoding'
HTTP_HEADER_ACCEPT_ENCODING = 'Accept-Encoding'
HTTP_HEADER_ACCEPT = "accept"
HTTP_HEADER_USER_AGENT = "User-Agent"
HTTP_HEADER_SERVICE_NAME = 'X-Snowflake-Service'

HTTP_HEADER_VALUE_OCTET_STREAM = 'application/octet-stream'


@unique
class OCSPMode(Enum):
    """OCSP Mode enumerator for all the available modes.

    OCSP mode descriptions:
        FAIL_CLOSED: If the client or driver does not receive a valid OCSP CA response for any reason,
            the connection fails.
        FAIL_OPEN: A response indicating a revoked certificate results in a failed connection. A response with any
            other certificate errors or statuses allows the connection to occur, but denotes the message in the logs
            at the WARNING level with the relevant details in JSON format.
        INSECURE: The connection will occur anyway.
    """
    FAIL_CLOSED = 'FAIL_CLOSED'
    FAIL_OPEN = 'FAIL_OPEN'
    INSECURE = 'INSECURE'


@unique
class QueryStatus(Enum):
    RUNNING = 0
    ABORTING = 1
    SUCCESS = 2
    FAILED_WITH_ERROR = 3
    ABORTED = 4
    QUEUED = 5
    FAILED_WITH_INCIDENT = 6
    DISCONNECTED = 7
    RESUMING_WAREHOUSE = 8
    # purposeful typo. Is present in QueryDTO.java
    QUEUED_REPAIRING_WAREHOUSE = 9
    RESTARTED = 10
    BLOCKED = 11
    NO_DATA = 12
