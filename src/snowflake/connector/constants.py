#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from collections import defaultdict, namedtuple
from enum import Enum, unique
from typing import Dict, List, Union

DBAPI_TYPE_STRING = 0
DBAPI_TYPE_BINARY = 1
DBAPI_TYPE_NUMBER = 2
DBAPI_TYPE_TIMESTAMP = 3

FIELD_TYPES = [
    {"name": "FIXED", "dbapi_type": [DBAPI_TYPE_NUMBER]},
    {"name": "REAL", "dbapi_type": [DBAPI_TYPE_NUMBER]},
    {"name": "TEXT", "dbapi_type": [DBAPI_TYPE_STRING]},
    {"name": "DATE", "dbapi_type": [DBAPI_TYPE_TIMESTAMP]},
    {"name": "TIMESTAMP", "dbapi_type": [DBAPI_TYPE_TIMESTAMP]},
    {"name": "VARIANT", "dbapi_type": [DBAPI_TYPE_BINARY]},
    {"name": "TIMESTAMP_LTZ", "dbapi_type": [DBAPI_TYPE_TIMESTAMP]},
    {"name": "TIMESTAMP_TZ", "dbapi_type": [DBAPI_TYPE_TIMESTAMP]},
    {"name": "TIMESTAMP_NTZ", "dbapi_type": [DBAPI_TYPE_TIMESTAMP]},
    {"name": "OBJECT", "dbapi_type": [DBAPI_TYPE_BINARY]},
    {"name": "ARRAY", "dbapi_type": [DBAPI_TYPE_BINARY]},
    {"name": "BINARY", "dbapi_type": [DBAPI_TYPE_BINARY]},
    {"name": "TIME", "dbapi_type": [DBAPI_TYPE_TIMESTAMP]},
    {"name": "BOOLEAN", "dbapi_type": []},
]


@unique
class SnowflakeType(Enum):
    FIXED = 0
    REAL = 1
    TEXT = 2
    DATE = 3
    TIMESTAMP = 4
    VARIANT = 5
    TIMESTAMP_LTZ = 6
    TIMESTAMP_TZ = 7
    TIMESTAMP_NTZ = 8
    OBJECT = 9
    ARRAY = 10
    BINARY = 11
    TIME = 12
    BOOLEAN = 13

    def __init__(self, type_code):
        self.type_code = type_code


@unique
class DBAPIType(Enum):
    STRING = 0
    BINARY = 1
    NUMBER = 2
    TIMESTAMP = 3


FIELD_TYPES: Dict[str, Union[SnowflakeType, List[DBAPIType]]] = [
    {"snowflake_type": SnowflakeType.FIXED, "dbapi_type": [DBAPIType.NUMBER]},
    {"snowflake_type": SnowflakeType.REAL, "dbapi_type": [DBAPIType.NUMBER]},
    {"snowflake_type": SnowflakeType.TEXT, "dbapi_type": [DBAPIType.STRING]},
    {"snowflake_type": SnowflakeType.DATE, "dbapi_type": [DBAPIType.TIMESTAMP]},
    {"snowflake_type": SnowflakeType.TIMESTAMP, "dbapi_type": [DBAPIType.TIMESTAMP]},
    {"snowflake_type": SnowflakeType.VARIANT, "dbapi_type": [DBAPIType.BINARY]},
    {
        "snowflake_type": SnowflakeType.TIMESTAMP_LTZ,
        "dbapi_type": [DBAPIType.TIMESTAMP],
    },
    {"snowflake_type": SnowflakeType.TIMESTAMP_TZ, "dbapi_type": [DBAPIType.TIMESTAMP]},
    {
        "snowflake_type": SnowflakeType.TIMESTAMP_NTZ,
        "dbapi_type": [DBAPIType.TIMESTAMP],
    },
    {"snowflake_type": SnowflakeType.OBJECT, "dbapi_type": [DBAPIType.BINARY]},
    {"snowflake_type": SnowflakeType.ARRAY, "dbapi_type": [DBAPIType.BINARY]},
    {"snowflake_type": SnowflakeType.BINARY, "dbapi_type": [DBAPIType.BINARY]},
    {"snowflake_type": SnowflakeType.TIME, "dbapi_type": [DBAPIType.TIMESTAMP]},
    {"snowflake_type": SnowflakeType.BOOLEAN, "dbapi_type": []},
]

NAME_TO_TYPE_CODE = defaultdict(int)
TYPE_CODE_TO_NAME = defaultdict(str)


__binary_types = []
__binary_type_names = []
__string_types = []
__string_type_names = []
__number_types = []
__number_type_names = []
__timestamp_types = []
__timestamp_type_names = []

for type_data in FIELD_TYPES:
    type_data: Dict[str, Union[SnowflakeType, List[DBAPIType]]]
    snowflake_type = type_data["snowflake_type"]

    TYPE_CODE_TO_NAME[snowflake_type.type_code] = snowflake_type.name
    NAME_TO_TYPE_CODE[snowflake_type.name] = snowflake_type.type_code

    # TODO: pull this out, using a reduce
    dbapi_types = type_data["dbapi_type"]
    for dbapi_type in dbapi_types:
        if dbapi_type == DBAPIType.BINARY:
            __binary_types.append(snowflake_type)
            __binary_type_names.append(snowflake_type.name)
        elif dbapi_type == DBAPIType.TIMESTAMP:
            __timestamp_types.append(snowflake_type)
            __timestamp_type_names.append(snowflake_type.name)
        elif dbapi_type == DBAPIType.NUMBER:
            __number_types.append(snowflake_type)
            __number_type_names.append(snowflake_type.name)
        elif dbapi_type == DBAPIType.STRING:
            __string_types.append(snowflake_type)
            __string_type_names.append(snowflake_type.name)


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
    return type_name == "DATE"


# Log format
LOG_FORMAT = (
    "%(asctime)s - %(filename)s:%(lineno)d - "
    "%(funcName)s() - %(levelname)s - %(message)s"
)

# String literals
UTF8 = "utf-8"
SHA256_DIGEST = "sha256_digest"


class ResultStatus(Enum):
    ERROR = "ERROR"
    UPLOADED = "UPLOADED"
    DOWNLOADED = "DOWNLOADED"
    COLLISION = "COLLISION"
    SKIPPED = "SKIPPED"
    RENEW_TOKEN = "RENEW_TOKEN"
    RENEW_PRESIGNED_URL = "RENEW_PRESIGNED_URL"
    NOT_FOUND_FILE = "NOT_FOUND_FILE"
    NEED_RETRY = "NEED_RETRY"
    NEED_RETRY_WITH_LOWER_CONCURRENCY = "NEED_RETRY_WITH_LOWER_CONCURRENCY"


FileHeader = namedtuple(
    "FileReader", ["digest", "content_length", "encryption_metadata"]
)

PARAMETER_AUTOCOMMIT = "AUTOCOMMIT"
PARAMETER_CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY = (
    "CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY"
)
PARAMETER_CLIENT_SESSION_KEEP_ALIVE = "CLIENT_SESSION_KEEP_ALIVE"
PARAMETER_CLIENT_PREFETCH_THREADS = "CLIENT_PREFETCH_THREADS"
PARAMETER_CLIENT_TELEMETRY_ENABLED = "CLIENT_TELEMETRY_ENABLED"
PARAMETER_CLIENT_TELEMETRY_OOB_ENABLED = "CLIENT_OUT_OF_BAND_TELEMETRY_ENABLED"
PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL = "CLIENT_STORE_TEMPORARY_CREDENTIAL"
PARAMETER_CLIENT_REQUEST_MFA_TOKEN = "CLIENT_REQUEST_MFA_TOKEN"
PARAMETER_CLIENT_USE_SECURE_STORAGE_FOR_TEMPORARY_CREDENTIAL = (
    "CLIENT_USE_SECURE_STORAGE_FOR_TEMPORARY_CREDENTAIL"
)
PARAMETER_TIMEZONE = "TIMEZONE"
PARAMETER_SERVICE_NAME = "SERVICE_NAME"
PARAMETER_CLIENT_VALIDATE_DEFAULT_PARAMETERS = "CLIENT_VALIDATE_DEFAULT_PARAMETERS"
PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT = "PYTHON_CONNECTOR_QUERY_RESULT_FORMAT"
PARAMETER_ENABLE_STAGE_S3_PRIVATELINK_FOR_US_EAST_1 = (
    "ENABLE_STAGE_S3_PRIVATELINK_FOR_US_EAST_1"
)

HTTP_HEADER_CONTENT_TYPE = "Content-Type"
HTTP_HEADER_CONTENT_ENCODING = "Content-Encoding"
HTTP_HEADER_ACCEPT_ENCODING = "Accept-Encoding"
HTTP_HEADER_ACCEPT = "accept"
HTTP_HEADER_USER_AGENT = "User-Agent"
HTTP_HEADER_SERVICE_NAME = "X-Snowflake-Service"

HTTP_HEADER_VALUE_OCTET_STREAM = "application/octet-stream"

DEFAULT_S3_CONNECTION_POOL_SIZE = 10
MAX_S3_CONNECTION_POOL_SIZE = 20


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

    FAIL_CLOSED = "FAIL_CLOSED"
    FAIL_OPEN = "FAIL_OPEN"
    INSECURE = "INSECURE"


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
    QUEUED_REPARING_WAREHOUSE = 9
    RESTARTED = 10
    BLOCKED = 11
    NO_DATA = 12


# ArrowResultChunk constants the unit in this iterator
# EMPTY_UNIT: default
# ROW_UNIT: fetch row by row if the user call `fetchone()`
# TABLE_UNIT: fetch one arrow table if the user call `fetch_pandas()`
@unique
class IterUnit(Enum):
    ROW_UNIT = "row"
    TABLE_UNIT = "table"
