#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from collections import namedtuple
from enum import Enum, unique
from operator import itemgetter
from typing import Dict, List, Union


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


# SnowflakeType._value2member_map_ : Dict[int, SnowflakeType]
TYPE_CODE_TO_NAME: Dict[int, str] = {
    k: v.name for k, v in SnowflakeType._value2member_map_.items()
}


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


def filter_by_dbapi_type(dbapi_type: DBAPIType) -> List[SnowflakeType]:
    return list(
        map(
            itemgetter("snowflake_type"),
            filter(
                lambda field_type: dbapi_type in field_type["dbapi_type"], FIELD_TYPES
            ),
        )
    )


__binary_types: List[SnowflakeType] = filter_by_dbapi_type(DBAPIType.BINARY)
__string_types: List[SnowflakeType] = filter_by_dbapi_type(DBAPIType.STRING)
__number_types: List[SnowflakeType] = filter_by_dbapi_type(DBAPIType.NUMBER)
__timestamp_types: List[SnowflakeType] = filter_by_dbapi_type(DBAPIType.TIMESTAMP)


def is_name_in_type_list(type_name: str, type_list: List[SnowflakeType]):
    return (
        type_name in SnowflakeType._member_map_
        and SnowflakeType[type_name] in type_list
    )


def get_binary_types():
    return __binary_types


def is_binary_type_name(type_name: str):
    return is_name_in_type_list(type_name, __binary_types)


def get_string_types():
    return __string_types


def is_string_type_name(type_name: str):
    return is_name_in_type_list(type_name, __string_types)


def get_number_types():
    return __number_types


def is_number_type_name(type_name):
    return is_name_in_type_list(type_name, __number_types)


def get_timestamp_types():
    return __timestamp_types


def is_timestamp_type_name(type_name):
    return is_name_in_type_list(type_name, __timestamp_types)


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
