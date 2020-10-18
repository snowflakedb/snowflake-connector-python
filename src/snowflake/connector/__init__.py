#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

#
# Python Db API v2
#
apilevel = '2.0'
threadsafety = 2
paramstyle = 'pyformat'

import logging
from logging import NullHandler

from .connection import SnowflakeConnection
from .cursor import DictCursor
from .dbapi import (
    BINARY,
    DATETIME,
    NUMBER,
    ROWID,
    STRING,
    Binary,
    Date,
    DateFromTicks,
    Json,
    Time,
    TimeFromTicks,
    Timestamp,
    TimestampFromTicks,
)
from .errors import (
    DatabaseError,
    DataError,
    Error,
    IntegrityError,
    InterfaceError,
    InternalError,
    NotSupportedError,
    OperationalError,
    ProgrammingError,
    Warning,
)
from .version import VERSION

logging.getLogger(__name__).addHandler(NullHandler())


def Connect(**kwargs):
    return SnowflakeConnection(**kwargs)


connect = Connect

SNOWFLAKE_CONNECTOR_VERSION = '.'.join(str(v) for v in VERSION[0:3])
__version__ = SNOWFLAKE_CONNECTOR_VERSION

__all__ = [
    # Error handling
    'Error', 'Warning',
    'InterfaceError', 'DatabaseError',
    'NotSupportedError', 'DataError', 'IntegrityError', 'ProgrammingError',
    'OperationalError', 'InternalError',

    # Extended cursor
    'DictCursor',

    # DBAPI PEP 249 required exports
    'connect',
    'apilevel',
    'threadsafety',
    'paramstyle',
    'Date',
    'Time',
    'Timestamp',
    'Binary',
    'DateFromTicks',
    'TimeFromTicks',
    'TimestampFromTicks',
    'STRING',
    'BINARY',
    'NUMBER',
    'DATETIME',
    'ROWID',

    # Extended data type (experimental)
    'Json',
]
