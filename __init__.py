#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

#
# Python Db API v2
#
apilevel = u'2.0'
threadsafety = 2
paramstyle = u'pyformat'

import logging
from logging import NullHandler

from .compat import TO_UNICODE
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

SNOWFLAKE_CONNECTOR_VERSION = u'.'.join(TO_UNICODE(v) for v in VERSION[0:3])
__version__ = SNOWFLAKE_CONNECTOR_VERSION

__all__ = [
    # Error handling
    u'Error', u'Warning',
    u'InterfaceError', u'DatabaseError',
    u'NotSupportedError', u'DataError', u'IntegrityError', u'ProgrammingError',
    u'OperationalError', u'InternalError',

    # Extended cursor
    u'DictCursor',

    # DBAPI PEP 249 required exports
    u'connect',
    u'apilevel',
    u'threadsafety',
    u'paramstyle',
    u'Date',
    u'Time',
    u'Timestamp',
    u'Binary',
    u'DateFromTicks',
    u'TimeFromTicks',
    u'TimestampFromTicks',
    u'STRING',
    u'BINARY',
    u'NUMBER',
    u'DATETIME',
    u'ROWID',

    # Extended data type (experimental)
    u'Json',
]
