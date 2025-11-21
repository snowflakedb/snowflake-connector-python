#!/usr/bin/env python
# Python Db API v2
#
from __future__ import annotations

from functools import wraps

from ._utils import _core_loader

apilevel = "2.0"
threadsafety = 2
paramstyle = "pyformat"

import logging
from logging import NullHandler

from snowflake.connector.externals_utils.externals_setup import setup_external_libraries

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
    _Warning,
)
from .log_configuration import EasyLoggingConfigPython
from .version import VERSION

# Load the core library - failures are captured in core_loader and don't prevent module loading
try:
    _core_loader.load()
except Exception:
    # Silently continue if core loading fails - the error is already captured in core_loader
    # This ensures the connector module loads even if the minicore library is unavailable
    pass

logging.getLogger(__name__).addHandler(NullHandler())
setup_external_libraries()


@wraps(SnowflakeConnection.__init__)
def Connect(**kwargs) -> SnowflakeConnection:
    return SnowflakeConnection(**kwargs)


connect = Connect

SNOWFLAKE_CONNECTOR_VERSION = ".".join(str(v) for v in VERSION[0:3])
__version__ = SNOWFLAKE_CONNECTOR_VERSION

__all__ = [
    "SnowflakeConnection",
    # Error handling
    "Error",
    "_Warning",
    "InterfaceError",
    "DatabaseError",
    "NotSupportedError",
    "DataError",
    "IntegrityError",
    "ProgrammingError",
    "OperationalError",
    "InternalError",
    # Extended cursor
    "DictCursor",
    # DBAPI PEP 249 required exports
    "connect",
    "apilevel",
    "threadsafety",
    "paramstyle",
    "Date",
    "Time",
    "Timestamp",
    "Binary",
    "DateFromTicks",
    "TimeFromTicks",
    "TimestampFromTicks",
    "STRING",
    "BINARY",
    "NUMBER",
    "DATETIME",
    "ROWID",
    # Extended data type (experimental)
    "EasyLoggingConfigPython",
]
