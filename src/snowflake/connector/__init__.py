#!/usr/bin/env python
# Python Db API v2
#
from __future__ import annotations

from functools import wraps

apilevel = "2.0"
threadsafety = 2
paramstyle = "pyformat"

import logging
from logging import NullHandler
from typing import TYPE_CHECKING

from typing_extensions import Unpack

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

if TYPE_CHECKING:
    from os import PathLike

    from .connection import SnowflakeConnectionConfig

logging.getLogger(__name__).addHandler(NullHandler())
setup_external_libraries()


@wraps(SnowflakeConnection.__init__)
def Connect(
    connection_name: str | None = None,
    connections_file_path: PathLike[str] | None = None,
    **kwargs: Unpack[SnowflakeConnectionConfig],
) -> SnowflakeConnection:
    return SnowflakeConnection(
        connection_name=connection_name,
        connections_file_path=connections_file_path,
        **kwargs,
    )


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
