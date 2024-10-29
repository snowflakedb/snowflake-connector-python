#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from ._connection import SnowflakeConnection
from ._cursor import DictCursor, SnowflakeCursor

__all__ = [
    SnowflakeConnection,
    SnowflakeCursor,
    DictCursor,
]


async def connect(**kwargs) -> SnowflakeConnection:
    conn = SnowflakeConnection(**kwargs)
    await conn.connect()
    return conn
