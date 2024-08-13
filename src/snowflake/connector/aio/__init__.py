#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from functools import wraps

from ._connection import SnowflakeConnection

__all__ = [SnowflakeConnection]


@wraps(SnowflakeConnection.__init__)
def Connect(**kwargs) -> SnowflakeConnection:
    return SnowflakeConnection(**kwargs)


connect = Connect
