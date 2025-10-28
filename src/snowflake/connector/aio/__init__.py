from __future__ import annotations

from typing import Any

from ._connection import SnowflakeConnection
from ._cursor import DictCursor, SnowflakeCursor

__all__ = [
    SnowflakeConnection,
    SnowflakeCursor,
    DictCursor,
]


class _AsyncConnectWrapper:
    """Wrapper that preserves metadata of SnowflakeConnection.__init__ while providing async connect behavior.

    This class makes the async connect function metadata-compatible with the synchronous Connect function,
    allowing introspection tools to see the same signature as SnowflakeConnection.__init__.
    """

    def __init__(self):
        # Copy metadata from SnowflakeConnection.__init__ to this instance
        # This allows introspection tools to see the proper signature
        self.__wrapped__ = SnowflakeConnection.__init__
        # Standard functools.wraps attributes
        self.__name__ = "connect"
        self.__doc__ = SnowflakeConnection.__init__.__doc__
        self.__module__ = __name__
        self.__qualname__ = "connect"
        self.__annotations__ = getattr(
            SnowflakeConnection.__init__, "__annotations__", {}
        )

    async def __call__(self, **kwargs: Any) -> SnowflakeConnection:
        """Create and connect to a Snowflake connection asynchronously.

        This async function creates a SnowflakeConnection instance and establishes
        the connection, replicating the behavior of the synchronous snowflake.connector.connect.
        """
        conn = SnowflakeConnection(**kwargs)
        await conn.connect()
        return conn


# Create the async connect function with preserved metadata
connect = _AsyncConnectWrapper()
