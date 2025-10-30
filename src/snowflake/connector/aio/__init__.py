from __future__ import annotations

from functools import wraps
from typing import Any, Coroutine, Generator

from ._connection import SnowflakeConnection
from ._cursor import DictCursor, SnowflakeCursor

__all__ = [
    SnowflakeConnection,
    SnowflakeCursor,
    DictCursor,
]


class _AsyncConnectContextManager:
    """Hybrid wrapper that enables both awaiting and async context manager usage.

    Allows both patterns:
    - conn = await connect(...)
    - async with connect(...) as conn:

    Implements the full coroutine protocol for maximum compatibility.
    """

    __slots__ = ("_coro", "_conn")

    def __init__(self, coro: Coroutine[Any, Any, SnowflakeConnection]) -> None:
        self._coro = coro
        self._conn: SnowflakeConnection | None = None

    def send(self, arg: Any) -> Any:
        """Send a value into the wrapped coroutine."""
        return self._coro.send(arg)

    def throw(self, *args: Any, **kwargs: Any) -> Any:
        """Throw an exception into the wrapped coroutine."""
        return self._coro.throw(*args, **kwargs)

    def close(self) -> None:
        """Close the wrapped coroutine."""
        return self._coro.close()

    def __await__(self) -> Generator[Any, None, SnowflakeConnection]:
        """Enable await connect(...)"""
        return self._coro.__await__()

    def __iter__(self) -> Generator[Any, None, SnowflakeConnection]:
        """Make the wrapper iterable like a coroutine."""
        return self.__await__()

    # This approach requires idempotent __aenter__ of SnowflakeConnection class - so check if connected and do not repeat connecting
    async def __aenter__(self) -> SnowflakeConnection:
        """Enable async with connect(...) as conn:"""
        self._conn = await self._coro
        return await self._conn.__aenter__()

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Exit async context manager."""
        if self._conn is not None:
            return await self._conn.__aexit__(exc_type, exc, tb)
        else:
            return None


class _AsyncConnectWrapper:
    """Preserves SnowflakeConnection.__init__ metadata for async connect function.

    This wrapper enables introspection tools and IDEs to see the same signature
    as the synchronous snowflake.connector.connect function.
    """

    def __init__(self) -> None:
        self.__wrapped__ = SnowflakeConnection.__init__
        self.__name__ = "connect"
        self.__doc__ = SnowflakeConnection.__init__.__doc__
        self.__module__ = __name__
        self.__qualname__ = "connect"
        self.__annotations__ = getattr(
            SnowflakeConnection.__init__, "__annotations__", {}
        )

    @wraps(SnowflakeConnection.__init__)
    def __call__(self, **kwargs: Any) -> _AsyncConnectContextManager:
        """Create and connect to a Snowflake connection asynchronously.

        Returns an awaitable that can also be used as an async context manager.
        Supports both patterns:
        - conn = await connect(...)
        - async with connect(...) as conn:
        """

        async def _connect_coro() -> SnowflakeConnection:
            conn = SnowflakeConnection(**kwargs)
            await conn.connect()
            return conn

        return _AsyncConnectContextManager(_connect_coro())


connect = _AsyncConnectWrapper()
