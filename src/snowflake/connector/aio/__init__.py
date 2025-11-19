from __future__ import annotations

from functools import wraps
from typing import Any, Coroutine, Generator, Protocol, TypeVar, runtime_checkable

from ._connection import SnowflakeConnection
from ._cursor import DictCursor, SnowflakeCursor

__all__ = [
    SnowflakeConnection,
    SnowflakeCursor,
    DictCursor,
]

# ============================================================================
# DESIGN NOTES:
#
# Pattern similar to aiohttp.ClientSession.request() which similarly returns
# an object that can be both awaited and used as an async context manager.
#
# The async connect function uses a wrapper to support both:
#   1. Direct awaiting: conn = await connect(...)
#   2. Async context manager: async with connect(...) as conn:
#
# connect: A function decorated with @wraps(SnowflakeConnection.__init__) that
#   preserves metadata for IDE support, type checking, and introspection.
#   Returns a _AsyncConnectContextManager instance when called.
#
# _AsyncConnectContextManager: Implements __await__ and __aenter__/__aexit__
#   to support both patterns on the same awaitable.
#
# The @wraps decorator ensures that connect() has the same signature and
# documentation as SnowflakeConnection.__init__, making it behave identically
# to the sync snowflake.connector.connect function from an introspection POV.
#
# Metadata preservation is critical for IDE autocomplete, static type checkers,
# and documentation generation to work correctly on the async connect function.
# ============================================================================


T = TypeVar("T")


@runtime_checkable
class HybridCoroutineContextManager(Protocol[T]):
    """Protocol for a hybrid coroutine that is also an async context manager.

    Combines the full coroutine protocol (PEP 492) with async context manager
    protocol (PEP 343/492), allowing code that expects either interface to work
    seamlessly with instances of this protocol.

    This is used when external code needs to manage the coroutine lifecycle
    (e.g., timeout handlers, async schedulers) or use it as a context manager.
    """

    # Full Coroutine Protocol (PEP 492)
    def send(self, __arg: Any) -> Any:
        """Send a value into the coroutine."""
        ...

    def throw(
        self,
        __typ: type[BaseException],
        __val: BaseException | None = None,
        __tb: Any = None,
    ) -> Any:
        """Throw an exception into the coroutine."""
        ...

    def close(self) -> None:
        """Close the coroutine."""
        ...

    def __await__(self) -> Generator[Any, None, T]:
        """Return awaitable generator."""
        ...

    def __iter__(self) -> Generator[Any, None, T]:
        """Iterate over the coroutine."""
        ...

    # Async Context Manager Protocol (PEP 343)
    async def __aenter__(self) -> T:
        """Async context manager entry."""
        ...

    async def __aexit__(
        self,
        __exc_type: type[BaseException] | None,
        __exc_val: BaseException | None,
        __exc_tb: Any,
    ) -> bool | None:
        """Async context manager exit."""
        ...


class _AsyncConnectContextManager(HybridCoroutineContextManager[SnowflakeConnection]):
    """Hybrid wrapper that enables both awaiting and async context manager usage.

    Allows both patterns:
    - conn = await connect(...)
    - async with connect(...) as conn:

    Implements the full coroutine protocol for maximum compatibility.
    Satisfies the HybridCoroutineContextManager protocol.
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


@wraps(SnowflakeConnection.__init__)
def connect(**kwargs: Any) -> HybridCoroutineContextManager[SnowflakeConnection]:
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
