from __future__ import annotations

from functools import update_wrapper, wraps
from typing import (
    Any,
    Callable,
    Coroutine,
    Generator,
    Protocol,
    TypeVar,
    runtime_checkable,
)

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
# The async connect function uses a two-layer wrapper to support both:
#   1. Direct awaiting: conn = await connect(...)
#   2. Async context manager: async with connect(...) as conn:
#
# _AsyncConnectContextManager: Implements __await__ and __aenter__/__aexit__
#   to support both patterns on the same awaitable.
#
# _AsyncConnectWrapper: A callable class that preserves SnowflakeConnection
#   metadata via @preserve_metadata decorator for IDE support, type checking,
#   and introspection. Returns _AsyncConnectContextManager instances when called.
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


def preserve_metadata(
    source: type, *, override_name: str | None = None
) -> Callable[[T], T]:
    """Decorator to copy metadata from a source class to class instances.

    Copies __wrapped__, __doc__, __module__, __annotations__ etc. to instances
    during their initialization, allowing instances to be introspected like the
    source class's __init__.

    Args:
        source: Class to copy metadata from (uses its __init__).
        override_name: Optional name override for instances.
    """

    def decorator(cls: T) -> T:
        metadata_source = source.__init__
        original_init = cls.__init__

        def new_init(self: Any) -> None:
            update_wrapper(self, metadata_source, updated=[])
            if override_name:
                self.__name__ = override_name
                self.__qualname__ = override_name
            original_init(self)

        cls.__init__ = new_init
        return cls

    return decorator


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


@preserve_metadata(SnowflakeConnection, override_name="connect")
class _AsyncConnectWrapper:
    """Preserves SnowflakeConnection.__init__ metadata for async connect function.

    This wrapper enables introspection tools and IDEs to see the same signature
    as the synchronous snowflake.connector.connect function.
    """

    def __init__(self) -> None: ...

    @wraps(SnowflakeConnection.__init__)
    def __call__(
        self, **kwargs: Any
    ) -> HybridCoroutineContextManager[SnowflakeConnection]:
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
