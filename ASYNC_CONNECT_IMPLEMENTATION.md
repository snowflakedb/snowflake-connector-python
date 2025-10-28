# Async Connect Wrapper Implementation

## Overview

This document describes the hybrid wrapper pattern used to implement `snowflake.connector.aio.connect()` that preserves metadata from `SnowflakeConnection.__init__` while supporting both simple await and async context manager usage patterns, with full coroutine protocol support.

## Problem Statement

The synchronous `snowflake.connector.connect()` uses:
```python
@wraps(SnowflakeConnection.__init__)
def Connect(**kwargs) -> SnowflakeConnection:
    return SnowflakeConnection(**kwargs)
```

The async version cannot be decorated with `@wraps` on a raw async function. We needed a solution that:
1. Preserves metadata for IDE introspection and tooling
2. Supports `conn = await aio.connect(...)`
3. Supports `async with aio.connect(...) as conn:`
4. Implements the full coroutine protocol (following aiohttp's pattern)

## Implementation

### Architecture

```
connect = _AsyncConnectWrapper()
    ↓ (calls __call__)
_AsyncConnectContextManager (coroutine wrapper)
    ├─ Coroutine Protocol: send(), throw(), close()
    ├─ __await__(), __iter__()
    └─ __aenter__(), __aexit__() (async context manager)
```

### Class: _AsyncConnectContextManager

Makes a coroutine both awaitable and an async context manager, while implementing the full coroutine protocol.

```python
class _AsyncConnectContextManager:
    """Hybrid wrapper that enables both awaiting and async context manager usage.

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
        """Enable: conn = await connect(...)"""
        return self._coro.__await__()

    def __iter__(self) -> Generator[Any, None, SnowflakeConnection]:
        """Make the wrapper iterable like a coroutine."""
        return self.__await__()

    async def __aenter__(self) -> SnowflakeConnection:
        """Enable: async with connect(...) as conn:"""
        self._conn = await self._coro
        return await self._conn.__aenter__()

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Exit async context manager."""
        if self._conn is not None:
            return await self._conn.__aexit__(exc_type, exc, tb)
```

#### Coroutine Protocol Methods

- **`send(arg)`**: Send a value into the wrapped coroutine (used for manual coroutine driving)
- **`throw(*args, **kwargs)`**: Throw an exception into the wrapped coroutine
- **`close()`**: Gracefully close the wrapped coroutine
- **`__await__()`**: Return a generator to enable `await` syntax
- **`__iter__()`**: Make the wrapper iterable (some async utilities require this)

### Class: _AsyncConnectWrapper

Callable wrapper that preserves `SnowflakeConnection.__init__` metadata.

```python
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
        self.__annotations__ = getattr(SnowflakeConnection.__init__, "__annotations__", {})

    @wraps(SnowflakeConnection.__init__)
    def __call__(self, **kwargs: Any) -> _AsyncConnectContextManager:
        """Create and connect to a Snowflake connection asynchronously."""
        async def _connect_coro() -> SnowflakeConnection:
            conn = SnowflakeConnection(**kwargs)
            await conn.connect()
            return conn

        return _AsyncConnectContextManager(_connect_coro())
```

## Usage Patterns

### Pattern 1: Simple Await (No Context Manager)
```python
conn = await aio.connect(
    account="myaccount",
    user="myuser",
    password="mypassword"
)
result = await conn.cursor().execute("SELECT 1")
await conn.close()
```

**Flow:**
1. `aio.connect(...)` returns `_AsyncConnectContextManager`
2. `await` calls `__await__()`, returns inner coroutine result
3. `conn` is a `SnowflakeConnection` object
4. Wrapper is garbage collected

### Pattern 2: Async Context Manager
```python
async with aio.connect(
    account="myaccount",
    user="myuser",
    password="mypassword"
) as conn:
    result = await conn.cursor().execute("SELECT 1")
    # Auto-closes on exit
```

**Flow:**
1. `aio.connect(...)` returns `_AsyncConnectContextManager`
2. `async with` calls `__aenter__()`, awaits coroutine, returns connection
3. Code block executes
4. `async with` calls `__aexit__()` on exit

### Pattern 3: Manual Coroutine Driving (Advanced)
```python
# For advanced use cases with manual iteration
coro_wrapper = aio.connect(account="myaccount", user="user", password="pass")
# Can use send(), throw(), close() methods directly if needed
```

## Key Design Decisions

### 1. Metadata Copying in `__init__`
```python
self.__wrapped__ = SnowflakeConnection.__init__
self.__name__ = "connect"
# ...
```
**Why:** Allows direct attribute access for introspection before calling `__call__`

### 2. `@wraps` Decorator on `__call__`
```python
@wraps(SnowflakeConnection.__init__)
def __call__(self, **kwargs: Any) -> _AsyncConnectContextManager:
```
**Why:** IDEs and inspection tools that examine `__call__` see correct metadata

### 3. Inner Coroutine Function
```python
async def _connect_coro() -> SnowflakeConnection:
    conn = SnowflakeConnection(**kwargs)
    await conn.connect()
    return conn
```
**Why:** Defers connection creation and establishment until await time, not at `connect()` call time

### 4. `__slots__` on Context Manager
```python
__slots__ = ("_coro", "_conn")
```
**Why:** Memory efficient, especially when many connections are created

### 5. Full Coroutine Protocol
Following aiohttp's `_RequestContextManager` pattern, we implement `send()`, `throw()`, and `close()` methods. This ensures:
- Maximum compatibility with async utilities and libraries
- Support for manual coroutine driving if needed
- Proper cleanup and exception handling

## Comparison with aiohttp's _RequestContextManager

Our implementation follows the same proven pattern used by aiohttp:

| Feature | aiohttp | Our Implementation |
|---------|---------|-------------------|
| `send()` method | ✓ | ✓ |
| `throw()` method | ✓ | ✓ |
| `close()` method | ✓ | ✓ |
| `__await__()` method | ✓ | ✓ |
| `__iter__()` method | ✓ | ✓ |
| `__aenter__()` method | ✓ | ✓ |
| `__aexit__()` method | ✓ | ✓ |
| Metadata preservation | N/A | ✓ |

## Behavior Comparison

| Aspect | Pattern 1 | Pattern 2 | Pattern 3 |
|--------|-----------|-----------|-----------|
| Syntax | `conn = await aio.connect(...)` | `async with aio.connect(...) as conn:` | Manual iteration |
| Connection Object | In local scope | In context scope | Via wrapper |
| Cleanup | Manual (`await conn.close()`) | Automatic (`__aexit__`) | Manual |
| Metadata Available | Yes | Yes | Yes |
| Error Handling | Manual try/except | Automatic via context manager | Manual |
| Use Case | Simple connections | Resource management | Advanced/testing |

## Verification

```python
# Metadata preservation
assert connect.__name__ == "connect"
assert hasattr(connect, "__wrapped__")
assert callable(connect)

# Return type validation
result = connect(account="test")
assert hasattr(result, "__await__")        # Awaitable
assert hasattr(result, "__aenter__")       # Async context manager
assert hasattr(result, "__aexit__")        # Async context manager

# Full coroutine protocol
assert hasattr(result, "send")             # Coroutine protocol
assert hasattr(result, "throw")            # Exception injection
assert hasattr(result, "close")            # Cleanup
assert hasattr(result, "__iter__")         # Iteration support
```

## File Location

`src/snowflake/connector/aio/__init__.py`

## Backwards Compatibility

- ✅ Existing code using `await aio.connect(...)` works unchanged
- ✅ New code can use `async with aio.connect(...) as conn:`
- ✅ Metadata available for IDE tooltips and introspection tools
- ✅ Signature matches synchronous version in tooling
- ✅ Full coroutine protocol support for advanced use cases

## Benefits

✅ **Full Coroutine Protocol** - Compatible with all async utilities and libraries
✅ **Flexible Usage** - Simple await or async context manager patterns
✅ **Metadata Preservation** - IDE tooltips and introspection support
✅ **Transparent & Efficient** - Minimal overhead, garbage collected after use
✅ **Backwards Compatible** - No breaking changes to existing code
✅ **Battle-tested Pattern** - Follows aiohttp's proven design
