# Async Connect Wrapper Implementation

## Overview

This document describes the hybrid wrapper pattern used to implement `snowflake.connector.aio.connect()` that preserves metadata from `SnowflakeConnection.__init__` while supporting both simple await and async context manager usage patterns with full coroutine protocol support.

## Problem Statement

The async version of `connect()` must:
1. Preserve metadata for IDE introspection and tooling (like the synchronous version)
2. Support `conn = await aio.connect(...)` pattern
3. Support `async with aio.connect(...) as conn:` pattern
4. Implement the full coroutine protocol for ecosystem compatibility (following aiohttp's pattern)

## Architecture

```
connect = _AsyncConnectWrapper()
    ↓ (calls __call__)
_AsyncConnectContextManager (implements HybridCoroutineContextManager protocol)
    ├─ Coroutine Protocol: send(), throw(), close(), __await__(), __iter__()
    └─ Async Context Manager: __aenter__(), __aexit__()
```

## Key Components

### HybridCoroutineContextManager Protocol

Combines PEP 492 (coroutine) and PEP 343 (async context manager) protocols. Allows the same object to be managed by external code expecting either interface (e.g., timeout handlers, async schedulers).

### _AsyncConnectContextManager

Implements `HybridCoroutineContextManager[SnowflakeConnection]`:
- **`send()`, `throw()`, `close()`** - Forward to inner coroutine for ecosystem compatibility
- **`__await__()`** - Enable `await` syntax
- **`__aenter__()` / `__aexit__()`** - Enable async context manager usage

### preserve_metadata Decorator

Copies `__wrapped__`, `__doc__`, `__module__`, `__annotations__` from a source class to instances during `__init__`. Allows instances to be introspected like the source class's `__init__`, enabling IDE support and tooling.

### _AsyncConnectWrapper

Callable wrapper decorated with `@preserve_metadata(SnowflakeConnection)` to preserve metadata. Its `__call__` method creates and returns a `_AsyncConnectContextManager` instance.

## Design Rationale

### Why Full Coroutine Protocol?

External async code (timeout handlers, async schedulers, introspection tools) expects `send()`, `throw()`, and `close()` methods. Without these, our wrapper breaks compatibility and may fail at runtime with code like:
```python
result = await asyncio.wait_for(aio.connect(...), timeout=5.0)  # May call throw()
```

### Why Preserve Metadata?

- IDEs show correct function signature when hovering over `connect`
- `help(connect)` displays proper docstring
- `inspect.signature(connect)` works correctly
- Static type checkers recognize parameters

### Why Both Await and Context Manager?

- **Await pattern:** Simple, lightweight for one-off connections
- **Context manager pattern:** Ensures cleanup via `__aexit__`, safer for resource management

## Usage Patterns

```python
# Pattern 1: Simple await
conn = await aio.connect(account="myaccount", user="user", password="pass")
result = await conn.cursor().execute("SELECT 1")
await conn.close()

# Pattern 2: Async context manager (recommended)
async with aio.connect(account="myaccount", user="user", password="pass") as conn:
    result = await conn.cursor().execute("SELECT 1")
    # Auto-closes on exit
```

## Implementation Details

### __slots__ = ("_coro", "_conn")
Memory efficient, especially when many connections are created.

### Inner Coroutine Function
```python
async def _connect_coro() -> SnowflakeConnection:
    conn = SnowflakeConnection(**kwargs)
    await conn.connect()
    return conn
```
Defers connection creation and establishment until await time, not at `connect()` call time.

## Verification

```python
# Metadata preservation
assert connect.__name__ == "connect"
assert hasattr(connect, "__wrapped__")
assert callable(connect)

# Return type is hybrid awaitable + context manager
result = connect(account="test")
assert hasattr(result, "__await__")    # Awaitable
assert hasattr(result, "__aenter__")   # Async context manager
assert hasattr(result, "send")         # Full coroutine protocol
```

## Backwards Compatibility

- ✅ Existing code using `await aio.connect(...)` works unchanged
- ✅ Metadata available for IDE tooltips and introspection
- ✅ Full coroutine protocol support for advanced/external tooling
- ✅ No breaking changes

## File Location

`src/snowflake/connector/aio/__init__.py`
