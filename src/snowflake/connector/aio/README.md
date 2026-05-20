# Notice

**This component is a Preview feature provided for experimental purposes only.
It is provided "AS IS" and without warranty of any kind. This module is not
supported by Snowflake Support. Use of this code is at your own risk and it
is not intended for production environments.**

## Features NOT Supported


- ❌ `conn.errorhandler` (get/set) - no support for async errorhandlers
- ❌ `enable_connection_diag=True` - no connection diagnostic
- ❌ `authenticator='PAT_WITH_EXTERNAL_SESSION'` - not supported
- ❌ `mfa_callback` / `password_callback` - not supported
- ❌ `_probe_connection=True` - no connection diagnostic
- ❌ Raw binary response handling - not supported
- ❌ CRL (Certificate Revocation List) - not supported (only OCSP is supported)

## Installation & Import

Using aio version requires additional installation of `aiohttp` dependency.

```python
# Same package, different import
from snowflake.connector.aio import connect, SnowflakeConnection, DictCursor
```


## Connection Patterns


```python
# Pattern 1: Async context manager (recommended)
async with connect(user='...', password='...', account='...') as conn:
   # Use connection
   pass


# Pattern 2: Direct await
conn = await connect(user='...', password='...', account='...')
await conn.close()


# Pattern 3: Manual
conn = SnowflakeConnection(user='...', password='...', account='...')
await conn.connect()
await conn.close()
```


## Basic Operations Comparison


| Operation | Sync | Async |
|-----------|------|-------|
| **Connect** | `conn = connect(...)` | `conn = await connect(...)` |
| **Create cursor** | `cur = conn.cursor()` | `cur = conn.cursor()` *(same)* |
| **Execute** | `cur.execute(sql)` | `await cur.execute(sql)` |
| **Fetch one** | `cur.fetchone()` | `await cur.fetchone()` |
| **Fetch many** | `cur.fetchmany(n)` | `await cur.fetchmany(n)` |
| **Fetch all** | `cur.fetchall()` | `await cur.fetchall()` |
| **Iterate** | `for row in cur:` | `async for row in cur:` |
| **Commit** | `conn.commit()` | `await conn.commit()` |
| **Rollback** | `conn.rollback()` | `await conn.rollback()` |
| **Close** | `conn.close()` | `await conn.close()` |


## Quick Examples


### Simple Query


```python
import asyncio
from snowflake.connector.aio import connect


async def query_data():
   async with connect(user='...', password='...', account='...') as conn:
       async with conn.cursor() as cur:
           await cur.execute("SELECT * FROM table WHERE id < %s", (100,))
           async for row in cur:
               print(row)


asyncio.run(query_data())
```
