"""
Async Snowflake Connector - True async/await interface using aiohttp.

This module provides async variants of the Snowflake connector classes that use
composition to wrap the sync classes, ensuring automatic updates from the base
library while providing true async I/O through aiohttp.
"""

from __future__ import annotations

from typing import Any

from .connection import AsyncSnowflakeConnection
from .cursor import AsyncSnowflakeCursor
from .auth import AsyncAuthByDefault, AsyncAuthByKeyPair


async def connect(**kwargs: Any) -> AsyncSnowflakeConnection:
    """
    Create an async connection to Snowflake.
    
    This function creates an AsyncSnowflakeConnection that wraps the synchronous
    SnowflakeConnection, providing true async I/O while automatically inheriting
    all business logic improvements from the base library.
    
    Args:
        **kwargs: Connection parameters (same as sync connector)
            - user: Snowflake username
            - password: Password or authenticator-specific credential  
            - account: Snowflake account identifier
            - database: Default database name
            - schema: Default schema name
            - warehouse: Default warehouse name
            - role: Default role name
            - And all other parameters from sync connector
            
    Returns:
        AsyncSnowflakeConnection: Connected async connection object
        
    Example:
        >>> import snowflake.connector.aio
        >>> conn = await snowflake.connector.aio.connect(
        ...     user='myuser',
        ...     password='mypassword', 
        ...     account='myaccount',
        ...     database='mydatabase'
        ... )
        >>> cursor = conn.cursor()
        >>> await cursor.execute("SELECT 1")
        >>> row = await cursor.fetchone()
        >>> await conn.close()
    """
    connection = AsyncSnowflakeConnection(**kwargs)
    await connection.connect()
    return connection


__all__ = ['connect', 'AsyncSnowflakeConnection', 'AsyncSnowflakeCursor', 'AsyncAuthByDefault', 'AsyncAuthByKeyPair']