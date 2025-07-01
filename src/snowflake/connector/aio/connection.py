"""
Async Snowflake Connection - True async connection using composition.

This module provides AsyncSnowflakeConnection that wraps the synchronous
SnowflakeConnection to provide async I/O while automatically inheriting
all business logic from the base library.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from .. import SnowflakeConnection
from ..cursor import SnowflakeCursor
from ..time_util import get_time_millis
from .network import AsyncSnowflakeRestful


class AsyncSnowflakeConnection:
    """
    Async Snowflake connection that composes a sync connection.
    
    Async version of: snowflake.connector.connection.SnowflakeConnection
    
    This class wraps the synchronous SnowflakeConnection to provide true async I/O
    while automatically inheriting all business logic improvements from the base
    library. Only the network layer is replaced with aiohttp.
    """
    
    def __init__(self, **kwargs: Any) -> None:
        """
        Initialize async connection by composing sync connection.
        
        Async version of: SnowflakeConnection.__init__()
        
        Args:
            **kwargs: All connection parameters passed to sync SnowflakeConnection
        """
        # Compose sync connection for all business logic
        self._sync_connection = SnowflakeConnection(**kwargs)
        self._async_rest_client: Optional[AsyncSnowflakeRestful] = None
        self._is_connected = False
        
    async def connect(self) -> None:
        """
        Establish async connection to Snowflake.
        
        Async version of: SnowflakeConnection.connect()
        
        This replaces the sync connection's network layer with an async one
        while reusing all authentication logic.
        """
        # Create async REST client that wraps the sync connection
        self._async_rest_client = AsyncSnowflakeRestful(self._sync_connection)
        
        # Perform async authentication
        await self._async_rest_client.authenticate()
        self._is_connected = True
        
    async def commit(self) -> None:
        """
        Commit current transaction.
        
        Async version of: SnowflakeConnection.commit()
        """
        cursor = self.cursor()
        await cursor.execute("COMMIT")
        
    async def rollback(self) -> None:
        """
        Rollback current transaction.
        
        Async version of: SnowflakeConnection.rollback()
        """
        cursor = self.cursor()
        await cursor.execute("ROLLBACK")
        
    async def cmd_query(
        self,
        sql: str,
        sequence_counter: int,
        request_id: uuid.UUID,
        binding_params: None | tuple | dict[str, dict[str, str]] = None,
        binding_stage: str | None = None,
        is_file_transfer: bool = False,
        statement_params: dict[str, str] | None = None,
        is_internal: bool = False,
        describe_only: bool = False,
        _no_results: bool = False,
        _update_current_object: bool = True,
        _no_retry: bool = False,
        timeout: int | None = None,
        dataframe_ast: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute query via async HTTP request.
        
        Async version of: SnowflakeConnection.cmd_query()
        
        This method provides direct access to the async network layer for query execution.
        """
        if not self._is_connected or not self._async_rest_client:
            raise RuntimeError("Connection not established")
            
        return await self._async_rest_client.cmd_query(
            sql=sql,
            sequence_counter=sequence_counter,
            request_id=request_id,
            binding_params=binding_params,
            binding_stage=binding_stage,
            is_file_transfer=is_file_transfer,
            statement_params=statement_params,
            is_internal=is_internal,
            describe_only=describe_only,
            _no_results=_no_results,
            _update_current_object=_update_current_object,
            _no_retry=_no_retry,
            timeout=timeout,
            dataframe_ast=dataframe_ast,
        )
        
    async def close(self) -> None:
        """
        Close async connection and cleanup resources.
        
        Async version of: SnowflakeConnection.close()
        """
        if self._async_rest_client:
            await self._async_rest_client.close()
            self._async_rest_client = None
            
        # Close sync connection
        self._sync_connection.close()
        self._is_connected = False
        
    def cursor(self) -> 'AsyncSnowflakeCursor':
        """
        Create an async cursor for this connection.
        
        Async version of: SnowflakeConnection.cursor()
        
        Returns:
            AsyncSnowflakeCursor: New async cursor object
        """
        # Import here to avoid circular imports
        from .cursor import AsyncSnowflakeCursor
        return AsyncSnowflakeCursor(self)
        
    # Delegate properties to sync connection for automatic updates
    
    @property
    def session_id(self) -> Optional[str]:
        """
        Get session ID from sync connection.
        
        Delegates to: SnowflakeConnection.session_id
        """
        return self._sync_connection.session_id
        
    @property
    def user(self) -> Optional[str]:
        """
        Get username from sync connection.
        
        Delegates to: SnowflakeConnection.user
        """
        return self._sync_connection.user
        
    @property
    def account(self) -> Optional[str]:
        """
        Get account from sync connection.
        
        Delegates to: SnowflakeConnection.account
        """
        return self._sync_connection.account
        
    @property
    def database(self) -> Optional[str]:
        """Get database from sync connection."""
        return self._sync_connection.database
        
    @property
    def schema(self) -> Optional[str]:
        """Get schema from sync connection."""
        return self._sync_connection.schema
        
    @property
    def warehouse(self) -> Optional[str]:
        """Get warehouse from sync connection."""
        return self._sync_connection.warehouse
        
    @property
    def role(self) -> Optional[str]:
        """Get role from sync connection."""
        return self._sync_connection.role
        
    @property
    def host(self) -> str:
        """Get host from sync connection."""
        return self._sync_connection.host
        
    @property
    def port(self) -> int:
        """Get port from sync connection."""
        return self._sync_connection.port
        
    def is_closed(self) -> bool:
        """Check if connection is closed."""
        return not self._is_connected or self._sync_connection.is_closed()
        
    def __repr__(self) -> str:
        """String representation of async connection."""
        return f"<AsyncSnowflakeConnection(user='{self.user}', account='{self.account}', database='{self.database}')>"