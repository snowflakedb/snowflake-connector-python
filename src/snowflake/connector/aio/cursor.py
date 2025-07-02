"""
Async Snowflake Cursor - True async cursor using composition.

This module provides AsyncSnowflakeCursor that wraps the synchronous
SnowflakeCursor to provide async I/O while automatically inheriting
all business logic from the base library.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional, Sequence

from ..cursor import SnowflakeCursor
from ..result_batch import create_batches_from_response
from .connection import AsyncSnowflakeConnection
from .result_batch import AsyncArrowResultBatch, AsyncJSONResultBatch
from .result_set import AsyncResultSet


class AsyncSnowflakeCursor:
    """
    Async Snowflake cursor that composes a sync cursor.
    
    Async version of: snowflake.connector.cursor.SnowflakeCursor
    
    This class wraps the synchronous SnowflakeCursor to provide true async I/O
    while automatically inheriting all business logic improvements from the base
    library. Only the network layer is replaced with aiohttp.
    """
    
    def __init__(self, async_connection: AsyncSnowflakeConnection) -> None:
        """
        Initialize async cursor by composing sync cursor.
        
        Async version of: SnowflakeCursor.__init__()
        
        Args:
            async_connection: The async connection that created this cursor
        """
        self._async_connection = async_connection
        # Create sync cursor for all business logic
        self._sync_cursor = SnowflakeCursor(async_connection._sync_connection)
        self._is_closed = False
        # Async result set for non-blocking result fetching
        self._async_result_set: Optional[AsyncResultSet] = None
        
    async def execute(
        self,
        command: str,
        params: Optional[Sequence[Any] | dict[Any, Any]] = None,
        **kwargs: Any
    ) -> 'AsyncSnowflakeCursor':
        """
        Execute SQL statement asynchronously.
        
        Async version of: SnowflakeCursor.execute()
        
        This method provides the core async execute functionality compatible
        with DB-API 2.0 and SQLAlchemy's async cursor interface.
        
        Args:
            command: SQL statement to execute
            params: Parameters for SQL statement
            **kwargs: Additional execution parameters
            
        Returns:
            Self for method chaining
            
        Raises:
            RuntimeError: If cursor is closed or connection not established
        """
        if self._is_closed:
            raise RuntimeError("Cursor is closed")
            
        if not self._async_connection._is_connected or not self._async_connection._async_rest_client:
            raise RuntimeError("Connection not established")
            
        # Use sync cursor for parameter processing (pure business logic)
        processed_command = command
        if params:
            # Delegate parameter binding to sync cursor
            processed_command = self._sync_cursor._preprocess_pyformat_query(command, params)
            
        # Generate sequence counter and request ID using sync connection logic
        sequence_counter = self._async_connection._sync_connection._next_sequence_counter()
        request_id = uuid.uuid4()
        
        # Extract execution parameters from kwargs (same as sync cursor)
        _no_results = kwargs.get('_exec_async', False)
        timeout = kwargs.get('timeout')
        statement_params = kwargs.get('_statement_params')
        is_internal = kwargs.get('_is_internal', False)
        describe_only = kwargs.get('_describe_only', False)
        
        # Execute via async network layer
        result = await self._async_connection._async_rest_client.cmd_query(
            sql=processed_command,
            sequence_counter=sequence_counter,
            request_id=request_id,
            statement_params=statement_params,
            is_internal=is_internal,
            describe_only=describe_only,
            _no_results=_no_results,
            timeout=timeout
        )
        
        # Initialize result metadata using sync cursor (pure business logic)
        self._sync_cursor._init_result_and_meta(result.get('data', {}))
        
        # Create async result set to replace blocking result fetching
        if result.get('data') and not _no_results:
            self._create_async_result_set(result['data'])
        else:
            self._async_result_set = None
        
        return self

    def _create_async_result_set(self, data: dict[str, Any]) -> None:
        """
        Create async result set from query response data.
        
        This replaces the sync result batches with async ones that use
        aiohttp for non-blocking downloads, fixing the critical blocking issue.
        """
        # Get result format and schema from sync cursor
        result_format = self._sync_cursor._query_result_format
        schema = getattr(self._sync_cursor, '_description', None) or []
        
        # Create async result batches from response
        async_batches = self._create_async_batches_from_response(
            result_format, data, schema
        )
        
        # Create async result set
        prefetch_threads = getattr(self._async_connection._sync_connection, '_prefetch_threads', 4)
        use_mp = getattr(self._async_connection._sync_connection, '_use_mp', False)
        
        self._async_result_set = AsyncResultSet(
            cursor=self,
            result_chunks=async_batches,
            prefetch_thread_num=prefetch_threads,
            use_mp=use_mp,
        )

    def _create_async_batches_from_response(
        self,
        _format: str,
        data: dict[str, Any],
        schema: Sequence[Any],
    ) -> list[AsyncJSONResultBatch | AsyncArrowResultBatch]:
        """
        Create async result batches from response data.
        
        This converts sync ResultBatch creation to async ResultBatch creation,
        replacing the blocking download mechanism with aiohttp.
        """
        # Reuse most of the sync logic for batch creation
        column_converters = []
        arrow_context = None
        rowtypes = data.get("rowtype", [])
        total_len: int = data.get("total", 0)
        first_chunk_len = total_len
        rest_of_chunks = []
        
        if _format == "json":
            def col_to_converter(col: dict[str, Any]) -> tuple[str, Any]:
                type_name = col["type"].upper()
                python_method = self._async_connection._sync_connection.converter.to_python_method(
                    type_name, col
                )
                return type_name, python_method

            column_converters = [col_to_converter(c) for c in rowtypes]
        else:
            rowset_b64 = data.get("rowsetBase64")
            from ..arrow_context import ArrowConverterContext
            arrow_context = ArrowConverterContext(
                self._async_connection._sync_connection._session_parameters
            )
            
        # Process remote chunks
        if "chunks" in data:
            chunks = data["chunks"]
            qrmk = data.get("qrmk")
            chunk_headers: dict[str, Any] = {}
            
            if "chunkHeaders" in data:
                chunk_headers = {}
                for header_key, header_value in data["chunkHeaders"].items():
                    chunk_headers[header_key] = header_value
            elif qrmk is not None:
                from ..result_batch import SSE_C_ALGORITHM, SSE_C_AES, SSE_C_KEY
                chunk_headers[SSE_C_ALGORITHM] = SSE_C_AES
                chunk_headers[SSE_C_KEY] = qrmk

            from ..result_batch import RemoteChunkInfo
            def remote_chunk_info(c: dict[str, Any]) -> RemoteChunkInfo:
                return RemoteChunkInfo(
                    url=c["url"],
                    uncompressedSize=c["uncompressedSize"],
                    compressedSize=c["compressedSize"],
                )

            if _format == "json":
                rest_of_chunks = [
                    AsyncJSONResultBatch(
                        c["rowCount"],
                        chunk_headers,
                        remote_chunk_info(c),
                        schema,
                        column_converters,
                        self._sync_cursor._use_dict_result,
                        json_result_force_utf8_decoding=self._async_connection._sync_connection._json_result_force_utf8_decoding,
                    )
                    for c in chunks
                ]
            else:
                rest_of_chunks = [
                    AsyncArrowResultBatch(
                        c["rowCount"],
                        chunk_headers,
                        remote_chunk_info(c),
                        arrow_context,
                        self._sync_cursor._use_dict_result,
                        self._async_connection._sync_connection._numpy,
                        schema,
                        self._async_connection._sync_connection._arrow_number_to_decimal,
                    )
                    for c in chunks
                ]
                
        # Calculate first chunk length
        for c in rest_of_chunks:
            first_chunk_len -= c.rowcount
            
        # Create first chunk (local data)
        if _format == "json":
            first_chunk = AsyncJSONResultBatch.from_data(
                data.get("rowset"),
                first_chunk_len,
                schema,
                column_converters,
                self._sync_cursor._use_dict_result,
            )
        elif rowset_b64 is not None:
            first_chunk = AsyncArrowResultBatch.from_data(
                rowset_b64,
                first_chunk_len,
                arrow_context,
                self._sync_cursor._use_dict_result,
                self._async_connection._sync_connection._numpy,
                schema,
                self._async_connection._sync_connection._arrow_number_to_decimal,
            )
        else:
            # Empty result set
            first_chunk = AsyncArrowResultBatch.from_data(
                "",
                0,
                arrow_context,
                self._sync_cursor._use_dict_result,
                self._async_connection._sync_connection._numpy,
                schema,
                self._async_connection._sync_connection._arrow_number_to_decimal,
            )

        return [first_chunk] + rest_of_chunks
        
    async def fetchone(self) -> Optional[tuple | dict]:
        """
        Fetch next row from query result using async result set.
        
        Async version of: SnowflakeCursor.fetchone()
        
        This method uses AsyncResultSet to fetch results without blocking
        the event loop, fixing the critical blocking issue.
        
        Returns:
            Next row as tuple or dict, None if no more rows
        """
        if self._is_closed:
            raise RuntimeError("Cursor is closed")
            
        if self._async_result_set is None:
            # No results to fetch (e.g., INSERT/UPDATE/DELETE)
            return None
            
        # Use async result set iterator to get next row
        try:
            if not hasattr(self, '_async_iterator'):
                self._async_iterator = self._async_result_set.__aiter__()
            return await self._async_iterator.__anext__()
        except StopAsyncIteration:
            return None
        
    async def fetchmany(self, size: Optional[int] = None) -> list[tuple | dict]:
        """
        Fetch multiple rows from query result using async result set.
        
        Async version of: SnowflakeCursor.fetchmany()
        
        This method uses AsyncResultSet to fetch results without blocking
        the event loop, fixing the critical blocking issue.
        
        Args:
            size: Number of rows to fetch (default: cursor.arraysize)
            
        Returns:
            List of rows
        """
        if self._is_closed:
            raise RuntimeError("Cursor is closed")
            
        if self._async_result_set is None:
            return []
            
        if size is None:
            size = self.arraysize
            
        rows = []
        for _ in range(size):
            row = await self.fetchone()
            if row is None:
                break
            rows.append(row)
        return rows
        
    async def fetchall(self) -> list[tuple | dict]:
        """
        Fetch all remaining rows from query result using async result set.
        
        Async version of: SnowflakeCursor.fetchall()
        
        This method uses optimized bulk fetching for large result sets
        to avoid row-by-row async iteration overhead.
        
        Returns:
            List of all remaining rows
        """
        if self._is_closed:
            raise RuntimeError("Cursor is closed")
            
        if self._async_result_set is None:
            return []
        
        # Use optimized bulk fetch for large result sets
        # This avoids the row-by-row async iteration overhead
        return await self._bulk_fetchall_async()
    
    async def _bulk_fetchall_async(self) -> list[tuple | dict]:
        """
        Optimized bulk fetch implementation that processes batches efficiently.
        
        This avoids the performance overhead of row-by-row async iteration
        by using bulk populate_data_async and processing batches concurrently.
        """
        all_rows = []
        
        # Process all batches concurrently for better performance  
        import asyncio
        
        async def process_batch_bulk(batch):
            """Process a single batch in bulk and return all its rows."""
            if batch._local:
                # Local batch - data already available
                return list(batch._data) if batch._data else []
            else:
                # Remote batch - populate data in bulk then return all rows
                await batch.populate_data_async(connection=self._async_connection)
                return list(batch._data) if batch._data else []
        
        # Create tasks for all batches to download concurrently
        batch_tasks = []
        for batch in self._async_result_set.batches:
            task = asyncio.create_task(process_batch_bulk(batch))
            batch_tasks.append(task)
        
        # Wait for all batches to complete
        if batch_tasks:
            batch_results = await asyncio.gather(*batch_tasks)
            # Flatten results maintaining order
            for batch_rows in batch_results:
                all_rows.extend(batch_rows)
        
        return all_rows
        
    async def close(self) -> None:
        """
        Close the cursor.
        
        Async version of: SnowflakeCursor.close()
        """
        self._sync_cursor.close()
        self._is_closed = True
        
    # Delegate properties to sync cursor for automatic updates
    
    @property
    def description(self):
        """
        Column descriptions.
        
        Delegates to: SnowflakeCursor.description
        """
        return self._sync_cursor.description
        
    @property
    def rowcount(self) -> int:
        """
        Number of rows affected by last operation.
        
        Delegates to: SnowflakeCursor.rowcount
        """
        return self._sync_cursor.rowcount
        
    @property
    def rownumber(self) -> Optional[int]:
        """Current row number."""
        return self._sync_cursor.rownumber
        
    @property
    def sfqid(self) -> Optional[str]:
        """
        Snowflake query ID.
        
        Delegates to: SnowflakeCursor.sfqid
        """
        return self._sync_cursor.sfqid
        
    @property
    def sqlstate(self) -> Optional[str]:
        """SQL state."""
        return self._sync_cursor.sqlstate
        
    @property
    def arraysize(self) -> int:
        """Number of rows to fetch in fetchmany()."""
        return self._sync_cursor.arraysize
        
    @arraysize.setter
    def arraysize(self, value: int) -> None:
        """Set arraysize."""
        self._sync_cursor.arraysize = value
        
    @property
    def connection(self) -> AsyncSnowflakeConnection:
        """The connection that created this cursor."""
        return self._async_connection
        
    def is_closed(self) -> bool:
        """Check if cursor is closed."""
        return self._is_closed
        
    def __repr__(self) -> str:
        """String representation of async cursor."""
        return f"<AsyncSnowflakeCursor(closed={self._is_closed})>"
        
    # Async iteration support (future enhancement)
    def __aiter__(self):
        """Async iterator support."""
        return self
        
    async def __anext__(self):
        """Async iteration."""
        row = await self.fetchone()
        if row is None:
            raise StopAsyncIteration
        return row