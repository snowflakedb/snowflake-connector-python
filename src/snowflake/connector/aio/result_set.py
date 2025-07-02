"""
Async Result Set - True async result set iteration.

This module provides AsyncResultSet that provides async iteration over
result batches without blocking the event loop, fixing the critical
blocking issue in result fetching.
"""

from __future__ import annotations

import asyncio
from collections import deque
from logging import getLogger
from typing import TYPE_CHECKING, Any, AsyncIterator, Deque, Iterator

from ..constants import IterUnit
from .result_batch import AsyncArrowResultBatch, AsyncJSONResultBatch, AsyncResultBatch

if TYPE_CHECKING:  # pragma: no cover
    from pandas import DataFrame
    from pyarrow import Table

    from .cursor import AsyncSnowflakeCursor

logger = getLogger(__name__)


async def async_result_set_iterator(
    first_batch_iter: AsyncIterator[tuple],
    unconsumed_batches: Deque[AsyncResultBatch],
    connection: Any | None = None,
    **kw: Any,
) -> AsyncIterator[dict | Exception] | AsyncIterator[tuple | Exception] | AsyncIterator['Table']:
    """
    Creates an async iterator over result batches.
    
    This provides async iteration over result batches using aiohttp
    for downloads, preventing event loop blocking.
    """
    # Yield from first batch
    async for item in first_batch_iter:
        yield item
        
    # Process remaining batches asynchronously
    while unconsumed_batches:
        batch = unconsumed_batches.popleft()
        logger.debug(f"user requesting to consume result batch {batch.id}")
        
        # Use async iterator for non-blocking batch processing
        async for item in batch.create_iter_async(connection=connection, **kw):
            yield item
        
        logger.debug(f"user finished consuming result batch {batch.id}")


class AsyncResultSet:
    """
    Async version of ResultSet with non-blocking result iteration.
    
    This class replaces the sync ResultSet to provide true async iteration
    over result batches using aiohttp for downloads, fixing the critical
    blocking issue where result fetching blocked the event loop.
    """

    def __init__(
        self,
        cursor: 'AsyncSnowflakeCursor',
        result_chunks: list[AsyncJSONResultBatch] | list[AsyncArrowResultBatch],
        prefetch_thread_num: int,
        use_mp: bool,
    ) -> None:
        self.batches = result_chunks
        self._cursor = cursor
        self.prefetch_thread_num = prefetch_thread_num
        self._use_mp = use_mp

    def _can_create_arrow_iter(self) -> None:
        """Check if arrow iteration is supported."""
        head_type = type(self.batches[0])
        if head_type != AsyncArrowResultBatch:
            from ..errors import NotSupportedError
            raise NotSupportedError(
                f"Trying to use arrow fetching on {head_type} which "
                f"is not AsyncArrowResultBatch"
            )

    async def _fetch_arrow_batches(self) -> AsyncIterator['Table']:
        """Fetch all results as Arrow Tables asynchronously."""
        self._can_create_arrow_iter()
        async for item in self._create_iter_async(iter_unit=IterUnit.TABLE_UNIT, structure="arrow"):
            yield item

    async def _fetch_arrow_all(self, force_return_table: bool = False) -> 'Table | None':
        """Fetch a single Arrow Table from all batches asynchronously."""
        from ..options import pyarrow as pa
        
        tables = []
        async for table in self._fetch_arrow_batches():
            tables.append(table)
            
        if tables:
            return pa.concat_tables(tables)
        else:
            return await self.batches[0].to_arrow_async() if force_return_table else None

    async def _fetch_pandas_batches(self, **kwargs) -> AsyncIterator['DataFrame']:
        """Fetch Pandas dataframes in batches asynchronously."""
        self._can_create_arrow_iter()
        async for item in self._create_iter_async(
            iter_unit=IterUnit.TABLE_UNIT, structure="pandas", **kwargs
        ):
            yield item

    async def _fetch_pandas_all(self, **kwargs) -> 'DataFrame':
        """Fetch a single Pandas dataframe asynchronously."""
        from ..options import pandas
        import inspect
        
        concat_args = list(inspect.signature(pandas.concat).parameters)
        concat_kwargs = {k: kwargs.pop(k) for k in dict(kwargs) if k in concat_args}
        
        dataframes = []
        async for df in self._fetch_pandas_batches(**kwargs):
            dataframes.append(df)
            
        if dataframes:
            return pandas.concat(
                dataframes,
                ignore_index=True,
                **concat_kwargs,
            )
        # Empty dataframe
        return await self.batches[0].to_pandas_async(**kwargs)

    def _get_metrics(self) -> dict[str, int]:
        """Sum up all the chunks' metrics."""
        overall_metrics: dict[str, int] = {}
        for c in self.batches:
            for n, v in c._metrics.items():
                overall_metrics[n] = overall_metrics.get(n, 0) + v
        return overall_metrics

    def __aiter__(self) -> 'AsyncResultSet':
        """Returns self for async iteration."""
        self._async_iter = None
        return self
        
    async def __anext__(self) -> tuple:
        """Get next item from async iterator."""
        if self._async_iter is None:
            self._async_iter = self._create_iter_async()
        return await self._async_iter.__anext__()

    def _create_iter_async(
        self,
        **kwargs,
    ) -> (
        AsyncIterator[dict | Exception]
        | AsyncIterator[tuple | Exception]
        | AsyncIterator['Table']
        | AsyncIterator['DataFrame']
    ):
        """
        Set up async iterator through all batches.
        
        This function provides async iteration without blocking the event loop,
        using aiohttp for result batch downloads.
        """
        # Add connection so that result batches can use sessions
        kwargs["connection"] = self._cursor._async_connection

        # Create async iterator for first batch
        first_batch_iter = self.batches[0].create_iter_async(**kwargs)

        # Batches that have not been fetched
        unfetched_batches = deque(self.batches[1:])
        for num, batch in enumerate(unfetched_batches):
            logger.debug(f"result batch {num + 1} has id: {batch.id}")

        return async_result_set_iterator(
            first_batch_iter,
            unfetched_batches,
            **kwargs,
        )

    def total_row_index(self) -> int:
        """Returns the total rowcount of the AsyncResultSet."""
        total = 0
        for p in self.batches:
            total += p.rowcount
        return total