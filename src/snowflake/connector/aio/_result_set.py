#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import inspect
from collections import deque
from logging import getLogger
from typing import (
    TYPE_CHECKING,
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Deque,
    Iterator,
    Literal,
    cast,
    overload,
)

from pandas import DataFrame
from pyarrow import Table

from snowflake.connector.aio._result_batch import (
    ArrowResultBatch,
    JSONResultBatch,
    ResultBatch,
)
from snowflake.connector.constants import IterUnit
from snowflake.connector.options import pandas
from snowflake.connector.result_set import ResultSet as ResultSetSync

from ..options import pyarrow as pa

if TYPE_CHECKING:
    from snowflake.connector.aio._cursor import SnowflakeCursor

logger = getLogger(__name__)


class ResultSetIterator:
    def __init__(
        self,
        first_batch_iter: Iterator[tuple],
        unfetched_batches: Deque[ResultBatch],
        final: Callable[[], Awaitable[None]],
        prefetch_thread_num: int,
        **kw: Any,
    ) -> None:
        self._is_fetch_all = kw.pop("is_fetch_all", False)
        self._first_batch_iter = first_batch_iter
        self._unfetched_batches = unfetched_batches
        self._final = final
        self._prefetch_thread_num = prefetch_thread_num
        self._kw = kw
        self._generator = self.generator()

    async def _download_all_batches(self):
        # try to download all the batches at one time, won't return until all the batches are downloaded
        tasks = []
        for result_batch in self._unfetched_batches:
            tasks.append(result_batch.create_iter(**self._kw))
            await asyncio.sleep(0)
        return tasks

    async def _download_batch_and_convert_to_list(self, result_batch):
        return list(await result_batch.create_iter(**self._kw))

    async def fetch_all_data(self):
        rets = list(self._first_batch_iter)
        tasks = [
            self._download_batch_and_convert_to_list(result_batch)
            for result_batch in self._unfetched_batches
        ]
        batches = await asyncio.gather(*tasks)
        for batch in batches:
            rets.extend(batch)
            # yield to avoid blocking the event loop for too long when processing large result sets
            # await asyncio.sleep(0)
        return rets

    async def generator(self):
        if self._is_fetch_all:

            tasks = await self._download_all_batches()
            for value in self._first_batch_iter:
                yield value

            new_batches = await asyncio.gather(*tasks)
            for batch in new_batches:
                for value in batch:
                    yield value

            await self._final()
        else:
            download_tasks = deque()
            for _ in range(len(self._unfetched_batches)):
                logger.debug(
                    f"queuing download of result batch id: {self._unfetched_batches[0].id}"
                )
                download_tasks.append(
                    asyncio.create_task(
                        self._unfetched_batches.popleft().create_iter(**self._kw)
                    )
                )

            for value in self._first_batch_iter:
                yield value

            i = 1
            while download_tasks:
                logger.debug(f"user requesting to consume result batch {i}")

                # Submit the next un-fetched batch to the pool
                if self._unfetched_batches:
                    logger.debug(
                        f"queuing download of result batch id: {self._unfetched_batches[0].id}"
                    )
                    download_tasks.append(
                        asyncio.create_task(
                            self._unfetched_batches.popleft().create_iter(**self._kw)
                        )
                    )

                task = download_tasks.popleft()
                # this will raise an exception if one has occurred
                batch_iterator = await task

                logger.debug(f"user began consuming result batch {i}")
                for value in batch_iterator:
                    yield value
                logger.debug(f"user finished consuming result batch {i}")
                i += 1
            await self._final()

    async def get_next(self):
        return await anext(self._generator, None)


class ResultSet(ResultSetSync):
    def __init__(
        self,
        cursor: SnowflakeCursor,
        result_chunks: list[JSONResultBatch] | list[ArrowResultBatch],
        prefetch_thread_num: int,
    ) -> None:
        super().__init__(cursor, result_chunks, prefetch_thread_num)
        self.batches = cast(
            list[JSONResultBatch] | list[ArrowResultBatch], self.batches
        )

    async def _create_iter(
        self,
        **kwargs,
    ) -> ResultSetIterator:
        """Set up a new iterator through all batches with first 5 chunks downloaded.

        This function is a helper function to ``__iter__`` and it was introduced for the
        cases where we need to propagate some values to later ``_download`` calls.
        """
        # pop is_fetch_all and pass it to result_set_iterator
        is_fetch_all = kwargs.pop("is_fetch_all", False)

        # add connection so that result batches can use sessions
        kwargs["connection"] = self._cursor.connection

        first_batch_iter = await self.batches[0].create_iter(**kwargs)

        # batches that have not been fetched
        unfetched_batches = deque(self.batches[1:])
        for num, batch in enumerate(unfetched_batches):
            logger.debug(f"result batch {num + 1} has id: {batch.id}")

        return ResultSetIterator(
            first_batch_iter,
            unfetched_batches,
            self._finish_iterating,
            self.prefetch_thread_num,
            is_fetch_all=is_fetch_all,
            **kwargs,
        )

    async def _fetch_arrow_batches(
        self,
    ) -> AsyncIterator[Table]:
        """Fetches all the results as Arrow Tables, chunked by Snowflake back-end."""
        self._can_create_arrow_iter()
        result_set_iterator = await self._create_iter(
            iter_unit=IterUnit.TABLE_UNIT, structure="arrow"
        )
        return result_set_iterator.generator()

    @overload
    async def _fetch_arrow_all(
        self, force_return_table: Literal[False]
    ) -> Table | None: ...

    @overload
    async def _fetch_arrow_all(self, force_return_table: Literal[True]) -> Table: ...

    async def _fetch_arrow_all(self, force_return_table: bool = False) -> Table | None:
        """Fetches a single Arrow Table from all of the ``ResultBatch``."""
        self._can_create_arrow_iter()
        result_set_iterator = await self._create_iter(
            iter_unit=IterUnit.TABLE_UNIT, structure="arrow"
        )
        tables = list(await result_set_iterator.fetch_all_data())
        if tables:
            return pa.concat_tables(tables)
        else:
            return self.batches[0].to_arrow() if force_return_table else None

    async def _fetch_pandas_batches(self, **kwargs) -> AsyncIterator[DataFrame]:
        self._can_create_arrow_iter()
        result_set_iterator = await self._create_iter(
            iter_unit=IterUnit.TABLE_UNIT, structure="pandas", **kwargs
        )
        return result_set_iterator.generator()

    async def _fetch_pandas_all(self, **kwargs) -> DataFrame:
        """Fetches a single Pandas dataframe."""
        result_set_iterator = await self._create_iter(
            iter_unit=IterUnit.TABLE_UNIT, structure="pandas", **kwargs
        )
        concat_args = list(inspect.signature(pandas.concat).parameters)
        concat_kwargs = {k: kwargs.pop(k) for k in dict(kwargs) if k in concat_args}
        dataframes = await result_set_iterator.fetch_all_data()
        if dataframes:
            return pandas.concat(
                dataframes,
                ignore_index=True,  # Don't keep in result batch indexes
                **concat_kwargs,
            )
        # Empty dataframe
        return self.batches[0].to_pandas(**kwargs)

    async def _finish_iterating(self) -> None:
        await self._report_metrics()

    async def _report_metrics(self) -> None:
        """Report metrics for the result set."""
        # TODO: SNOW-1572217 async telemetry
        super()._report_metrics()
