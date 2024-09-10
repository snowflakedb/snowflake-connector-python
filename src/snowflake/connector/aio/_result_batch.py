#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import abc
import asyncio
import json
from logging import getLogger
from typing import TYPE_CHECKING, Any, AsyncIterator, Iterator, Sequence

import aiohttp

from snowflake.connector import Error
from snowflake.connector.aio._network import (
    raise_failed_request_error,
    raise_okta_unauthorized_error,
)
from snowflake.connector.aio._time_util import TimerContextManager
from snowflake.connector.arrow_context import ArrowConverterContext
from snowflake.connector.backoff_policies import exponential_backoff
from snowflake.connector.compat import OK, UNAUTHORIZED
from snowflake.connector.constants import IterUnit
from snowflake.connector.converter import SnowflakeConverterType
from snowflake.connector.cursor import ResultMetadataV2
from snowflake.connector.network import (
    RetryRequest,
    get_http_retryable_error,
    is_retryable_http_code,
)
from snowflake.connector.result_batch import (
    MAX_DOWNLOAD_RETRY,
    SSE_C_AES,
    SSE_C_ALGORITHM,
    SSE_C_KEY,
)
from snowflake.connector.result_batch import ArrowResultBatch as ArrowResultBatchSync
from snowflake.connector.result_batch import DownloadMetrics
from snowflake.connector.result_batch import JSONResultBatch as JSONResultBatchSync
from snowflake.connector.result_batch import RemoteChunkInfo
from snowflake.connector.result_batch import ResultBatch as ResultBatchSync
from snowflake.connector.result_batch import _create_nanoarrow_iterator
from snowflake.connector.secret_detector import SecretDetector

if TYPE_CHECKING:
    from pandas import DataFrame
    from pyarrow import Table

    from snowflake.connector.aio._connection import SnowflakeConnection
    from snowflake.connector.aio._cursor import SnowflakeCursor

logger = getLogger(__name__)


# TODO: consolidate this with the sync version
def create_batches_from_response(
    cursor: SnowflakeCursor,
    _format: str,
    data: dict[str, Any],
    schema: Sequence[ResultMetadataV2],
) -> list[ResultBatch]:
    column_converters: list[tuple[str, SnowflakeConverterType]] = []
    arrow_context: ArrowConverterContext | None = None
    rowtypes = data["rowtype"]
    total_len: int = data.get("total", 0)
    first_chunk_len = total_len
    rest_of_chunks: list[ResultBatch] = []
    if _format == "json":

        def col_to_converter(col: dict[str, Any]) -> tuple[str, SnowflakeConverterType]:
            type_name = col["type"].upper()
            python_method = cursor._connection.converter.to_python_method(
                type_name, col
            )
            return type_name, python_method

        column_converters = [col_to_converter(c) for c in rowtypes]
    else:
        rowset_b64 = data.get("rowsetBase64")
        arrow_context = ArrowConverterContext(cursor._connection._session_parameters)
    if "chunks" in data:
        chunks = data["chunks"]
        logger.debug(f"chunk size={len(chunks)}")
        # prepare the downloader for further fetch
        qrmk = data.get("qrmk")
        chunk_headers: dict[str, Any] = {}
        if "chunkHeaders" in data:
            chunk_headers = {}
            for header_key, header_value in data["chunkHeaders"].items():
                chunk_headers[header_key] = header_value
                if "encryption" not in header_key:
                    logger.debug(
                        f"added chunk header: key={header_key}, value={header_value}"
                    )
        elif qrmk is not None:
            logger.debug(f"qrmk={SecretDetector.mask_secrets(qrmk)}")
            chunk_headers[SSE_C_ALGORITHM] = SSE_C_AES
            chunk_headers[SSE_C_KEY] = qrmk

        def remote_chunk_info(c: dict[str, Any]) -> RemoteChunkInfo:
            return RemoteChunkInfo(
                url=c["url"],
                uncompressedSize=c["uncompressedSize"],
                compressedSize=c["compressedSize"],
            )

        if _format == "json":
            rest_of_chunks = [
                JSONResultBatch(
                    c["rowCount"],
                    chunk_headers,
                    remote_chunk_info(c),
                    schema,
                    column_converters,
                    cursor._use_dict_result,
                    json_result_force_utf8_decoding=cursor._connection._json_result_force_utf8_decoding,
                )
                for c in chunks
            ]
        else:
            rest_of_chunks = [
                ArrowResultBatch(
                    c["rowCount"],
                    chunk_headers,
                    remote_chunk_info(c),
                    arrow_context,
                    cursor._use_dict_result,
                    cursor._connection._numpy,
                    schema,
                    cursor._connection._arrow_number_to_decimal,
                )
                for c in chunks
            ]
    for c in rest_of_chunks:
        first_chunk_len -= c.rowcount
    if _format == "json":
        first_chunk = JSONResultBatch.from_data(
            data.get("rowset"),
            first_chunk_len,
            schema,
            column_converters,
            cursor._use_dict_result,
        )
    elif rowset_b64 is not None:
        first_chunk = ArrowResultBatch.from_data(
            rowset_b64,
            first_chunk_len,
            arrow_context,
            cursor._use_dict_result,
            cursor._connection._numpy,
            schema,
            cursor._connection._arrow_number_to_decimal,
        )
    else:
        logger.error(f"Don't know how to construct ResultBatches from response: {data}")
        first_chunk = ArrowResultBatch.from_data(
            "",
            0,
            arrow_context,
            cursor._use_dict_result,
            cursor._connection._numpy,
            schema,
            cursor._connection._arrow_number_to_decimal,
        )

    return [first_chunk] + rest_of_chunks


class ResultBatch(ResultBatchSync):
    pass

    @abc.abstractmethod
    async def create_iter(
        self, **kwargs
    ) -> (
        AsyncIterator[dict | Exception]
        | AsyncIterator[tuple | Exception]
        | AsyncIterator[Table]
        | AsyncIterator[DataFrame]
    ):
        """Downloads the data from blob storage that this ResultChunk points at.

        This function is the one that does the actual work for ``self.__iter__``.

        It is necessary because a ``ResultBatch`` can return multiple types of
        iterators. A good example of this is simply iterating through
        ``SnowflakeCursor`` and calling ``fetch_pandas_batches`` on it.
        """
        raise NotImplementedError()

    async def _download(
        self, connection: SnowflakeConnection | None = None, **kwargs
    ) -> aiohttp.ClientResponse:
        """Downloads the data that the ``ResultBatch`` is pointing at."""
        sleep_timer = 1
        backoff = (
            connection._backoff_generator
            if connection is not None
            else exponential_backoff()()
        )
        for retry in range(MAX_DOWNLOAD_RETRY):
            try:
                # TODO: feature parity with download timeout setting, in sync it's set to 7s
                #  but in async we schedule multiple tasks at the same time so some tasks might
                #  take longer than 7s to finish which is expected
                async with TimerContextManager() as download_metric:
                    logger.debug(f"started downloading result batch id: {self.id}")
                    chunk_url = self._remote_chunk_info.url
                    request_data = {
                        "url": chunk_url,
                        "headers": self._chunk_headers,
                        # "timeout": DOWNLOAD_TIMEOUT,
                    }
                    # Try to reuse a connection if possible
                    if connection and connection._rest is not None:
                        async with connection._rest._use_requests_session() as session:
                            logger.debug(
                                f"downloading result batch id: {self.id} with existing session {session}"
                            )
                            response = await session.request("get", **request_data)
                    else:
                        logger.debug(
                            f"downloading result batch id: {self.id} with new session"
                        )
                        async with aiohttp.ClientSession() as session:
                            response = await session.get(**request_data)

                    if response.status == OK:
                        logger.debug(
                            f"successfully downloaded result batch id: {self.id}"
                        )
                        break

                    # Raise error here to correctly go in to exception clause
                    if is_retryable_http_code(response.status):
                        # retryable server exceptions
                        error: Error = get_http_retryable_error(response.status)
                        raise RetryRequest(error)
                    elif response.status == UNAUTHORIZED:
                        # make a unauthorized error
                        raise_okta_unauthorized_error(None, response)
                    else:
                        raise_failed_request_error(None, chunk_url, "get", response)

            except (RetryRequest, Exception) as e:
                if retry == MAX_DOWNLOAD_RETRY - 1:
                    # Re-throw if we failed on the last retry
                    e = e.args[0] if isinstance(e, RetryRequest) else e
                    raise e
                sleep_timer = next(backoff)
                logger.exception(
                    f"Failed to fetch the large result set batch "
                    f"{self.id} for the {retry + 1} th time, "
                    f"backing off for {sleep_timer}s for the reason: '{e}'"
                )
                await asyncio.sleep(sleep_timer)

        self._metrics[DownloadMetrics.download.value] = (
            download_metric.get_timing_millis()
        )
        return response


class JSONResultBatch(ResultBatch, JSONResultBatchSync):
    async def create_iter(
        self, connection: SnowflakeConnection | None = None, **kwargs
    ) -> Iterator[dict | Exception] | Iterator[tuple | Exception]:
        if self._local:
            return iter(self._data)
        response = await self._download(connection=connection)
        # Load data to a intermediate form
        logger.debug(f"started loading result batch id: {self.id}")
        async with TimerContextManager() as load_metric:
            downloaded_data = await self._load(response)
        logger.debug(f"finished loading result batch id: {self.id}")
        self._metrics[DownloadMetrics.load.value] = load_metric.get_timing_millis()
        # Process downloaded data
        async with TimerContextManager() as parse_metric:
            parsed_data = self._parse(downloaded_data)
        self._metrics[DownloadMetrics.parse.value] = parse_metric.get_timing_millis()
        return iter(parsed_data)

    async def _load(self, response: aiohttp.ClientResponse) -> list:
        """This function loads a compressed JSON file into memory.

        Returns:
            Whatever ``json.loads`` return, but in a list.
            Unfortunately there's no type hint for this.
            For context: https://github.com/python/typing/issues/182
        """
        # if users specify how to decode the data, we decode the bytes using the specified encoding
        if self._json_result_force_utf8_decoding:
            try:
                read_data = str(await response.read(), "utf-8", errors="strict")
            except Exception as exc:
                err_msg = f"failed to decode json result content due to error {exc!r}"
                logger.error(err_msg)
                raise Error(msg=err_msg)
        else:
            # note: SNOW-787480 response.apparent_encoding is unreliable, chardet.detect can be wrong which is used by
            # response.text to decode content, check issue: https://github.com/chardet/chardet/issues/148
            read_data = await response.text()
        return json.loads("".join(["[", read_data, "]"]))


class ArrowResultBatch(ResultBatch, ArrowResultBatchSync):
    async def _load(
        self, response: aiohttp.ClientResponse, row_unit: IterUnit
    ) -> Iterator[dict | Exception] | Iterator[tuple | Exception]:
        """Creates a ``PyArrowIterator`` from a response.

        This is used to iterate through results in different ways depending on which
        mode that ``PyArrowIterator`` is in.
        """
        return _create_nanoarrow_iterator(
            await response.read(),
            self._context,
            self._use_dict_result,
            self._numpy,
            self._number_to_decimal,
            row_unit,
        )

    async def _create_iter(
        self, iter_unit: IterUnit, connection: SnowflakeConnection | None = None
    ) -> Iterator[dict | Exception] | Iterator[tuple | Exception] | Iterator[Table]:
        """Create an iterator for the ResultBatch. Used by get_arrow_iter."""
        """Create an iterator for the ResultBatch. Used by get_arrow_iter."""
        if self._local:
            try:
                return self._from_data(self._data, iter_unit)
            except Exception:
                if connection and getattr(connection, "_debug_arrow_chunk", False):
                    logger.debug(f"arrow data can not be parsed: {self._data}")
                raise
        response = await self._download(connection=connection)
        logger.debug(f"started loading result batch id: {self.id}")
        async with TimerContextManager() as load_metric:
            try:
                loaded_data = await self._load(response, iter_unit)
            except Exception:
                if connection and getattr(connection, "_debug_arrow_chunk", False):
                    logger.debug(f"arrow data can not be parsed: {response}")
                raise
        logger.debug(f"finished loading result batch id: {self.id}")
        self._metrics[DownloadMetrics.load.value] = load_metric.get_timing_millis()
        return loaded_data

    async def _get_pandas_iter(
        self, connection: SnowflakeConnection | None = None, **kwargs
    ) -> Iterator[DataFrame]:
        """An iterator for this batch which yields a pandas DataFrame"""
        iterator_data = []
        dataframe = await self.to_pandas(connection=connection, **kwargs)
        if not dataframe.empty:
            iterator_data.append(dataframe)
        return iter(iterator_data)

    async def _get_arrow_iter(
        self, connection: SnowflakeConnection | None = None
    ) -> Iterator[Table]:
        """Returns an iterator for this batch which yields a pyarrow Table"""
        return await self._create_iter(
            iter_unit=IterUnit.TABLE_UNIT, connection=connection
        )

    async def to_arrow(self, connection: SnowflakeConnection | None = None) -> Table:
        """Returns this batch as a pyarrow Table"""
        val = next(await self._get_arrow_iter(connection=connection), None)
        if val is not None:
            return val
        return self._create_empty_table()

    async def to_pandas(
        self, connection: SnowflakeConnection | None = None, **kwargs
    ) -> DataFrame:
        """Returns this batch as a pandas DataFrame"""
        self._check_can_use_pandas()
        table = await self.to_arrow(connection=connection)
        return table.to_pandas(**kwargs)

    async def create_iter(
        self, connection: SnowflakeConnection | None = None, **kwargs
    ) -> (
        Iterator[dict | Exception]
        | Iterator[tuple | Exception]
        | Iterator[Table]
        | Iterator[DataFrame]
    ):
        """The interface used by ResultSet to create an iterator for this ResultBatch."""
        iter_unit: IterUnit = kwargs.pop("iter_unit", IterUnit.ROW_UNIT)
        if iter_unit == IterUnit.TABLE_UNIT:
            structure = kwargs.pop("structure", "pandas")
            if structure == "pandas":
                return await self._get_pandas_iter(connection=connection, **kwargs)
            else:
                return await self._get_arrow_iter(connection=connection)
        else:
            return await self._create_iter(iter_unit=iter_unit, connection=connection)
