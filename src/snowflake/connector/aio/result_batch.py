"""
Async Result Batch - True async result fetching using aiohttp.

This module provides AsyncResultBatch classes that replace the blocking
requests.get() calls in the sync ResultBatch._download() method with
non-blocking aiohttp downloads, fixing the critical blocking issue.
"""

from __future__ import annotations

import abc
import asyncio
import json
import time
from base64 import b64decode
from logging import getLogger
from typing import TYPE_CHECKING, Any, AsyncIterator, Iterator, Sequence

import aiohttp

from ..arrow_context import ArrowConverterContext
from ..backoff_policies import exponential_backoff
from ..compat import OK, UNAUTHORIZED
from ..constants import IterUnit
from ..errorcode import ER_FAILED_TO_CONVERT_ROW_TO_PYTHON_TYPE
from ..errors import Error, InterfaceError, ProgrammingError
from ..network import (
    RetryRequest,
    get_http_retryable_error,
    is_retryable_http_code,
    raise_failed_request_error,
    raise_okta_unauthorized_error,
)
from ..result_batch import (
    DOWNLOAD_TIMEOUT,
    MAX_DOWNLOAD_RETRY,
    DownloadMetrics,
    RemoteChunkInfo,
    _create_nanoarrow_iterator,
)
from ..time_util import TimerContextManager

if TYPE_CHECKING:  # pragma: no cover
    from pandas import DataFrame
    from pyarrow import Table

    from ..cursor import ResultMetadataV2
    from .connection import AsyncSnowflakeConnection

logger = getLogger(__name__)


class AsyncResultBatch(abc.ABC):
    """
    Async version of ResultBatch with non-blocking downloads.
    
    Replaces sync ResultBatch._download() with aiohttp for true async I/O.
    This fixes the critical blocking issue where result fetching blocked
    the event loop.
    """

    def __init__(
        self,
        rowcount: int,
        chunk_headers: dict[str, str] | None,
        remote_chunk_info: RemoteChunkInfo | None,
        schema: Sequence[ResultMetadataV2],
        use_dict_result: bool,
    ) -> None:
        self.rowcount = rowcount
        self._chunk_headers = chunk_headers
        self._remote_chunk_info = remote_chunk_info
        self._schema = schema
        self.schema = (
            [s._to_result_metadata_v1() for s in schema] if schema is not None else None
        )
        self._use_dict_result = use_dict_result
        self._metrics: dict[str, int] = {}
        self._data: str | list[tuple[Any, ...]] | None = None
        
        if self._remote_chunk_info:
            from ..compat import urlparse
            parsed_url = urlparse(self._remote_chunk_info.url)
            path_parts = parsed_url.path.rsplit("/", 1)
            self.id = path_parts[-1]
        else:
            self.id = str(self.rowcount)

    @property
    def _local(self) -> bool:
        """Whether this chunk is local."""
        return self._data is not None

    @property
    def compressed_size(self) -> int | None:
        """Returns the size of chunk in bytes in compressed form."""
        if self._local:
            return None
        return self._remote_chunk_info.compressedSize

    @property
    def uncompressed_size(self) -> int | None:
        """Returns the size of chunk in bytes in uncompressed form."""
        if self._local:
            return None
        return self._remote_chunk_info.uncompressedSize

    @property
    def column_names(self) -> list[str]:
        return [col.name for col in self._schema]

    async def _download_async(
        self, 
        connection: AsyncSnowflakeConnection | None = None,
        session: aiohttp.ClientSession | None = None
    ) -> aiohttp.ClientResponse:
        """
        Downloads the data that the AsyncResultBatch is pointing at using aiohttp.
        
        This replaces the blocking requests.get() call with non-blocking aiohttp,
        fixing the critical event loop blocking issue.
        """
        sleep_timer = 1
        backoff = (
            connection._sync_connection._backoff_generator
            if connection is not None
            else exponential_backoff()()
        )
        
        # Use provided session or create new one
        close_session = session is None
        if session is None:
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT)
            )
        
        # Start download timing outside retry loop to capture total time
        download_metric = TimerContextManager()
        download_metric.__enter__()
        
        try:
            for retry in range(MAX_DOWNLOAD_RETRY):
                try:
                    logger.debug(f"started downloading result batch id: {self.id}")
                    chunk_url = self._remote_chunk_info.url
                    
                    async with session.get(
                        chunk_url,
                        headers=self._chunk_headers
                    ) as response:
                        if response.status == OK:
                            logger.debug(
                                f"successfully downloaded result batch id: {self.id}"
                            )
                            # Read response content and return mock response object
                            content = await response.read()
                            
                            # Create mock response object compatible with sync code
                            class MockResponse:
                                def __init__(self, content: bytes, status_code: int, text: str):
                                    self.content = content
                                    self.status_code = status_code
                                    self.text = text
                                    
                            try:
                                text_content = content.decode('utf-8')
                            except UnicodeDecodeError:
                                text_content = content.decode('utf-8', errors='replace')
                                
                            mock_response = MockResponse(content, response.status, text_content)
                            
                            # End timing measurement and store it
                            download_metric.__exit__(None, None, None)
                            self._metrics[DownloadMetrics.download.value] = download_metric.get_timing_millis()
                            
                            return mock_response

                        # Handle retryable errors
                        if is_retryable_http_code(response.status):
                            error: Error = get_http_retryable_error(response.status)
                            raise RetryRequest(error)
                        elif response.status == UNAUTHORIZED:
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
        except Exception:
            # If an error occurred, still end the timing measurement
            download_metric.__exit__(None, None, None)
            self._metrics[DownloadMetrics.download.value] = download_metric.get_timing_millis()
            raise
        finally:
            if close_session:
                await session.close()

    @abc.abstractmethod
    async def create_iter_async(
        self, connection: AsyncSnowflakeConnection | None = None, **kwargs
    ) -> AsyncIterator[dict | Exception] | AsyncIterator[tuple | Exception]:
        """
        Async version of create_iter() that yields results without blocking.
        
        This method downloads data asynchronously and yields results as they
        become available, preventing event loop blocking.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    async def populate_data_async(
        self, connection: AsyncSnowflakeConnection | None = None, **kwargs
    ) -> 'AsyncResultBatch':
        """
        Downloads the data that the AsyncResultBatch is pointing at and populates it into self._data.
        Returns the instance itself.
        """
        raise NotImplementedError()

    def _check_can_use_pandas(self) -> None:
        """Check if pandas is available for DataFrame operations."""
        from ..options import installed_pandas
        from ..errorcode import ER_NO_PYARROW
        
        if not installed_pandas:
            msg = (
                "Optional dependency: 'pandas' is not installed, please see the following link for install "
                "instructions: https://docs.snowflake.com/en/user-guide/python-connector-pandas.html#installation"
            )
            errno = ER_NO_PYARROW

            raise Error.errorhandler_make_exception(
                ProgrammingError,
                {
                    "msg": msg,
                    "errno": errno,
                },
            )

    @abc.abstractmethod
    async def to_pandas_async(
        self, connection: AsyncSnowflakeConnection | None = None
    ) -> 'DataFrame':
        """Async version of to_pandas()."""
        raise NotImplementedError()

    @abc.abstractmethod
    async def to_arrow_async(
        self, connection: AsyncSnowflakeConnection | None = None
    ) -> 'Table':
        """Async version of to_arrow()."""
        raise NotImplementedError()


class AsyncJSONResultBatch(AsyncResultBatch):
    """
    Async version of JSONResultBatch with non-blocking downloads.
    
    Replaces sync JSONResultBatch._download() with aiohttp for true async I/O.
    """

    def __init__(
        self,
        rowcount: int,
        chunk_headers: dict[str, str] | None,
        remote_chunk_info: RemoteChunkInfo | None,
        schema: Sequence[ResultMetadataV2],
        column_converters: Sequence[tuple[str, Any]],
        use_dict_result: bool,
        *,
        json_result_force_utf8_decoding: bool = False,
    ) -> None:
        super().__init__(
            rowcount,
            chunk_headers,
            remote_chunk_info,
            schema,
            use_dict_result,
        )
        self._json_result_force_utf8_decoding = json_result_force_utf8_decoding
        self.column_converters = column_converters

    @classmethod
    def from_data(
        cls,
        data: Sequence[Sequence[Any]],
        data_len: int,
        schema: Sequence[ResultMetadataV2],
        column_converters: Sequence[tuple[str, Any]],
        use_dict_result: bool,
    ):
        """Initializes an AsyncJSONResultBatch from static, local data."""
        new_chunk = cls(
            len(data),
            None,
            None,
            schema,
            column_converters,
            use_dict_result,
        )
        new_chunk._data = new_chunk._parse(data)
        return new_chunk

    def _load(self, response) -> list:
        """Load a compressed JSON file into memory."""
        if self._json_result_force_utf8_decoding:
            try:
                read_data = str(response.content, "utf-8", errors="strict")
            except Exception as exc:
                err_msg = f"failed to decode json result content due to error {exc!r}"
                logger.error(err_msg)
                raise Error(msg=err_msg)
        else:
            read_data = response.text
        return json.loads("".join(["[", read_data, "]"]))

    def _parse(
        self, downloaded_data
    ) -> list[dict | Exception] | list[tuple | Exception]:
        """Parse downloaded data into its final form."""
        logger.debug(f"parsing for result batch id: {self.id}")
        result_list = []
        if self._use_dict_result:
            for row in downloaded_data:
                row_result = {}
                try:
                    for (_t, c), v, col in zip(
                        self.column_converters,
                        row,
                        self._schema,
                    ):
                        row_result[col.name] = v if c is None or v is None else c(v)
                    result_list.append(row_result)
                except Exception as error:
                    msg = f"Failed to convert: field {col.name}: {_t}::{v}, Error: {error}"
                    logger.exception(msg)
                    result_list.append(
                        Error.errorhandler_make_exception(
                            InterfaceError,
                            {
                                "msg": msg,
                                "errno": ER_FAILED_TO_CONVERT_ROW_TO_PYTHON_TYPE,
                            },
                        )
                    )
        else:
            for row in downloaded_data:
                row_result = [None] * len(self._schema)
                try:
                    idx = 0
                    for (_t, c), v, _col in zip(
                        self.column_converters,
                        row,
                        self._schema,
                    ):
                        row_result[idx] = v if c is None or v is None else c(v)
                        idx += 1
                    result_list.append(tuple(row_result))
                except Exception as error:
                    msg = f"Failed to convert: field {_col.name}: {_t}::{v}, Error: {error}"
                    logger.exception(msg)
                    result_list.append(
                        Error.errorhandler_make_exception(
                            InterfaceError,
                            {
                                "msg": msg,
                                "errno": ER_FAILED_TO_CONVERT_ROW_TO_PYTHON_TYPE,
                            },
                        )
                    )
        return result_list

    async def _fetch_data_async(
        self, connection: AsyncSnowflakeConnection | None = None, **kwargs
    ) -> list[dict | Exception] | list[tuple | Exception]:
        """Async version of _fetch_data() using aiohttp."""
        response = await self._download_async(connection=connection)
        
        # Load data to intermediate form
        logger.debug(f"started loading result batch id: {self.id}")
        with TimerContextManager() as load_metric:
            downloaded_data = self._load(response)
        logger.debug(f"finished loading result batch id: {self.id}")
        self._metrics[DownloadMetrics.load.value] = load_metric.get_timing_millis()
        
        # Process downloaded data
        with TimerContextManager() as parse_metric:
            parsed_data = self._parse(downloaded_data)
        self._metrics[DownloadMetrics.parse.value] = parse_metric.get_timing_millis()
        
        return parsed_data

    async def populate_data_async(
        self, connection: AsyncSnowflakeConnection | None = None, **kwargs
    ) -> 'AsyncJSONResultBatch':
        """Async version of populate_data()."""
        self._data = await self._fetch_data_async(connection=connection, **kwargs)
        return self

    async def create_iter_async(
        self, connection: AsyncSnowflakeConnection | None = None, **kwargs
    ) -> AsyncIterator[dict | Exception] | AsyncIterator[tuple | Exception]:
        """Async version of create_iter()."""
        if self._local:
            for item in self._data:
                yield item
        else:
            data = await self._fetch_data_async(connection=connection, **kwargs)
            for item in data:
                yield item

    async def to_pandas_async(
        self, connection: AsyncSnowflakeConnection | None = None
    ) -> 'DataFrame':
        """Async version of to_pandas() - not supported for JSON batches."""
        from ..errors import NotSupportedError
        raise NotSupportedError(
            f"Trying to use arrow fetching on {type(self)} which "
            f"is not ArrowResultChunk"
        )

    async def to_arrow_async(
        self, connection: AsyncSnowflakeConnection | None = None
    ) -> 'Table':
        """Async version of to_arrow() - not supported for JSON batches."""
        from ..errors import NotSupportedError
        raise NotSupportedError(
            f"Trying to use arrow fetching on {type(self)} which "
            f"is not ArrowResultChunk"
        )

    def __repr__(self) -> str:
        return f"AsyncJSONResultBatch({self.id})"


class AsyncArrowResultBatch(AsyncResultBatch):
    """
    Async version of ArrowResultBatch with non-blocking downloads.
    
    Replaces sync ArrowResultBatch._download() with aiohttp for true async I/O.
    """

    def __init__(
        self,
        rowcount: int,
        chunk_headers: dict[str, str] | None,
        remote_chunk_info: RemoteChunkInfo | None,
        context: ArrowConverterContext,
        use_dict_result: bool,
        numpy: bool,
        schema: Sequence[ResultMetadataV2],
        number_to_decimal: bool,
    ) -> None:
        super().__init__(
            rowcount,
            chunk_headers,
            remote_chunk_info,
            schema,
            use_dict_result,
        )
        self._context = context
        self._numpy = numpy
        self._number_to_decimal = number_to_decimal

    def _load(
        self, response, row_unit: IterUnit
    ) -> Iterator[dict | Exception] | Iterator[tuple | Exception]:
        """Create a PyArrowIterator from a response."""
        return _create_nanoarrow_iterator(
            response.content,
            self._context,
            self._use_dict_result,
            self._numpy,
            self._number_to_decimal,
            row_unit,
        )

    def _from_data(
        self,
        data: str | bytes,
        iter_unit: IterUnit,
        check_error_on_every_column: bool = True,
    ) -> Iterator[dict | Exception] | Iterator[tuple | Exception]:
        """Create a PyArrowIterator from string data."""
        if len(data) == 0:
            return iter([])

        if isinstance(data, str):
            data = b64decode(data)

        return _create_nanoarrow_iterator(
            data,
            self._context,
            self._use_dict_result,
            self._numpy,
            self._number_to_decimal,
            iter_unit,
            check_error_on_every_column,
        )

    @classmethod
    def from_data(
        cls,
        data: str,
        data_len: int,
        context: ArrowConverterContext,
        use_dict_result: bool,
        numpy: bool,
        schema: Sequence[ResultMetadataV2],
        number_to_decimal: bool,
    ):
        """Initialize an AsyncArrowResultBatch from static, local data."""
        new_chunk = cls(
            data_len,
            None,
            None,
            context,
            use_dict_result,
            numpy,
            schema,
            number_to_decimal,
        )
        new_chunk._data = data
        return new_chunk

    async def _create_iter_async(
        self,
        iter_unit: IterUnit,
        connection: AsyncSnowflakeConnection | None = None,
    ) -> AsyncIterator[dict | Exception] | AsyncIterator[tuple | Exception] | AsyncIterator['Table']:
        """Async version of _create_iter()."""
        if self._local:
            try:
                sync_iterator = self._from_data(
                    self._data,
                    iter_unit,
                    (
                        connection._sync_connection.check_arrow_conversion_error_on_every_column
                        if connection
                        else None
                    ),
                )
                for item in sync_iterator:
                    yield item
            except Exception:
                if connection and getattr(connection._sync_connection, "_debug_arrow_chunk", False):
                    logger.debug(f"arrow data can not be parsed: {self._data}")
                raise
        else:
            response = await self._download_async(connection=connection)
            logger.debug(f"started loading result batch id: {self.id}")
            
            # Time only the data loading, not the iteration
            with TimerContextManager() as load_metric:
                try:
                    loaded_data = self._load(response, iter_unit)
                except Exception:
                    if connection and getattr(connection._sync_connection, "_debug_arrow_chunk", False):
                        logger.debug(f"arrow data can not be parsed: {response}")
                    raise
            
            # Store load timing after loading is complete
            self._metrics[DownloadMetrics.load.value] = load_metric.get_timing_millis()
            logger.debug(f"finished loading result batch id: {self.id}")
            
            # Yield data items (not timed)
            for item in loaded_data:
                yield item

    async def _get_arrow_iter_async(
        self, connection: AsyncSnowflakeConnection | None = None
    ) -> AsyncIterator['Table']:
        """Async version of _get_arrow_iter()."""
        async for item in self._create_iter_async(iter_unit=IterUnit.TABLE_UNIT, connection=connection):
            yield item

    async def to_arrow_async(
        self, connection: AsyncSnowflakeConnection | None = None
    ) -> 'Table':
        """Async version of to_arrow()."""
        async for val in self._get_arrow_iter_async(connection=connection):
            return val
        
        # Return empty table if no data
        from ..options import pyarrow as pa
        from ..constants import FIELD_TYPES
        
        fields = [
            pa.field(s.name, FIELD_TYPES[s.type_code].pa_type(s))
            for s in self._schema
        ]
        return pa.schema(fields).empty_table()

    async def to_pandas_async(
        self, connection: AsyncSnowflakeConnection | None = None, **kwargs
    ) -> 'DataFrame':
        """Async version of to_pandas()."""
        self._check_can_use_pandas()
        table = await self.to_arrow_async(connection=connection)
        return table.to_pandas(**kwargs)

    async def create_iter_async(
        self, connection: AsyncSnowflakeConnection | None = None, **kwargs
    ) -> (
        AsyncIterator[dict | Exception]
        | AsyncIterator[tuple | Exception] 
        | AsyncIterator['Table']
        | AsyncIterator['DataFrame']
    ):
        """Async version of create_iter()."""
        iter_unit: IterUnit = kwargs.pop("iter_unit", IterUnit.ROW_UNIT)
        if iter_unit == IterUnit.TABLE_UNIT:
            structure = kwargs.pop("structure", "pandas")
            if structure == "pandas":
                # Return single DataFrame as async iterator
                dataframe = await self.to_pandas_async(connection=connection, **kwargs)
                if not dataframe.empty:
                    yield dataframe
            else:
                async for item in self._get_arrow_iter_async(connection=connection):
                    yield item
        else:
            async for item in self._create_iter_async(iter_unit=iter_unit, connection=connection):
                yield item

    async def populate_data_async(
        self, connection: AsyncSnowflakeConnection | None = None, **kwargs
    ) -> 'AsyncArrowResultBatch':
        """Async version of populate_data()."""
        response = await self._download_async(connection=connection)
        self._data = response.content
        return self

    def __repr__(self) -> str:
        return f"AsyncArrowResultBatch({self.id})"