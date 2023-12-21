import abc
import json
import aiohttp
import asyncio
from typing import TYPE_CHECKING, Iterator, Sequence, Any
from logging import getLogger

from .converter import SnowflakeConverterType
from .cursor import SnowflakeCursor, ResultMetadata
from .event_loop_runner import LOOP_RUNNER
from .backoff_policies import DEFAULT_TIMEOUT_GENERATOR_FUNCTION
from .compat import OK, UNAUTHORIZED
from .network import is_retryable_http_code, get_http_retryable_error, RetryRequest, raise_okta_unauthorized_error, \
    raise_failed_request_error
from .network_async import make_client_session, get_default_aiohttp_session_request_kwargs, \
    raise_okta_unauthorized_error_async, raise_failed_request_error_async
from .result_batch import ResultBatch, MAX_DOWNLOAD_RETRY, DOWNLOAD_TIMEOUT, DownloadMetrics, JSONResultBatch, \
    SSE_C_ALGORITHM, SSE_C_AES, SSE_C_KEY, RemoteChunkInfo, ArrowResultBatch
from .secret_detector import SecretDetector
from .time_util import TimerContextManager
from .errors import Error

logger = getLogger(__name__)

from pandas import DataFrame
from .connection import SnowflakeConnection

# YICHUAN: Same deal as always; aiohttp implementation of ResultBatch and JSONResultBatch (no Arrow support currently)
# The structure is the same as storage_client_async and s3_storage_client_async so see those for explanations

class ResultBatchAsync(ResultBatch):
    async def _download_async(
        self, connection: SnowflakeConnection | None = None, **kwargs
    ) -> aiohttp.ClientResponse:
        """Downloads the data that the ``ResultBatch`` is pointing at."""
        sleep_timer = 1
        backoff = (
            connection._backoff_generator
            if connection is not None
            else DEFAULT_TIMEOUT_GENERATOR_FUNCTION()
        )
        for retry in range(MAX_DOWNLOAD_RETRY):
            try:
                with TimerContextManager() as download_metric:
                    logger.debug(f"started downloading result batch id: {self.id}")
                    chunk_url = self._remote_chunk_info.url
                    request_data = {
                        "url": chunk_url,
                        "headers": self._chunk_headers,
                        "timeout": DOWNLOAD_TIMEOUT,
                    }
                    # Try to reuse a connection if possible
                    if connection and connection._rest is not None:
                        logger.debug(
                            f"downloading result batch id: {self.id} with existing session from connection"
                        )
                        session_manager = connection._rest._use_requests_session_async(chunk_url)
                    else:
                        logger.debug(
                            f"downloading result batch id: {self.id} with new session"
                        )
                        session_manager = make_client_session()

                    async with session_manager as session:
                        response = await session.request(
                            method="get",
                            **(
                                request_data
                                | get_default_aiohttp_session_request_kwargs(url=chunk_url)
                            ),
                        )

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
                        raise_okta_unauthorized_error_async(None, response)
                    else:
                        raise_failed_request_error_async(None, chunk_url, "get", response)

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

        self._metrics[
            DownloadMetrics.download.value
        ] = download_metric.get_timing_millis()
        return response

    def create_iter(
        self, **kwargs
    ) -> (
        Iterator[dict | Exception]
        | Iterator[tuple | Exception]
        | Iterator[DataFrame]
    ):
        return LOOP_RUNNER.run_coro(self.create_iter_async(**kwargs))

    @abc.abstractmethod
    async def create_iter_async(
            self, **kwargs
    ) -> (
            Iterator[dict | Exception]
            | Iterator[tuple | Exception]
            | Iterator[DataFrame]
    ):
        """Downloads the data from blob storage that this ResultChunk points at.

        This function is the one that does the actual work for ``self.__iter__``.

        It is necessary because a ``ResultBatch`` can return multiple types of
        iterators. A good example of this is simply iterating through
        ``SnowflakeCursor`` and calling ``fetch_pandas_batches`` on it.
        """
        raise NotImplementedError()

class JSONResultBatchAsync(ResultBatchAsync, JSONResultBatch):
    async def _load_async(self, response: aiohttp.ClientResponse) -> list:
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
            read_data = await response.text()
        return json.loads("".join(["[", read_data, "]"]))

    async def create_iter_async(
        self, connection: SnowflakeConnection | None = None, **kwargs
    ) -> Iterator[dict | Exception] | Iterator[tuple | Exception]:
        if self._local:
            return iter(self._data)

        response = await self._download_async(connection=connection)

        # Load data to a intermediate form
        logger.debug(f"started loading result batch id: {self.id}")
        with TimerContextManager() as load_metric:
            downloaded_data = await self._load_async(response)

        logger.debug(f"finished loading result batch id: {self.id}")
        self._metrics[DownloadMetrics.load.value] = load_metric.get_timing_millis()
        # Process downloaded data
        with TimerContextManager() as parse_metric:
            parsed_data = self._parse(downloaded_data)
        self._metrics[DownloadMetrics.parse.value] = parse_metric.get_timing_millis()
        return iter(parsed_data)

def create_batches_from_response_async(
    cursor: SnowflakeCursor,
    _format: str,
    data: dict[str, Any],
    schema: Sequence[ResultMetadata],
) -> list[ResultBatchAsync]:
    column_converters: list[tuple[str, SnowflakeConverterType]] = []
    rowtypes = data["rowtype"]
    total_len: int = data.get("total", 0)
    first_chunk_len = total_len
    rest_of_chunks: list[ResultBatchAsync] = []
    if _format != "json":
        raise Exception("Non-JSON formats not supported for ResultBatchAsync")

    def col_to_converter(col: dict[str, Any]) -> tuple[str, SnowflakeConverterType]:
        type_name = col["type"].upper()
        python_method = cursor._connection.converter.to_python_method(
            type_name, col
        )
        return type_name, python_method

    column_converters = [col_to_converter(c) for c in rowtypes]

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

        rest_of_chunks = [
            JSONResultBatchAsync(
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

    for c in rest_of_chunks:
        first_chunk_len -= c.rowcount

    first_chunk = JSONResultBatchAsync.from_data(
        data.get("rowset"),
        first_chunk_len,
        schema,
        column_converters,
        cursor._use_dict_result,
    )

    return [first_chunk] + rest_of_chunks