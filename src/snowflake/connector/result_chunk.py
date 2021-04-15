#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import json
import time
from enum import Enum, unique
from gzip import GzipFile
from logging import getLogger
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
)

from snowflake.connector.chunk_downloader import JsonBinaryHandler
from snowflake.connector.time_util import DecorrelateJitterBackoff, TimeCNM
from snowflake.connector.vendored import requests
from snowflake.connector.vendored.urllib3.util import parse_url

logger = getLogger(__name__)

MAX_DOWNLOAD_RETRY = 10
DOWNLOAD_TIMEOUT = 7  # seconds
AVAILABLE_RESULT_CHUNK_FORMATS = {"json", "arrow"}

if TYPE_CHECKING:  # pragma: no cover
    from snowflake.connector.converter import SnowflakeConverterType


@unique
class DownloadMetrics(Enum):
    """Defines the keywords by which to store metrics for chunks."""

    download = "download"  # Download time in milliseconds
    parse = "parse"  # Parsing time to final data types
    load = "load"  # Parsing time from initial type to intermediate types


class RemoteChunkInfo(NamedTuple):
    """Small class that holds information about chunks that are given by back-end."""

    url: str
    uncompressedSize: int
    compressedSize: int


class ResultChunk:
    """A chunk of a result set.

    TODO redo doc-string

    A ResultChunk can exist in 2 different states:
        1. It has all the information necessary to download its own data
        2. It either has it's data downloaded and parsed
    Most result chunks should start in state 1 and then when necessary transition
    themselves into state 2.
    """

    def __init__(
        self,
        rowcount: int,
        chunk_headers: Optional[Dict[str, str]],
        remote_chunk_info: Optional["RemoteChunkInfo"],
        converters: Optional[Sequence["SnowflakeConverterType"]],
        _format: str = "json",
    ):
        """Initialize ResultChunk with necessary state for state 1."""
        # Sanitize input
        if _format not in AVAILABLE_RESULT_CHUNK_FORMATS:
            raise AttributeError(f"Unavailable result chunk format: {_format}")
        self.rowcount = rowcount
        self._chunk_headers = chunk_headers
        self._remote_chunk_info = remote_chunk_info
        self._converters = converters
        self._data: Optional[List[List[Any, ...]]] = None
        self._format = _format
        self._metrics: Dict[str, int] = {}

    @classmethod
    def from_data(
        cls,
        data: Sequence[Sequence[Any]],
    ):
        """Initialize ResultChunk straight in state 2."""
        new_chunk = cls(len(data), None, None, None)
        new_chunk._data = data
        return new_chunk

    def __repr__(self) -> str:
        if self._local:
            return f"ResultChunk({self.rowcount})"
        else:
            path = parse_url(self._remote_chunk_info.url).path
            return f"ResultChunk({path.rsplit('/', 1)[1]})"

    @property
    def _local(self) -> bool:
        """Whether this chunk is local."""
        return self._data is not None

    @property
    def compressed_size(self) -> Optional[int]:
        """Returns the size of chunk in bytes in compressed form.

        If it's a local chunk this function returns None.
        """
        if self._remote_chunk_info:
            return self._remote_chunk_info.compressedSize
        return None

    @property
    def uncompressed_size(self) -> Optional[int]:
        """Returns the size of chunk in bytes in uncompressed form.

        If it's a local chunk this function returns None.
        """
        if self._remote_chunk_info:
            return self._remote_chunk_info.uncompressedSize
        return None

    def __iter__(self) -> Iterator[List[Any]]:
        """Returns an iterator through the data this chunk holds.

        In case of this being a local chunk it iterates through the local already parsed
        data and if it's a remote chunk it will download, parse its data and return an
        iterator for it.
        """
        return iter(self._download())

    def _download(self) -> List[List[Any]]:
        """Transition from phase 1 to 2 by downloading the data from blob storage.

        Note that this is a synchronous method. If parallelism is necessary caller
        should take care of that.
        """
        if self._local:
            return self._data
        sleep_timer = 1
        backoff = DecorrelateJitterBackoff(1, 16)
        binary_data_handler = (  # NOQA
            JsonBinaryHandler(is_raw_binary_iterator=True)
            if self._format == "json"
            else None
        )
        # TODO ArrowBinaryHandler(self._cursor, self._connection)
        for retry in range(MAX_DOWNLOAD_RETRY):
            try:
                with TimeCNM() as download_metric:
                    response = requests.get(
                        self._remote_chunk_info.url,
                        headers=self._chunk_headers,
                        timeout=DOWNLOAD_TIMEOUT,
                        stream=True,  # Default to non-streaming unless arrow
                    )
                    if response.ok:
                        break
            except Exception:
                if retry == MAX_DOWNLOAD_RETRY - 1:
                    # Re-throw if we failed on the last retry
                    raise
                sleep_timer = backoff.next_sleep(1, sleep_timer)
                logger.exception(
                    f"Failed to fetch the large result set chunk "
                    f"{self._remote_chunk_info.url} for the {retry + 1} th time, "
                    f"backing off for {sleep_timer}s"
                )
                time.sleep(sleep_timer)

        self._metrics[DownloadMetrics.download.value] = int(download_metric)
        # Load data to a intermediate form
        with TimeCNM() as load_metric:
            with GzipFile(fileobj=response.raw, mode="r") as gfd:
                if self._format == "json":
                    # Read in decompressed data
                    read_data: str = gfd.read().decode("utf-8", "replace")
                    downloaded_data = json.loads("".join(["[", read_data, "]"]))
                elif self._format == "arrow":
                    # TODO
                    downloaded_data = None
        self._metrics[DownloadMetrics.load.value] = int(load_metric)
        # Process downloaded data
        # TODO do we still parse for Arrow
        with TimeCNM() as parse_metric:
            parsed_data = [
                [c(d) for c, d in zip(self._converters, r)] for r in downloaded_data
            ]
        self._metrics[DownloadMetrics.parse.value] = int(parse_metric)
        return parsed_data
