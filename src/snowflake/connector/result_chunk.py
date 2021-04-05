#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import json
import time
from enum import Enum, unique
from gzip import GzipFile
from logging import getLogger
from typing import Dict, List, NamedTuple, Optional, Union

from snowflake.connector.chunk_downloader import JsonBinaryHandler
from snowflake.connector.converter import SnowflakeConverter
from snowflake.connector.time_util import DecorrelateJitterBackoff, TimeCNM
from snowflake.connector.vendored import requests
from snowflake.connector.vendored.urllib3.util import parse_url

logger = getLogger(__name__)

MAX_DOWNLOAD_RETRY = 10
DOWNLOAD_TIMEOUT = 7  # seconds
AVAILABLE_RESULT_CHUNK_FORMATS = {"json", "arrow"}


@unique
class DownloadMetrics(Enum):
    """Defines the keywords by which to store metrics for chunks."""

    download = "download"  # Download time in milliseconds
    parse = "parse"  # Parsing time to final data types
    load = "load"  # Parsing time from initial type to intermediate types


class RemoteChunkInfo(NamedTuple):
    """Small class that holds information about chunks that are in phase 1."""

    url: str
    rowCount: int
    uncompressedSize: int
    compressedSize: int


class ResultChunk:
    """A chunk of a resultset.

    A ResultChunk can exist in 2 different states:
        1. It has all the information necessary to download its own data
        2. It either has it's data downloaded and parsed
    Most result chunks should start in state 1 and then when necessary transition themselves into state 2.
    """

    def __init__(
        self,
        chunk_headers: Optional[Dict[str, str]],
        remote_chunk_info: Optional[List["SnowflakeConverter"]],
        converters: Optional[Dict[str, Union[int, str]]],
        _format: str = "json",
    ):
        """Initialize ResultChunk with necessary state for state 1."""
        # Sanitize input
        if _format not in AVAILABLE_RESULT_CHUNK_FORMATS:
            raise AttributeError(f"Unavailable result chunk format: {_format}")
        # Set up class for state 1
        self._chunk_headers = chunk_headers
        self._remote_chunk_info = remote_chunk_info
        self._converters = converters
        self._data: Optional[List[List]] = None
        self._format = _format
        self._metrics: Dict[str, int] = {}

    @classmethod
    def from_data(
        cls,
        data: List[List],
    ):
        """Initialize ResultChunk straight in state 2."""
        new_chunk = cls(None, None, None)
        new_chunk._data = data
        return new_chunk

    def __repr__(self):
        """Make devs' lives easier. If not downloaded yet display file's basename and if downloaded display length."""
        if not self._downloaded:
            path = parse_url(self._remote_chunk_info.url).path
            return f"ResultChunk({path.rsplit('/', 1)[1]})"
        else:
            return f"ResultChunk({len(self)})"

    def __len__(self):
        if self._downloaded:
            return len(self._data)
        else:
            return 0

    @property
    def _downloaded(self) -> bool:
        """Whether this chunk has been transitioned to state 2."""
        return self._data is not None

    def __iter__(self):
        if not self._downloaded:
            self._download()
        return iter(self._data)

    def _download(self) -> None:
        """Transition from phase 1 to 2 by downloading the data from blob storage.

        Note that this is a synchronous method. If parallelism is necessary caller should take care of that.
        """
        if self._downloaded:
            return
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
                    f"Failed to fetch the large result set chunk {self._remote_chunk_info.url} "
                    f"for the {retry + 1} th time, backing off for {sleep_timer}s"
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
        with TimeCNM() as parse_metric:
            self._data = [
                [c(d) for c, d in zip(self._converters, r)] for r in downloaded_data
            ]
        self._metrics[DownloadMetrics.parse.value] = int(parse_metric)
        # After we transitioned out of state 1 remove now unnecessary info
        self._chunk_headers = None
        self._chunk_info = None
        self._converters = None
