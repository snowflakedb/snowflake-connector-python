#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import json
import time
from collections import namedtuple
from concurrent.futures.thread import ThreadPoolExecutor
from gzip import GzipFile
from logging import getLogger
from threading import Condition, Lock

from snowflake.connector.gzip_decoder import decompress_raw_data

from .arrow_context import ArrowConverterContext
from .errorcode import ER_CHUNK_DOWNLOAD_FAILED
from .errors import Error, OperationalError
from .time_util import get_time_millis, DecorrelateJitterBackoff

DEFAULT_REQUEST_TIMEOUT = 7

DEFAULT_CLIENT_PREFETCH_THREADS = 4
MAX_CLIENT_PREFETCH_THREADS = 10

MAX_RETRY_DOWNLOAD = 10
MAX_WAIT = 360
WAIT_TIME_IN_SECONDS = 10

SSE_C_ALGORITHM = u"x-amz-server-side-encryption-customer-algorithm"
SSE_C_KEY = u"x-amz-server-side-encryption-customer-key"
SSE_C_AES = u"AES256"

SnowflakeChunk = namedtuple('SnowflakeChunk', [
    'url',  # S3 bucket URL to download the chunk
    'row_count',  # number of rows in the chunk
    'result_data',  # pointer to the generator of the chunk
    'ready'  # True if ready to consume or False
])

logger = getLogger(__name__)


class SnowflakeChunkDownloader(object):
    u"""
    Large Result set chunk downloader class.
    """

    def _pre_init(self, chunks, connection, cursor, qrmk, chunk_headers,
                  query_result_format='JSON',
                  prefetch_threads=DEFAULT_CLIENT_PREFETCH_THREADS):
        self._query_result_format = query_result_format

        self._downloader_error = None

        self._connection = connection
        self._cursor = cursor
        self._qrmk = qrmk
        self._chunk_headers = chunk_headers

        self._chunk_size = len(chunks)
        self._chunks = {}
        self._chunk_cond = Condition()

        self._effective_threads = min(prefetch_threads, self._chunk_size)
        if self._effective_threads < 1:
            self._effective_threads = 1

        for idx, chunk in enumerate(chunks):
            logger.debug(u"queued chunk %d: rowCount=%s", idx,
                         chunk[u'rowCount'])
            self._chunks[idx] = SnowflakeChunk(
                url=chunk[u'url'],
                result_data=None,
                ready=False,
                row_count=int(chunk[u'rowCount']))

        logger.debug(u'prefetch threads: %s, '
                     u'number of chunks: %s, '
                     u'effective threads: %s',
                     prefetch_threads,
                     self._chunk_size,
                     self._effective_threads)

        self._pool = ThreadPoolExecutor(self._effective_threads)

        self._downloading_chunks_lock = Lock()
        self._total_millis_downloading_chunks = 0
        self._total_millis_parsing_chunks = 0

        self._next_chunk_to_consume = 0

    def __init__(self, chunks, connection, cursor, qrmk, chunk_headers,
                 query_result_format='JSON',
                 prefetch_threads=DEFAULT_CLIENT_PREFETCH_THREADS):
        self._pre_init(chunks, connection, cursor, qrmk, chunk_headers,
                       query_result_format=query_result_format,
                       prefetch_threads=prefetch_threads)
        logger.debug('Chunk Downloader in memory')
        for idx in range(self._effective_threads):
            self._pool.submit(self._download_chunk, idx)
        self._next_chunk_to_download = self._effective_threads

    def _download_chunk(self, idx):
        """
        Downloads a chunk asynchronously
        """
        logger.debug(u'downloading chunk %s/%s', idx + 1, self._chunk_size)
        headers = {}
        if self._chunk_headers is not None:
            headers = self._chunk_headers
            logger.debug(u'use chunk headers from result')
        elif self._qrmk is not None:
            headers[SSE_C_ALGORITHM] = SSE_C_AES
            headers[SSE_C_KEY] = self._qrmk

        last_error = None
        backoff = DecorrelateJitterBackoff(1, 16)
        sleep_timer = 1
        for retry in range(10):
            try:
                logger.debug(u"started getting the result set %s: %s",
                             idx + 1, self._chunks[idx].url)
                result_data = self._fetch_chunk(self._chunks[idx].url, headers)
                logger.debug(u"finished getting the result set %s: %s",
                             idx + 1, self._chunks[idx].url)

                if isinstance(result_data, ResultIterWithTimings):
                    metrics = result_data.get_timings()
                    with self._downloading_chunks_lock:
                        self._total_millis_downloading_chunks += metrics[
                            ResultIterWithTimings.DOWNLOAD]
                        self._total_millis_parsing_chunks += metrics[
                            ResultIterWithTimings.PARSE]

                with self._chunk_cond:
                    self._chunks[idx] = self._chunks[idx]._replace(
                        result_data=result_data,
                        ready=True)
                    self._chunk_cond.notify_all()
                    logger.debug(
                        u'added chunk %s/%s to a chunk list.', idx + 1,
                        self._chunk_size)
                break
            except Exception as e:
                last_error = e
                sleep_timer = backoff.next_sleep(1, sleep_timer)
                logger.exception(
                    u'Failed to fetch the large result set chunk %s/%s for the %s th time, backing off for %s s',
                    idx + 1, self._chunk_size, retry + 1, sleep_timer)
                time.sleep(sleep_timer)
        else:
            self._downloader_error = last_error

    def next_chunk(self):
        """
        Gets the next chunk if ready
        """
        logger.debug(
            u'next_chunk_to_consume={next_chunk_to_consume}, '
            u'next_chunk_to_download={next_chunk_to_download}, '
            u'total_chunks={total_chunks}'.format(
                next_chunk_to_consume=self._next_chunk_to_consume + 1,
                next_chunk_to_download=self._next_chunk_to_download + 1,
                total_chunks=self._chunk_size))
        if self._next_chunk_to_consume > 0:
            # clean up the previously fetched data
            n = self._next_chunk_to_consume - 1
            self._chunks[n] = self._chunks[n]._replace(result_data=None, ready=False)

            if self._next_chunk_to_download < self._chunk_size:
                self._pool.submit(self._download_chunk, self._next_chunk_to_download)
                self._next_chunk_to_download += 1

        if self._downloader_error is not None:
            raise self._downloader_error

        for attempt in range(MAX_RETRY_DOWNLOAD):
            logger.debug(u'waiting for chunk %s/%s'
                         u' in %s/%s download attempt',
                         self._next_chunk_to_consume + 1,
                         self._chunk_size,
                         attempt + 1,
                         MAX_RETRY_DOWNLOAD)
            done = False
            for wait_counter in range(MAX_WAIT):
                with self._chunk_cond:
                    if self._downloader_error:
                        raise self._downloader_error
                    if self._chunks[self._next_chunk_to_consume].ready:
                        done = True
                        break
                    logger.debug(u'chunk %s/%s is NOT ready to consume'
                                 u' in %s/%s(s)',
                                 self._next_chunk_to_consume + 1,
                                 self._chunk_size,
                                 (wait_counter + 1) * WAIT_TIME_IN_SECONDS,
                                 MAX_WAIT * WAIT_TIME_IN_SECONDS)
                    self._chunk_cond.wait(WAIT_TIME_IN_SECONDS)
            else:
                logger.debug(
                    u'chunk %s/%s is still NOT ready. Restarting chunk '
                    u'downloader threads',
                    self._next_chunk_to_consume + 1,
                    self._chunk_size)
                self._pool.shutdown(wait=False)  # terminate the thread pool
                self._pool = ThreadPoolExecutor(self._effective_threads)
                for idx0 in range(self._effective_threads):
                    idx = idx0 + self._next_chunk_to_consume
                    self._pool.submit(self._download_chunk, idx)
            if done:
                break
        else:
            Error.errorhandler_wrapper(
                self._connection,
                self._cursor,
                OperationalError,
                {
                    u'msg': u'The result set chunk download fails or hang for '
                            u'unknown reason.',
                    u'errno': ER_CHUNK_DOWNLOAD_FAILED
                })
        logger.debug(u'chunk %s/%s is ready to consume',
                     self._next_chunk_to_consume + 1,
                     self._chunk_size)

        ret = self._chunks[self._next_chunk_to_consume]
        self._next_chunk_to_consume += 1
        return ret

    def terminate(self):
        """
        Terminates downloading the chunks.
        """
        if hasattr(self, u'_pool') and self._pool is not None:
            self._pool.shutdown()
            self._pool = None

    def __del__(self):
        try:
            self.terminate()
        except Exception:
            # ignore all errors in the destructor
            pass

    def _fetch_chunk(self, url, headers):
        """
        Fetch the chunk from S3.
        """
        handler = JsonBinaryHandler(is_raw_binary_iterator=True) \
            if self._query_result_format == 'json' else \
            ArrowBinaryHandler(self._cursor, self._connection)

        return self._connection.rest.fetch(
            u'get', url, headers,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            is_raw_binary=True,
            binary_data_handler=handler)


class ResultIterWithTimings:
    DOWNLOAD = u"download"
    PARSE = u"parse"

    def __init__(self, it, timings):
        self._it = it
        self._timings = timings

    def __next__(self):
        return next(self._it)

    def next(self):
        return self.__next__()

    def get_timings(self):
        return self._timings


class RawBinaryDataHandler:
    """
    Abstract class being passed to network.py to handle raw binary data
    """
    def to_iterator(self, raw_data_fd, download_time):
        pass


class JsonBinaryHandler(RawBinaryDataHandler):
    """
    Convert result chunk in json format into interator
    """
    def __init__(self, is_raw_binary_iterator):
        self._is_raw_binary_iterator = is_raw_binary_iterator

    def to_iterator(self, raw_data_fd, download_time):
        parse_start_time = get_time_millis()
        raw_data = decompress_raw_data(
            raw_data_fd, add_bracket=True
        ).decode('utf-8', 'replace')
        if not self._is_raw_binary_iterator:
            ret = json.loads(raw_data)
        ret = iter(json.loads(raw_data))

        parse_end_time = get_time_millis()

        timing_metrics = {
            ResultIterWithTimings.DOWNLOAD: download_time,
            ResultIterWithTimings.PARSE: parse_end_time - parse_start_time
        }

        return ResultIterWithTimings(ret, timing_metrics)


class ArrowBinaryHandler(RawBinaryDataHandler):

    def __init__(self, cursor, connection):
        self._cursor = cursor
        self._arrow_context = ArrowConverterContext(connection._session_parameters)

    """
    Handler to consume data as arrow stream
    """
    def to_iterator(self, raw_data_fd, download_time):
        from .arrow_iterator import PyArrowIterator
        gzip_decoder = GzipFile(fileobj=raw_data_fd, mode='r')
        it = PyArrowIterator(self._cursor, gzip_decoder, self._arrow_context, self._cursor._use_dict_result,
                             self._cursor.connection._numpy)
        return it
