#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

import threading
import weakref
from collections import namedtuple
from logging import getLogger
from multiprocessing.pool import ThreadPool
from threading import Condition

from .errorcode import (ER_NO_ADDITIONAL_CHUNK)
from .errors import (Error, OperationalError)
from .network import (SnowflakeRestful, NO_TOKEN)

DEFAULT_REQUEST_TIMEOUT = 300
DEFAULT_CLIENT_RESULT_PREFETCH_SLOTS = 2
DEFAULT_CLIENT_RESULT_PREFETCH_THREADS = 1

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


class SnowflakeChunkDownloader(object):
    u"""
    Large Result set chunk downloader class.
    """

    def __init__(self, chunks, connection, cursor, qrmk, chunk_headers,
                 prefetch_slots=DEFAULT_CLIENT_RESULT_PREFETCH_SLOTS,
                 prefetch_threads=DEFAULT_CLIENT_RESULT_PREFETCH_THREADS,
                 use_ijson=False):
        self.logger = getLogger(__name__)
        self._use_ijson = use_ijson
        self._condition = Condition()
        self._session = None

        self._downloader_error = None

        self._connection = connection
        self._cursor = cursor
        self._qrmk = qrmk
        self._chunk_headers = chunk_headers

        self._prefetch_slots = prefetch_slots
        self._prefetch_threads = prefetch_threads

        self._chunks = []
        for idx, chunk in enumerate(chunks):
            self.logger.info(u"queued chunk: url=%s, rowCount=%s",
                             chunk[u'url'], chunk[u'rowCount'])
            self._chunks.append(SnowflakeChunk(
                url=chunk[u'url'],
                result_data=None,
                ready=False,
                row_count=int(chunk[u'rowCount'])))

        num_chunks = len(self._chunks)
        effective_threads = min(self._prefetch_threads, num_chunks)
        if effective_threads < 1:
            effective_threads = 1

        self.logger.debug(u'prefetch slots: %s', self._prefetch_slots)
        self.logger.debug(u'prefetch threads: %s', self._prefetch_threads)
        self.logger.debug(u'number of chunks: %s', num_chunks)
        self.logger.debug(u'effective threads: %s', effective_threads)

        # workaround for https://bugs.python.org/issue10015 for Python 2.6
        if not hasattr(threading.current_thread(), u"_children"):
            threading.current_thread()._children = weakref.WeakKeyDictionary()
        self._pool = ThreadPool(effective_threads)

        num_chunks_to_prefetch = min(self._prefetch_slots, len(self._chunks))

        self._total_millis_downloading_chunks = 0
        self._total_millis_parsing_chunks = 0

        self._next_chunk_to_consume = 0

        for idx in range(num_chunks_to_prefetch):
            self._pool.apply_async(self._download_chunk, [idx])
        self._next_chunk_to_download = num_chunks_to_prefetch

    def _download_chunk(self, idx):
        """
        Downloads a chunk asynchronously
        """
        self.logger.debug(u'downloading chunk %s', idx)
        headers = {}
        err = None
        result_data = None
        try:
            if self._chunk_headers is not None:
                headers = self._chunk_headers
                self.logger.debug(u'use chunk headers from result')
            elif self._qrmk is not None:
                headers[SSE_C_ALGORITHM] = SSE_C_AES
                headers[SSE_C_KEY] = self._qrmk

            self.logger.debug(u"started getting the result set %s:%s",
                              idx, self._chunks[idx].url)
            result_data = self._get_request(
                self._chunks[idx].url,
                headers)
            self.logger.debug(u"finished getting the result set %s:%s",
                              idx, self._chunks[idx].url)

        except Exception as e:
            self.logger.exception(
                u'Failed to fetch the large result set chunk')
            err = e

        with self._condition:
            if err is None:
                self._chunks[idx] = self._chunks[idx]._replace(
                    result_data=result_data,
                    ready=True)
                self.logger.debug(
                    u'added chunk %s to a chunk list.', idx)
            else:
                self._downloader_error = err
            self._condition.notify()

    def next_chunk(self):
        """
        Gets the next chunk if ready
        """
        self.logger.debug(
            u'next_chunk_to_consume={next_chunk_to_consume}, '
            u'next_chunk_to_download={next_chunk_to_download}, '
            u'total_chunks={total_chunks}'.format(
                next_chunk_to_consume=self._next_chunk_to_consume,
                next_chunk_to_download=self._next_chunk_to_download,
                total_chunks=len(self._chunks)))
        if self._next_chunk_to_consume > 0:
            # clean up the previously fetched data
            self._chunks[self._next_chunk_to_consume - 1] = None

            if self._next_chunk_to_download < len(self._chunks):
                self._pool.apply_async(
                    self._download_chunk,
                    [self._next_chunk_to_download])
                self._next_chunk_to_download += 1

        if self._next_chunk_to_consume >= len(self._chunks):
            Error.errorhandler_wrapper(
                self._connection, self._cursor,
                OperationalError,
                {
                    u'msg': u"expect a chunk but got None",
                    u'errno': ER_NO_ADDITIONAL_CHUNK})

        if self._downloader_error is not None:
            raise self._downloader_error

        with self._condition:
            while not self._chunks[self._next_chunk_to_consume].ready and \
                            self._downloader_error is None:
                self.logger.debug(u'chunk %s is NOT ready to consume',
                                  self._next_chunk_to_consume)
                self._condition.wait(WAIT_TIME_IN_SECONDS)

            if self._downloader_error:
                raise self._downloader_error
            else:
                self.logger.debug(u'chunk %s is ready to consume',
                                  self._next_chunk_to_consume)

            ret = self._chunks[self._next_chunk_to_consume]
            self._next_chunk_to_consume += 1
            return ret

    def terminate(self):
        """
        Terminates downloading the chunks.
        """
        if hasattr(self, u'_pool') and self._pool is not None:
            self._pool.close()
            self._pool.join()
            self._pool = None

        if self._session is not None:
            self._session = None

    def __del__(self):
        try:
            self.terminate()
        except:
            # ignore all errors in the destructor
            pass

    def _get_request(self, url, headers, retry=10):
        """
        GET request for Large Result set chunkloader
        """
        # sharing the proxy and certificate
        proxies = SnowflakeRestful.set_proxies(
            self._connection.rest._proxy_host,
            self._connection.rest._proxy_port,
            self._connection.rest._proxy_user,
            self._connection.rest._proxy_password)

        self.logger.debug(u'proxies=%s, url=%s', proxies, url)

        return SnowflakeRestful.access_url(
            self._connection,
            self,
            u'get',
            full_url=url,
            headers=headers,
            data=None,
            proxies=proxies,
            timeout=(self._connection._connect_timeout,
                     self._connection._connect_timeout,
                     DEFAULT_REQUEST_TIMEOUT),
            retry=retry,
            token=NO_TOKEN,
            is_raw_binary=True,
            use_ijson=self._use_ijson)
