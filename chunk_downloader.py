#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

import collections
import sys
import threading
import time
import weakref
from concurrent import futures
from logging import getLogger

from .compat import PY2
from .errorcode import ER_CHUNK_DOWNLOAD_FAILED
from .errors import (Error, OperationalError)

DEFAULT_REQUEST_TIMEOUT = 3600

MAX_RETRY_DOWNLOAD = 3
WAIT_TIME_IN_SECONDS = 1200

# Scheduling ramp constants.  Use caution if changing these.
SCHED_MAX_PENDING = 40  # Adjust down to reduce memory usage.
SCHED_GROWTH_ADJ = 0.25  # Increase to ramp concurrency faster.
SCHED_SHRINK_ADJ = 0.99  # Adjusts concurrency down when data is ready.

SSE_C_ALGORITHM = u"x-amz-server-side-encryption-customer-algorithm"
SSE_C_KEY = u"x-amz-server-side-encryption-customer-key"
SSE_C_AES = u"AES256"

logger = getLogger(__name__)


class SnowflakeChunkDownloader(object):
    u"""
    Large Result set chunk downloader class.
    """

    Status = collections.namedtuple('ChunkDownloaderStatus', 'active, ready')
    time = getattr(time, 'perf_counter', time.time)

    def __init__(self, chunks, connection, cursor, qrmk, chunk_headers,
                 use_ijson=False):
        self._use_ijson = use_ijson
        self._connection = connection
        self._cursor = cursor
        self._qrmk = qrmk
        self._headers = chunk_headers
        self._manifests = chunks
        self._total = len(chunks)
        self._calling_thread = None
        self._consumed = 0
        self._sched_lock = threading.RLock()
        self._sched_work = {}
        self._sched_cursor = 0
        self._sched_active = 0
        self._sched_ready = 0
        self._sched_backoff_till = 0
        self._sched_ticks = 0
        self._sched_pending_fill = 1
        # Improved performance for high thread counts.
        if not PY2:
            self._switchinterval_save = sys.getswitchinterval()
            sys.setswitchinterval(0.200)

    def __iter__(self):
        return self

    def next(self):
        self.assertFixedThread()
        idx = self._consumed
        if idx >= self._total:
            raise StopIteration()
        with self._sched_lock:
            if idx == self._sched_cursor:
                logger.warning(u'chunk downloader reached starvation')
                self.sched_next()
        for attempt in range(MAX_RETRY_DOWNLOAD + 1):
            if attempt:
                logger.warning(u'retrying chunk %d download (retry %d/%d)',
                               idx + 1, attempt, MAX_RETRY_DOWNLOAD)
                self._sched(idx, retry=attempt)
            with self._sched_lock:
                fut = self._sched_work.pop(idx)
            # Wait for the result with a small inner timeout that is used
            # to maintain the scheduler (maybe_sched_more).  Otherwise it
            # might become starved for some network conditions.
            start_ts = self.time()
            while True:
                try:
                    rows = fut.result(timeout=0.250)
                except futures.TimeoutError:
                    elapsed = self.time() - start_ts
                    if elapsed > WAIT_TIME_IN_SECONDS:
                        logger.warning(
                            u'chunk %d download timed out after %g second(s)',
                            idx + 1, elapsed)
                        with self._sched_lock:
                            fut.cancel()
                            self._sched_active -= 1
                            break
                    else:
                        self._sched_tick()
                else:
                    self._consumed += 1
                    with self._sched_lock:
                        self._sched_ready -= 1
                    self._sched_tick()
                    return rows
        Error.errorhandler_wrapper(
            self._connection,
            self._cursor,
            OperationalError,
            {
                u'msg': u'The result set chunk download fails or hang for '
                        u'unknown reason.',
                u'errno': ER_CHUNK_DOWNLOAD_FAILED
            })

    __next__ = next

    def get_status(self):
        """ Thread safe access to tuple of (active, ready) chunk counts. """
        with self._sched_lock:
            return self.Status(self._sched_active, self._sched_ready)

    def assertFixedThread(self):
        """
        Ensure threadsafety == 2 is enforced.
        https://www.python.org/dev/peps/pep-0249/#threadsafety
        """
        current = threading.current_thread()
        if self._calling_thread is None:
            self._calling_thread = weakref.ref(current)
        else:
            expected = self._calling_thread()
            assert current is expected, '%r is not %r' % (current, expected)

    def sched_next(self):
        with self._sched_lock:
            idx = self._sched_cursor
            if idx >= self._total:
                return None
            self._sched_chunk(idx)
            self._sched_cursor += 1
            return idx

    def _sched_chunk(self, idx, retry=None):
        """
        Schedule a download in a background thread.  Return a Future object
        that represents the eventual result.
        """
        future = futures.Future()
        with self._sched_lock:
            assert idx not in self._sched_work or \
                   self._sched_work[idx].cancelled()
            self._sched_work[idx] = future
        tname = 'ChunkDownloader_%d' % (idx + 1)
        if retry is not None:
            tname += '_retry_%d' % retry
        t = threading.Thread(name=tname,
                             target=self._fetch_chunk_worker_runner,
                             args=(future, self._manifests[idx]))
        t.daemon = True
        with self._sched_lock:
            self._sched_active += 1
        t.start()
        return future

    def _fetch_chunk_worker_runner(self, future, chunk):
        """
        Entry point for ChunkDownloader threads.  Thread safety rules apply
        from here out.
        """
        try:
            rows = self._fetch_chunk_worker(chunk)
        except BaseException as e:
            exc = e
        else:
            exc = None
        with self._sched_lock:
            if future.cancelled():
                if exc is None:
                    logger.warning("Ignoring good result from cancelled work")
                return
            self._sched_active -= 1
            self._sched_ready += 1
            if exc is not None:
                future.set_exception(exc)
            else:
                future.set_result(rows)
        self._sched_tick()

    def _sched_tick(self,
                    _max_pending=SCHED_MAX_PENDING,
                    _growth_adj=SCHED_GROWTH_ADJ,
                    _shrink_adj=SCHED_SHRINK_ADJ):
        """ Threadsafe scheduler for chunk queue management.  In short this
        monitors progress, makes any changes to the amount of concurrency
        requested and may start new chunk downloads. """
        with self._sched_lock:
            if self._sched_cursor >= self._total:
                return
            self._sched_ticks += 1
            pending = self._sched_active + self._sched_ready
            now = self.time()
            # Only perform ceiling adjustments occasionally and backoff
            # gradually with each use to stabilize the values.
            if now > self._sched_backoff_till:
                self._sched_backoff_till = now + (self._sched_ticks / 100)
                if pending < _max_pending and self._sched_ready <= 1:
                    adj = 1 + ((1 - min(pending / _max_pending, 0.99)) *
                               _growth_adj)
                else:
                    adj = _shrink_adj
                adj_ceiling = min(self._sched_pending_fill * adj, _max_pending)
                self._sched_pending_fill = max(1, adj_ceiling)
            if pending < self._sched_pending_fill:
                # Only launch one per tick to avoid bursts.
                self.sched_next()

    def _fetch_chunk_worker(self, chunk):
        """
        Thread worker to fetch the chunk from S3.
        """
        if self._headers is not None:
            headers = self._headers
        else:
            headers = {}
            if self._qrmk is not None:
                headers[SSE_C_ALGORITHM] = SSE_C_AES
                headers[SSE_C_KEY] = self._qrmk
        timeouts = (
            self._connection._connect_timeout,
            self._connection._connect_timeout,
            DEFAULT_REQUEST_TIMEOUT
        )
        return self._connection.rest.fetch(
            u'get', chunk['url'], headers, timeouts=timeouts,
            is_raw_binary=True, is_raw_binary_iterator=False,
            use_ijson=self._use_ijson)

    def terminate(self):
        """
        Terminates downloading the chunks.
        """
        if not PY2:
            sys.setswitchinterval(self._switchinterval_save)
        with self._sched_lock:
            futures = list(self._sched_work.values())
            self._sched_work = None
        for f in futures:
            f.cancel()

    def __del__(self):
        try:
            self.terminate()
        except:
            pass
