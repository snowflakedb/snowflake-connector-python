#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

# cython: profile=False

from base64 import b64decode
from logging import getLogger
from .telemetry import TelemetryField
from .time_util import get_time_millis
try:
    from pyarrow.ipc import open_stream
    from .arrow_iterator import PyArrowChunkIterator
except ImportError:
    pass


logger = getLogger(__name__)


cdef class ArrowResult:
    cdef:
        object _cursor
        object _connection
        int total_row_index;
        int _chunk_index
        int _chunk_count
        int _current_chunk_row_count
        list _description
        object _column_idx_to_name
        object _current_chunk_row
        object _chunk_downloader

    def __init__(self, raw_response, cursor):
        self._reset()
        self._cursor = cursor
        self._connection = cursor.connection
        self._chunk_info(raw_response)

    def _chunk_info(self, data):
        self.total_row_index = -1  # last fetched number of rows

        self._chunk_index = 0
        self._chunk_count = 0
        # result as arrow chunk
        arrow_bytes = b64decode(data.get(u'rowsetBase64'))
        arrow_reader = open_stream(arrow_bytes)
        self._current_chunk_row = PyArrowChunkIterator()
        for rb in arrow_reader:
            self._current_chunk_row.add_record_batch(rb)

        if u'chunks' in data:
            chunks = data[u'chunks']
            self._chunk_count = len(chunks)
            logger.debug(u'chunk size=%s', self._chunk_count)
            # prepare the downloader for further fetch
            qrmk = data[u'qrmk'] if u'qrmk' in data else None
            chunk_headers = None
            if u'chunkHeaders' in data:
                chunk_headers = {}
                for header_key, header_value in data[
                    u'chunkHeaders'].items():
                    chunk_headers[header_key] = header_value
                    logger.debug(
                        u'added chunk header: key=%s, value=%s',
                        header_key,
                        header_value)

            logger.debug(u'qrmk=%s', qrmk)
            self._chunk_downloader = self._connection._chunk_downloader_class(
                chunks, self._connection, self._cursor, qrmk, chunk_headers,
                query_result_format='arrow',
                prefetch_threads=self._connection.client_prefetch_threads,
                use_ijson=False)

    def __iter__(self):
        return self

    def __next__(self):
        is_done = False
        try:
            row = None
            self.total_row_index += 1
            try:
                row = self._current_chunk_row.__next__()
            except StopIteration:
                if self._chunk_index < self._chunk_count:
                    logger.debug(
                        u"chunk index: %s, chunk_count: %s",
                        self._chunk_index, self._chunk_count)
                    next_chunk = self._chunk_downloader.next_chunk()
                    self._current_chunk_row = next_chunk.result_data
                    self._chunk_index += 1
                    try:
                        row = self._current_chunk_row.__next__()
                    except StopIteration:
                        is_done = True
                        raise IndexError
                else:
                    if self._chunk_count > 0 and \
                            self._chunk_downloader is not None:
                        self._chunk_downloader.terminate()
                        self._cursor._log_telemetry_job_data(
                            TelemetryField.TIME_DOWNLOADING_CHUNKS,
                            self._chunk_downloader._total_millis_downloading_chunks)
                        self._cursor._log_telemetry_job_data(
                            TelemetryField.TIME_PARSING_CHUNKS,
                            self._chunk_downloader._total_millis_parsing_chunks)
                    self._chunk_downloader = None
                    self._chunk_count = 0
                    self._current_chunk_row = iter(())
                    is_done = True

            if is_done:
                raise StopIteration

            return row

        except IndexError:
            # returns None if the iteration is completed so that iter() stops
            return None
        finally:
            if is_done and self._cursor._first_chunk_time:
                logger.info("fetching data done")
                time_consume_last_result = get_time_millis() - self._cursor._first_chunk_time
                self._cursor._log_telemetry_job_data(
                    TelemetryField.TIME_CONSUME_LAST_RESULT,
                    time_consume_last_result)

    def _reset(self):
        self.total_row_index = -1  # last fetched number of rows
        self._current_chunk_row_count = 0
        self._current_chunk_row = iter(())
        self._chunk_index = 0

        if hasattr(self, u'_chunk_count') and self._chunk_count > 0 and \
                self._chunk_downloader is not None:
            self._chunk_downloader.terminate()

        self._chunk_count = 0
        self._chunk_downloader = None

