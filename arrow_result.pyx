#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

# cython: profile=False
# cython: language_level=3

from base64 import b64decode
import io
from logging import getLogger
from .telemetry import TelemetryField
from .time_util import get_time_millis
from .arrow_iterator import PyArrowIterator
from .arrow_iterator import EmptyPyArrowIterator
from .arrow_iterator import ROW_UNIT, TABLE_UNIT, EMPTY_UNIT
from .arrow_context import ArrowConverterContext
from .options import pandas, installed_pandas

logger = getLogger(__name__)

if installed_pandas:
    from pyarrow import concat_tables
else:
    logger.info("Failed to import optional packages, pyarrow")


cdef class ArrowResult:
    cdef:
        object _cursor
        object _connection
        int total_row_index;
        int _chunk_index
        int _chunk_count
        int _current_chunk_row_count
        list _description
        list _column_idx_to_name
        object _current_chunk_row
        object _chunk_downloader
        object _arrow_context
        str _iter_unit
        object _use_dict_result
        object _use_numpy


    def __init__(self, raw_response, cursor, use_dict_result=False, _chunk_downloader=None):
        self._reset()
        self._cursor = cursor
        self._connection = cursor.connection
        self._use_dict_result = use_dict_result
        self._use_numpy = self._connection._numpy

        self._column_idx_to_name = []
        for idx, column in enumerate(raw_response.get(u'rowtype')):
            self._column_idx_to_name.append(column[u'name'])

        self._chunk_info(raw_response, _chunk_downloader)

    def _chunk_info(self, data, _chunk_downloader=None):
        self.total_row_index = -1  # last fetched number of rows

        self._chunk_index = 0
        self._chunk_count = 0
        # result as arrow chunk
        rowset_b64 = data.get(u'rowsetBase64')

        if rowset_b64:
            arrow_bytes = b64decode(rowset_b64)
            self._arrow_context = ArrowConverterContext(self._connection._session_parameters)
            self._current_chunk_row = PyArrowIterator(self._cursor, io.BytesIO(arrow_bytes),
                                                      self._arrow_context, self._use_dict_result,
                                                      self._use_numpy)
        else:
            logger.debug("Data from first gs response is empty")
            self._current_chunk_row = EmptyPyArrowIterator()
        self._iter_unit = EMPTY_UNIT

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
            self._chunk_downloader = _chunk_downloader if _chunk_downloader \
                else self._connection._chunk_downloader_class(
                    chunks, self._connection, self._cursor, qrmk, chunk_headers,
                    query_result_format='arrow',
                    prefetch_threads=self._connection.client_prefetch_threads)

    def __iter__(self):
        return self

    def __next__(self):
        if self._iter_unit == EMPTY_UNIT:
            self._iter_unit = ROW_UNIT
            self._current_chunk_row.init(self._iter_unit)
        elif self._iter_unit == TABLE_UNIT:
            logger.debug(u'The iterator has been built for fetching arrow table')
            raise RuntimeError

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
                    self._current_chunk_row.init(self._iter_unit)
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
                    self._current_chunk_row = EmptyPyArrowIterator()
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
        self._current_chunk_row = EmptyPyArrowIterator()
        self._chunk_index = 0

        if hasattr(self, u'_chunk_count') and self._chunk_count > 0 and \
                self._chunk_downloader is not None:
            self._chunk_downloader.terminate()

        self._chunk_count = 0
        self._chunk_downloader = None
        self._arrow_context = None
        self._iter_unit = EMPTY_UNIT

    def _fetch_arrow_batches(self):
        '''
            Fetch Arrow Table in batch, where 'batch' refers to Snowflake Chunk
            Thus, the batch size (the number of rows in table) may be different
        '''
        if self._iter_unit == EMPTY_UNIT:
            self._iter_unit = TABLE_UNIT
        elif self._iter_unit == ROW_UNIT:
            logger.debug(u'The iterator has been built for fetching row')
            raise RuntimeError

        try:
            self._current_chunk_row.init(self._iter_unit)
            logger.debug(u'Init table iterator successfully, current chunk index: %s, '
                         u'chunk count: %s', self._chunk_index, self._chunk_count)
            while self._chunk_index <= self._chunk_count:
                stop_iteration_except = False
                try:
                    table = self._current_chunk_row.__next__()
                except StopIteration:
                    stop_iteration_except = True

                if self._chunk_index < self._chunk_count: # multiple chunks
                    logger.debug(
                        u"chunk index: %s, chunk_count: %s",
                        self._chunk_index, self._chunk_count)
                    next_chunk = self._chunk_downloader.next_chunk()
                    self._current_chunk_row = next_chunk.result_data
                    self._current_chunk_row.init(self._iter_unit)
                self._chunk_index += 1

                if stop_iteration_except:
                    continue
                else:
                    yield table
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
                self._current_chunk_row = EmptyPyArrowIterator()
        finally:
            if self._cursor._first_chunk_time:
                logger.info("fetching data into pandas dataframe done")
                time_consume_last_result = get_time_millis() - self._cursor._first_chunk_time
                self._cursor._log_telemetry_job_data(
                    TelemetryField.TIME_CONSUME_LAST_RESULT,
                    time_consume_last_result)

    def _fetch_arrow_all(self):
        """
            Fetch a single Arrow Table
        """
        tables = list(self._fetch_arrow_batches())
        if tables:
            return concat_tables(tables)
        else:
            return None

    def _fetch_pandas_batches(self, **kwargs):
        u"""
            Fetch Pandas dataframes in batch, where 'batch' refers to Snowflake Chunk
            Thus, the batch size (the number of rows in dataframe) is optimized by
            Snowflake Python Connector
        """
        for table in self._fetch_arrow_batches():
            yield table.to_pandas(**kwargs)

    def _fetch_pandas_all(self, **kwargs):
        """
            Fetch a single Pandas dataframe
        """
        table = self._fetch_arrow_all()
        if table:
            return table.to_pandas(**kwargs)
        else:

            return pandas.DataFrame(columns=self._column_idx_to_name)
