#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

# cython: profile=False
# cython: language_level=3

import io
from base64 import b64decode

from snowflake.connector.snow_logging import getSnowLogger

from .arrow_context import ArrowConverterContext
from .arrow_iterator import (
    EMPTY_UNIT,
    ROW_UNIT,
    TABLE_UNIT,
    EmptyPyArrowIterator,
    PyArrowIterator,
)
from .options import installed_pandas, pandas
from .telemetry import TelemetryField
from .time_util import get_time_millis

snow_logger = getSnowLogger(__name__)

if installed_pandas:
    from pyarrow import concat_tables
else:
    snow_logger.info(path_name="arrow_result.pyx", msg="Failed to import optional packages, pyarrow")


cdef class ArrowResult:
    cdef:
        object _cursor
        object _connection
        readonly int total_row_index;
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
        for idx, column in enumerate(raw_response.get('rowtype')):
            self._column_idx_to_name.append(column['name'])

        self._chunk_info(raw_response, _chunk_downloader)

    def _chunk_info(self, data, _chunk_downloader=None):
        self.total_row_index = -1  # last fetched number of rows

        self._chunk_index = 0
        self._chunk_count = 0
        # result as arrow chunk
        rowset_b64 = data.get('rowsetBase64')

        if rowset_b64:
            arrow_bytes = b64decode(rowset_b64)
            self._arrow_context = ArrowConverterContext(self._connection._session_parameters)
            self._current_chunk_row = PyArrowIterator(self._cursor, io.BytesIO(arrow_bytes),
                                                      self._arrow_context, self._use_dict_result,
                                                      self._use_numpy)
        else:
            snow_logger.debug(path_name="arrow_result.pyx", func_name="_chunk_info",
                              msg="Data from first gs response is empty")
            self._current_chunk_row = EmptyPyArrowIterator()
        self._iter_unit = EMPTY_UNIT

        if 'chunks' in data:
            chunks = data['chunks']
            self._chunk_count = len(chunks)
            snow_logger.debug(path_name="arrow_result.pyx", func_name="_chunk_info",
                              msg='chunk size={}'.format(self._chunk_count))
            # prepare the downloader for further fetch
            qrmk = data['qrmk'] if 'qrmk' in data else None
            chunk_headers = None
            if 'chunkHeaders' in data:
                chunk_headers = {}
                for header_key, header_value in data[
                    'chunkHeaders'].items():
                    chunk_headers[header_key] = header_value
                    snow_logger.debug(path_name="arrow_result.pyx", func_name="_chunk_info",
                                      msg="added chunk header: key={}, value={}".format(header_key, header_value))

            snow_logger.debug(path_name="arrow_result.pyx", func_name="_chunk_info",
                                 msg='qrmk={}'.format(qrmk))
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
            snow_logger.debug(path_name="arrow_result.pyx", func_name="__next__",
                              msg='The iterator has been built for fetching arrow table')
            raise RuntimeError

        is_done = False
        try:
            row = None
            self.total_row_index += 1
            try:
                row = self._current_chunk_row.__next__()
            except StopIteration:
                if self._chunk_index < self._chunk_count:
                    snow_logger.debug(path_name="arrow_result.pyx", func_name="__next__",
                                      msg="chunk index:{}, chunk_count:{}".format(self._chunk_index, self._chunk_count))
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
                snow_logger.info(path_name="arrow_result.pyx", func_name="__next__", msg="fetching data done")
                time_consume_last_result = get_time_millis() - self._cursor._first_chunk_time
                self._cursor._log_telemetry_job_data(
                    TelemetryField.TIME_CONSUME_LAST_RESULT,
                    time_consume_last_result)

    def _reset(self):
        self.total_row_index = -1  # last fetched number of rows
        self._current_chunk_row_count = 0
        self._current_chunk_row = EmptyPyArrowIterator()
        self._chunk_index = 0

        if hasattr(self, '_chunk_count') and self._chunk_count > 0 and \
                self._chunk_downloader is not None:
            self._chunk_downloader.terminate()

        self._chunk_count = 0
        self._chunk_downloader = None
        self._arrow_context = None
        self._iter_unit = EMPTY_UNIT

    def _fetch_arrow_batches(self):
        """Fetch Arrow Table in batch, where 'batch' refers to Snowflake Chunk. Thus, the batch size (the number of
        rows in table) may be different."""
        if self._iter_unit == EMPTY_UNIT:
            self._iter_unit = TABLE_UNIT
        elif self._iter_unit == ROW_UNIT:
            snow_logger.debug(path_name="arrow_result.pyx", func_name="_fetch_arrow_batches",
                              msg="The iterator has been built for fetching row")
            raise RuntimeError

        try:
            self._current_chunk_row.init(self._iter_unit)
            snow_logger.debug(path_name="arrow_result.pyx", func_name="_fetch_arrow_batches",
                              msg='Init table iterator successfully, current chunk index: {},'
                                  'chunk count: {}'.format(self._chunk_index, self._chunk_count))
            while self._chunk_index <= self._chunk_count:
                stop_iteration_except = False
                try:
                    table = self._current_chunk_row.__next__()
                except StopIteration:
                    stop_iteration_except = True

                if self._chunk_index < self._chunk_count: # multiple chunks
                    snow_logger.debug(path_name="arrow_result.pyx", func_name="_fetch_arrow_batches",
                                    msg="chunk index: {}, chunk_count: {}".format(self._chunk_index, self._chunk_count))
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
                snow_logger.info(path_name="arrow_result.pyx", func_name="_fetch_arrow_batches",
                                 msg="fetching data into pandas dataframe done")
                time_consume_last_result = get_time_millis() - self._cursor._first_chunk_time
                self._cursor._log_telemetry_job_data(
                    TelemetryField.TIME_CONSUME_LAST_RESULT,
                    time_consume_last_result)

    def _fetch_arrow_all(self):
        """Fetches a single Arrow Table."""
        tables = list(self._fetch_arrow_batches())
        if tables:
            return concat_tables(tables)
        else:
            return None

    def _fetch_pandas_batches(self, **kwargs):
        """Fetches Pandas dataframes in batch, where 'batch' refers to Snowflake Chunk. Thus, the batch size (the
        number of rows in dataframe) is optimized by Snowflake Python Connector."""
        for table in self._fetch_arrow_batches():
            yield table.to_pandas(**kwargs)

    def _fetch_pandas_all(self, **kwargs):
        """Fetches a single Pandas dataframe."""
        table = self._fetch_arrow_all()
        if table:
            return table.to_pandas(**kwargs)
        else:

            return pandas.DataFrame(columns=self._column_idx_to_name)
