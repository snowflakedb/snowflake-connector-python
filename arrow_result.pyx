#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

# cython: profile=False
# cython: language_level=3

from base64 import b64decode
from logging import getLogger
from .telemetry import TelemetryField
from .time_util import get_time_millis
try:
    from pyarrow.ipc import open_stream
    from pyarrow import concat_tables
    from .arrow_iterator import PyArrowIterator, EmptyPyArrowIterator, ROW_UNIT, TABLE_UNIT, EMPTY_UNIT
    from .arrow_context import ArrowConverterContext
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
        object _arrow_context
        str _iter_unit

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
        rowset_b64 = data.get(u'rowsetBase64')

        if rowset_b64:
            arrow_bytes = b64decode(rowset_b64)
            arrow_reader = open_stream(arrow_bytes)
            self._arrow_context = ArrowConverterContext(self._connection._session_parameters)
            self._current_chunk_row = PyArrowIterator(arrow_reader, self._arrow_context)
        else:
            self._current_chunk_row = EmptyPyArrowIterator(None, None)
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
            self._chunk_downloader = self._connection._chunk_downloader_class(
                chunks, self._connection, self._cursor, qrmk, chunk_headers,
                query_result_format='arrow',
                prefetch_threads=self._connection.client_prefetch_threads,
                use_ijson=False)

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
                    self._current_chunk_row = EmptyPyArrowIterator(None, None)
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
        self._current_chunk_row = EmptyPyArrowIterator(None, None)
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
            self._current_chunk_row.init(self._iter_unit) # AttributeError if it is iter(())
            while self._chunk_index <= self._chunk_count:
                table = self._current_chunk_row.__next__()
                if self._chunk_index < self._chunk_count: # multiple chunks
                    logger.debug(
                        u"chunk index: %s, chunk_count: %s",
                        self._chunk_index, self._chunk_count)
                    next_chunk = self._chunk_downloader.next_chunk()
                    self._current_chunk_row = next_chunk.result_data
                    self._current_chunk_row.init(self._iter_unit)
                self._chunk_index += 1
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
                self._current_chunk_row = EmptyPyArrowIterator(None, None)
        except AttributeError:
            # just for handling the case of empty result
            return None
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

    def _fetch_pandas_batches(self):
        """
            Fetch Pandas dataframes in batch, where 'batch' refers to Snowflake Chunk
            Thus, the batch size (the number of rows in dataframe) may be different
            TODO: take a look at pyarrow to_pandas() API, which provides some useful arguments
            e.g. 1. use `use_threads=true` for acceleration
                 2. use `strings_to_categorical` and `categories` to encoding categorical data,
                    which is really different from `string` in data science.
                    For example, some data may be marked as 0 and 1 as binary class in dataset,
                    the user wishes to interpret as categorical data instead of integer.
                 3. use `zero_copy_only` to capture the potential unnecessary memory copying
            we'd better also provide these handy arguments to make data scientists happy :)
        """
        for table in self._fetch_arrow_batches():
            yield table.to_pandas()

    def _fetch_pandas_all(self):
        """
            Fetch a single Pandas dataframe
        """
        table = self._fetch_arrow_all()
        if table:
            return table.to_pandas()
        else:
            return None
