#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from logging import getLogger

from .constants import FIELD_ID_TO_NAME
from .errorcode import ER_FAILED_TO_CONVERT_ROW_TO_PYTHON_TYPE
from .errors import Error, InterfaceError
from .telemetry import TelemetryField
from .time_util import get_time_millis

logger = getLogger(__name__)


class JsonResult:
    def __init__(self, raw_response, cursor):
        self._reset()
        self._cursor = cursor
        self._connection = cursor.connection
        self._init_from_meta(raw_response)

    def _init_from_meta(self, data):
        self._total_row_index = -1  # last fetched number of rows
        self._chunk_index = 0
        self._chunk_count = 0

        self._current_chunk_row = iter(data.get(u'rowset'))
        self._current_chunk_row_count = len(data.get(u'rowset'))

        self._column_converter = []
        self._column_idx_to_name = {}
        for idx, column in enumerate(data[u'rowtype']):
            self._column_idx_to_name[idx] = column[u'name']
            self._column_converter.append(
                self._connection.converter.to_python_method(
                    column[u'type'].upper(), column))

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
                query_result_format='json',
                prefetch_threads=self._connection.client_prefetch_threads)

    def __iter__(self):
        return self

    def next(self):
        return self.__next__()

    def __next__(self):
        is_done = False
        try:
            row = None
            self.total_row_index += 1
            try:
                row = next(self._current_chunk_row)
            except StopIteration:
                if self._chunk_index < self._chunk_count:
                    logger.debug(
                        u"chunk index: %s, chunk_count: %s",
                        self._chunk_index, self._chunk_count)
                    next_chunk = self._chunk_downloader.next_chunk()
                    self._current_chunk_row_count = next_chunk.row_count
                    self._current_chunk_row = next_chunk.result_data
                    self._chunk_index += 1
                    try:
                        row = next(self._current_chunk_row)
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

            return self._row_to_python(row) if row is not None else None

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

    def _row_to_python(self, row):
        """
        Converts data in row if required.

        NOTE: surprisingly using idx+1 is faster than enumerate here. Also
        removing generator improved performance even better.
        """
        idx = 0
        for col in row:
            conv = self._column_converter[idx]
            try:
                row[idx] = col if conv is None or col is None else conv(col)
            except Exception as e:
                col_desc = self._cursor.description[idx]
                msg = u'Failed to convert: ' \
                      u'field {name}: {type}::{value}, Error: ' \
                      u'{error}'.format(
                            name=col_desc[0],
                            type=FIELD_ID_TO_NAME[col_desc[1]],
                            value=col,
                            error=e)
                logger.exception(msg)
                Error.errorhandler_wrapper(
                    self._connection, self._cursor, InterfaceError, {
                        u'msg': msg,
                        u'errno': ER_FAILED_TO_CONVERT_ROW_TO_PYTHON_TYPE,
                    })
            idx += 1
        return tuple(row)

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


class DictJsonResult(JsonResult):

    def __init__(self, raw_response, cursor):
        JsonResult.__init__(self, raw_response, cursor)

    def _row_to_python(self, row):
        # see the base class
        res = {}
        idx = 0
        for col in row:
            col_name = self._column_idx_to_name[idx]
            conv = self._column_converter[idx]
            try:
                res[col_name] = col if conv is None or col is None else conv(
                    col)
            except Exception as e:
                col_desc = self._cursor.description[idx]
                msg = u'Failed to convert: ' \
                      u'field {name}: {type}::{value}, Error: ' \
                      u'{error}'.format(
                    name=col_desc[0],
                    type=FIELD_ID_TO_NAME[col_desc[1]],
                    value=col,
                    error=e
                )
                logger.exception(msg)
                Error.errorhandler_wrapper(
                    self._connection, self._cursor, InterfaceError, {
                        u'msg': msg,
                        u'errno': ER_FAILED_TO_CONVERT_ROW_TO_PYTHON_TYPE,
                    })
            idx += 1
        return res
