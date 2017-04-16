#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import logging
import re
import signal
import sys
import uuid
from logging import getLogger
from threading import (Timer, Lock)

from six import u

from .chunk_downloader import (DEFAULT_CLIENT_RESULT_PREFETCH_SLOTS,
                               DEFAULT_CLIENT_RESULT_PREFETCH_THREADS)
from .compat import (BASE_EXCEPTION_CLASS)
from .constants import (FIELD_NAME_TO_ID, FIELD_ID_TO_NAME)
from .errorcode import (ER_UNSUPPORTED_METHOD,
                        ER_CURSOR_IS_CLOSED,
                        ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT,
                        ER_NOT_POSITIVE_SIZE,
                        ER_FAILED_PROCESSING_PYFORMAT,
                        ER_FAILED_TO_CONVERT_ROW_TO_PYTHON_TYPE,
                        ER_INVALID_VALUE)
from .errors import (Error, ProgrammingError, NotSupportedError,
                     DatabaseError, InterfaceError)
from .file_transfer_agent import (SnowflakeFileTransferAgent)
from .sqlstate import (SQLSTATE_FEATURE_NOT_SUPPORTED)

STATEMENT_TYPE_ID_DML = 0x3000
STATEMENT_TYPE_ID_INSERT = STATEMENT_TYPE_ID_DML + 0x100
STATEMENT_TYPE_ID_UPDATE = STATEMENT_TYPE_ID_DML + 0x200
STATEMENT_TYPE_ID_DELETE = STATEMENT_TYPE_ID_DML + 0x300
STATEMENT_TYPE_ID_MERGE = STATEMENT_TYPE_ID_DML + 0x400
STATEMENT_TYPE_ID_MULTI_TABLE_INSERT = STATEMENT_TYPE_ID_DML + 0x500

STATEMENT_TYPE_ID_DML_SET = frozenset(
    [STATEMENT_TYPE_ID_DML, STATEMENT_TYPE_ID_INSERT,
     STATEMENT_TYPE_ID_UPDATE,
     STATEMENT_TYPE_ID_DELETE, STATEMENT_TYPE_ID_MERGE,
     STATEMENT_TYPE_ID_MULTI_TABLE_INSERT])

DESC_TABLE_RE = re.compile(u(r'desc(?:ribe)?\s+([\w_]+)\s*;?\s*$'),
                           flags=re.IGNORECASE)


class SnowflakeCursor(object):
    u"""
    Implementation of Cursor object that is returned from Connection.cursor()
    method.
    """
    PUT_SQL_RE = re.compile(u(r'^(?:/\*.*\*/\s*)*put\s+'), flags=re.IGNORECASE)
    GET_SQL_RE = re.compile(u(r'^(?:/\*.*\*/\s*)*get\s+'), flags=re.IGNORECASE)
    INSERT_SQL_RE = re.compile(u(r'^insert\s+into'), flags=re.IGNORECASE)
    COMMENT_SQL_RE = re.compile(u"/\*.*\*/")
    INSERT_SQL_VALUES_RE = re.compile(u(r'.*VALUES\s*(\(.*\)).*'),
                                      re.IGNORECASE | re.MULTILINE | re.DOTALL)
    ALTER_SESSION_RE = re.compile(
        u(r'alter\s+session\s+set\s+(.*)=\'?([^\']+)\'?\s*;'),
        flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)

    def __init__(self, connection):
        self._connection = connection

        self._errorhandler = Error.default_errorhandler
        self.messages = []
        self._timebomb = None  # must be here for abort_exit method
        self._description = None
        self._column_idx_to_name = None
        self._sfqid = None
        self._sqlstate = None
        self._total_rowcount = -1
        self._sequence_counter = -1
        self._request_id = None
        self._is_file_transfer = False

        self._timestamp_output_format = None
        self._timestamp_ltz_output_format = None
        self._timestamp_ntz_output_format = None
        self._timestamp_tz_output_format = None
        self._date_output_format = None
        self._time_output_format = None
        self._timezone = None
        self._binary_output_format = None

        self._client_result_prefetch_slots = \
            DEFAULT_CLIENT_RESULT_PREFETCH_SLOTS
        self._client_result_prefetch_threads = \
            DEFAULT_CLIENT_RESULT_PREFETCH_THREADS
        self._arraysize = 1  # PEP-0249: defaults to 1

        self._lock_canceling = Lock()
        self.logger = getLogger(__name__)

        self.reset()

    def __del__(self):
        try:
            self.close()
        except BASE_EXCEPTION_CLASS as e:
            logger = getLogger(__name__)
            if logger.getEffectiveLevel() <= logging.INFO:
                logger.info(e)

    @property
    def description(self):
        u"""
        Columns information in a tuple:
        - name
        - type_code
        - display_size
        - internal_size
        - precision
        - scale
        - null_ok
        """
        return self._description

    @property
    def rowcount(self):
        u"""
        The number of records updated or selected.
        If not clear, -1 is returned
        """
        return self._total_rowcount if self._total_rowcount >= 0 else None

    @property
    def rownumber(self):
        u"""
        The current 0-based index of the cursor in the result set or None if
        the index cannot be determined.
        """
        return self._total_row_index if self._total_row_index >= 0 else None

    @property
    def sfqid(self):
        u"""
        Snowflake query id in UUID form. Include this in the problem report to
        the customer support
        """
        return self._sfqid

    @property
    def sqlstate(self):
        u"""
        SQL State code
        """
        return self._sqlstate

    @property
    def timestamp_output_format(self):
        u"""
        Snowflake timestamp_output_format
        """
        return self._timestamp_output_format

    @property
    def timestamp_ltz_output_format(self):
        u"""
        Snowflake timestamp_output_format
        """
        return self._timestamp_ltz_output_format if \
            self._timestamp_ltz_output_format else \
            self._timestamp_output_format

    @property
    def timestamp_tz_output_format(self):
        u"""
        Snowflake timestamp_output_format
        """
        return self._timestamp_tz_output_format if \
            self._timestamp_tz_output_format else \
            self._timestamp_output_format

    @property
    def timestamp_ntz_output_format(self):
        u"""
        Snowflake timestamp_output_format
        """
        return self._timestamp_ntz_output_format if \
            self._timestamp_ntz_output_format else \
            self._timestamp_output_format

    @property
    def date_output_format(self):
        u"""
        Snowflake date_output_format
        """
        return self._date_output_format

    @property
    def time_output_format(self):
        u"""
        Snowflake time_output_format
        """
        return self._time_output_format

    @property
    def timezone(self):
        u"""
        Snowflake timezone
        """
        return self._timezone

    @property
    def binary_output_format(self):
        u"""
        Snowflake binary_output_format
        """
        return self._binary_output_format

    @property
    def arraysize(self):
        u"""
        The default number of rows fetched in fetchmany
        """
        return self._arraysize

    @arraysize.setter
    def arraysize(self, value):
        self._arraysize = int(value)

    @property
    def connection(self):
        u"""
        The connection object on which the cursor was created
        """
        return self._connection

    @property
    def errorhandler(self):
        return self._errorhandler

    @errorhandler.setter
    def errorhandler(self, value):
        self.logger.debug(u'setting errorhandler: %s', value)
        if value is None:
            raise ProgrammingError(u'Invalid errorhandler is specified')
        self._errorhandler = value

    @property
    def is_file_transfer(self):
        """
        Is PUT or GET command?
        """
        return hasattr(self, '_is_file_transfer') and self._is_file_transfer

    def callproc(self, procname, args=()):
        u"""
        Not supported
        """
        Error.errorhandler_wrapper(
            self.connection, self,
            NotSupportedError,
            {
                u'msg': u"callproc is not supported.",
                u'errno': ER_UNSUPPORTED_METHOD,
                u'sqlstate': SQLSTATE_FEATURE_NOT_SUPPORTED})

    def close(self):
        u"""
        Closes the cursor object
        """
        try:
            if self.is_closed():
                return False

            with self._lock_canceling:
                self.reset()
                self._connection = None
                del self.messages[:]
                return True
        except:
            pass

    def is_closed(self):
        return self._connection is None or self._connection.is_closed()

    def _execute_helper(
            self, query, timeout=0, statement_params=None,
            is_internal=False, _no_results=False, _is_put_get=None):
        del self.messages[:]

        if statement_params is not None and not isinstance(
                statement_params, dict):
            Error.errorhandler_wrapper(
                self.connection, self,
                ProgrammingError,
                {
                    u'msg': u"The data type of statement params is invalid. "
                            u"It must be dict.",
                    u'errno': ER_INVALID_VALUE,
                })

        self._sequence_counter = self._connection._next_sequence_counter()
        self._request_id = uuid.uuid4()

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            self.logger.debug(
                u'running query [%s]',
                u' '.join(line.strip() for line in query.split(u'\n')),
            )
        if _is_put_get is not None:
            # if told the query is PUT or GET, use the information
            self._is_file_transfer = _is_put_get
        else:
            # or detect it.
            self._is_file_transfer = self.PUT_SQL_RE.match(
                query) or self.GET_SQL_RE.match(query)
        self.logger.debug(u'is_file_transfer: %s',
                          self._is_file_transfer is not None)

        real_timeout = timeout if timeout and timeout > 0 \
            else self._connection.request_timeout

        if real_timeout is not None:
            self._timebomb = Timer(
                real_timeout, self.__cancel_query, [query])
            self._timebomb.start()
        else:
            self._timebomb = None

        original_sigint = signal.getsignal(signal.SIGINT)

        def abort_exit(signum, frame):
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                if self._timebomb is not None:
                    self._timebomb.cancel()
                    self._timebomb = None
                self.__cancel_query(query)
            finally:
                signal.signal(signal.SIGINT, original_sigint)
            raise KeyboardInterrupt

        try:
            signal.signal(signal.SIGINT, abort_exit)
        except ValueError:
            self.logger.info(
                u'Failed to set SIGINT handler. '
                u'Not in main thread. Ignored...')
        try:
            ret = self._connection._cmd_query(
                query,
                self._sequence_counter,
                self._request_id,
                is_file_transfer=self._is_file_transfer,
                statement_params=statement_params,
                is_internal=is_internal,
                _no_results=_no_results)
        finally:
            try:
                signal.signal(signal.SIGINT, original_sigint)
            except ValueError:
                self.logger.info(
                    u'Failed to reset SIGINT handler. Not in main '
                    u'thread. Ignored...')
            if self._timebomb is not None:
                self._timebomb.cancel()
            self.logger.debug(u'cancelled timebomb in finally')

        if u'data' in ret and u'parameters' in ret[u'data']:
            for kv in ret[u'data'][u'parameters']:
                if u'TIMESTAMP_OUTPUT_FORMAT' in kv[u'name']:
                    self._timestamp_output_format = kv[u'value']
                if u'TIMESTAMP_NTZ_OUTPUT_FORMAT' in kv[u'name']:
                    self._timestamp_ntz_output_format = kv[u'value']
                if u'TIMESTAMP_LTZ_OUTPUT_FORMAT' in kv[u'name']:
                    self._timestamp_ltz_output_format = kv[u'value']
                if u'TIMESTAMP_TZ_OUTPUT_FORMAT' in kv[u'name']:
                    self._timestamp_tz_output_format = kv[u'value']
                if u'DATE_OUTPUT_FORMAT' in kv[u'name']:
                    self._date_output_format = kv[u'value']
                if u'TIME_OUTPUT_FORMAT' in kv[u'name']:
                    self._time_output_format = kv[u'value']
                if u'TIMEZONE' in kv[u'name']:
                    self._timezone = kv[u'value']
                if u'BINARY_OUTPUT_FORMAT' in kv[u'name']:
                    self._binary_output_format = kv[u'value']
                if u'CLIENT_RESULT_PREFETCH_THREADS' in kv[u'name']:
                    self._client_result_prefetch_threads = kv[u'value']
                if u'CLIENT_RESULT_PREFETCH_SLOTS' in kv[u'name']:
                    self._client_result_prefetch_slots = kv[u'value']
            self._connection.converter.set_parameters(
                ret[u'data'][u'parameters'])

        self._sequence_counter = -1
        return ret

    def execute(self, command, params=None, timeout=None,
                _do_reset=True,
                _put_callback=None,
                _put_callback_output_stream=sys.stdout,
                _get_callback=None,
                _get_callback_output_stream=sys.stdout,
                _statement_params=None,
                _is_internal=False,
                _no_results=False,
                _use_ijson=False,
                _is_put_get=None):
        u"""
        Executes a command/query
        """
        self.logger.debug(u'executing SQL/command')
        if self.is_closed():
            Error.errorhandler_wrapper(
                self.connection, self,
                DatabaseError,
                {u'msg': u"Cursor is closed in execute.",
                 u'errno': ER_CURSOR_IS_CLOSED})

        if _do_reset:
            self.reset()
        command = command.strip(u' \t\n\r') if command else None
        if not command:
            self.logger.warning(u'execute: no query is given to execute')
            return

        processed_params = self.__process_params(params)
        self.logger.debug(u'binding: %s with input=%s, processed=%s',
                          command,
                          params, processed_params)
        if len(processed_params) > 0:
            query = command % processed_params
        else:
            query = command

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            self.logger.debug(
                u'query: [%s]',
                u' '.join(line.strip() for line in query.split(u'\n')))
        m = DESC_TABLE_RE.match(query)
        if m:
            query1 = u'describe table {0}'.format(m.group(1))
            if self.logger.getEffectiveLevel() <= logging.WARNING:
                self.logger.warning(
                    u'query was rewritten: org=%s, new=%s',
                    u' '.join(line.strip() for line in query.split(u'\n')),
                    query1
                )
            query = query1

        ret = self._execute_helper(query, timeout=timeout,
                                   statement_params=_statement_params,
                                   is_internal=_is_internal,
                                   _no_results=_no_results,
                                   _is_put_get=_is_put_get)
        self._sfqid = ret[u'data'][
            u'queryId'] if u'data' in ret and u'queryId' in ret[
            u'data'] else None
        self._sqlstate = ret[u'data'][
            u'sqlState'] if u'data' in ret and u'sqlState' in ret[
            u'data'] else None
        self.logger.debug(u'sfqid=%s', self._sfqid)

        if ret[u'success']:
            self.logger.debug(u'SUCCESS')
            data = ret[u'data']
            if u'finalDatabaseName' in data:
                self._connection._database = data[u'finalDatabaseName']
            if u'finalSchemaName' in data:
                self._connection._schema = data[u'finalSchemaName']
            if u'finalWarehouseName' in data:
                self._connection._warehouse = data[u'finalWarehouseName']
            if u'finalRoleName' in data:
                self._connection._role = data[u'finalRoleName']

            # self.logger.debug(ret)
            self.logger.debug(u"PUT OR GET: %s", self.is_file_transfer)
            if self.is_file_transfer:
                sf_file_transfer_agent = SnowflakeFileTransferAgent(
                    self, query, ret,
                    put_callback=_put_callback,
                    put_callback_output_stream=_put_callback_output_stream,
                    get_callback=_get_callback,
                    get_callback_output_stream=_get_callback_output_stream)
                sf_file_transfer_agent.execute()
                data = sf_file_transfer_agent.result()
                self._total_rowcount = len(data[u'rowset']) if \
                    u'rowset' in data else -1
            m = self.ALTER_SESSION_RE.match(query)
            if m:
                # session parameters
                param = m.group(1).upper()
                value = m.group(2)
                self._connection.converter.set_parameter(param, value)

            if _no_results:
                self._total_rowcount = ret[u'data'][
                    u'total'] if u'data' in ret and u'total' in ret[
                    u'data'] else -1
                return data
            self.chunk_info(data, use_ijson=_use_ijson)
        else:
            self._total_rowcount = ret[u'data'][
                u'total'] if u'data' in ret and u'total' in ret[u'data'] else -1
            self.logger.info(u'failed')
            self.logger.debug(ret)
            err = ret[u'message']
            code = ret[u'code'] if u'code' in ret else None
            if u'data' in ret and u'errorMessage' in ret[u'data']:
                err += ret[u'data'][u'errorMessage']
            errvalue = {
                u'msg': err,
                u'errno': int(code),
                u'sqlstate': self._sqlstate,
                u'sfqid': self._sfqid
            }
            Error.errorhandler_wrapper(self.connection, self,
                                       ProgrammingError,
                                       errvalue)
        return self

    def _is_dml(self, data):
        return u'statementTypeId' in data \
               and int(data[u'statementTypeId']) in \
                   STATEMENT_TYPE_ID_DML_SET

    def chunk_info(self, data, use_ijson=False):
        is_dml = self._is_dml(data)

        if self._total_rowcount == -1 and not is_dml and data.get(u'total') \
                is not None:
            self._total_rowcount = data['total']

        self._description = []
        self._column_idx_to_name = {}
        self._column_converter = []
        for idx, column in enumerate(data[u'rowtype']):
            self._column_idx_to_name[idx] = column[u'name']
            type_value = FIELD_NAME_TO_ID[column[u'type'].upper()]
            self._description.append((column[u'name'],
                                      type_value,
                                      None,
                                      column[u'length'],
                                      column[u'precision'],
                                      column[u'scale'],
                                      column[u'nullable']))
            self._column_converter.append(
                self._connection.converter.to_python_method(
                    column[u'type'].upper(), column))

        self._total_row_index = -1  # last fetched number of rows

        self._chunk_index = 0
        self._chunk_count = 0
        self._current_chunk_row = iter(data.get(u'rowset'))
        self._current_chunk_row_count = len(data.get(u'rowset'))

        if u'chunks' in data:
            chunks = data[u'chunks']
            self._chunk_count = len(chunks)
            self.logger.debug(u'chunk size=%s', self._chunk_count)
            # prepare the downloader for further fetch
            qrmk = data[u'qrmk'] if u'qrmk' in data else None
            chunk_headers = None
            if u'chunkHeaders' in data:
                chunk_headers = {}
                for header_key, header_value in data[
                    u'chunkHeaders'].items():
                    chunk_headers[header_key] = header_value
                    self.logger.debug(
                        u'added chunk header: key=%s, value=%s',
                        header_key,
                        header_value)

            self.logger.debug(u'qrmk=%s', qrmk)
            self._chunk_downloader = self._connection._chunk_downloader_class(
                chunks, self._connection, self, qrmk, chunk_headers,
                prefetch_slots=self._client_result_prefetch_slots,
                prefetch_threads=self._client_result_prefetch_threads,
                use_ijson=use_ijson)

        if is_dml:
            updated_rows = 0
            for idx, desc in enumerate(self._description):
                if desc[0] in (
                        u'number of rows updated',
                        u'number of multi-joined rows updated',
                        u'number of rows deleted') or \
                        desc[0].startswith(u'number of rows inserted'):
                    updated_rows += int(data[u'rowset'][0][idx])
            if self._total_rowcount == -1:
                self._total_rowcount = updated_rows
            else:
                self._total_rowcount += updated_rows

    def query_result(self, qid, _use_ijson=False):
        url = ('/queries/{qid}/result').format(qid=qid)
        ret = self._connection._con.request(url=url, method='get')
        self._sfqid = ret[u'data'][
            u'queryId'] if u'data' in ret and u'queryId' in ret[
            u'data'] else None
        self._sqlstate = ret[u'data'][
            u'sqlState'] if u'data' in ret and u'sqlState' in ret[
            u'data'] else None
        self.logger.debug(u'sfqid=%s', self._sfqid)

        if ret.get(u'success'):
            data = ret.get(u'data')
            self.chunk_info(data, use_ijson=_use_ijson)
        else:
            self.logger.info(u'failed')
            self.logger.debug(ret)
            err = ret[u'message']
            code = ret[u'code'] if u'code' in ret else None
            if u'data' in ret and u'errorMessage' in ret[u'data']:
                err += ret[u'data'][u'errorMessage']
            errvalue = {
                u'msg': err,
                u'errno': int(code),
                u'sqlstate': self._sqlstate,
                u'sfqid': self._sfqid
            }
            Error.errorhandler_wrapper(self.connection, self,
                                       ProgrammingError,
                                       errvalue)
        return self

    def abort_query(self, qid):
        url = '/queries/{qid}/abort-request'.format(qid=qid)
        ret = self._connection._con.request(url=url, method='post')
        return ret.get(u'success')

    def executemany(self, command, seqparams):
        u"""
        Executes a command/query with the given set of parameters sequentially.
        """
        self.logger.info(u'executing many SQLs/commands')
        command = command.strip(u' \t\n\r') if command else None

        if self.INSERT_SQL_RE.match(command):
            self.logger.debug(u'rewriting INSERT query')
            command_wo_comments = re.sub(self.COMMENT_SQL_RE, u'', command)
            m = self.INSERT_SQL_VALUES_RE.match(command_wo_comments)
            if not m:
                errorvalue = {
                    u'msg': u"Failed to rewrite multi-row insert",
                    u'errno': ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT
                }
                Error.errorhandler_wrapper(
                    self.connection, self, InterfaceError, errorvalue
                )

            fmt = m.group(1)
            values = []
            for param in seqparams:
                self.logger.debug(u'parameter: %s', param)
                values.append(fmt % self.__process_params(param))
            command = command.replace(fmt, u','.join(values), 1)
            self.execute(command)
            return self

        self.reset()
        for param in seqparams:
            self.execute(command, param, _do_reset=False)
        return self

    def fetchone(self):
        """
        Fetch one row
        """
        try:
            row = None
            self._total_row_index += 1
            try:
                row = next(self._current_chunk_row)
            except StopIteration:
                if self._chunk_index < self._chunk_count:
                    self.logger.debug(
                        u"chunk index: %s, chunk_count: %s",
                        self._chunk_index, self._chunk_count)
                    next_chunk = self._chunk_downloader.next_chunk()
                    self._current_chunk_row_count = next_chunk.row_count
                    self._current_chunk_row = next_chunk.result_data
                    self._chunk_index += 1
                    try:
                        row = next(self._current_chunk_row)
                    except StopIteration:
                        raise IndexError
                else:
                    if self._chunk_count > 0 and \
                                    self._chunk_downloader is not None:
                        self._chunk_downloader.terminate()
                    self._chunk_downloader = None
                    self._chunk_count = 0
                    self._current_chunk_row = iter(())
            return self._row_to_python(row) if row is not None else None

        except IndexError:
            # returns None if the iteration is completed so that iter() stops
            return None

    def fetchmany(self, size=None):
        u"""
        Fetch the number of specified rows
        """
        if size is None:
            size = self.arraysize

        if size < 0:
            errorvalue = {
                u'msg': (u"The number of rows is not zero or "
                         u"positive number: {0}").format(
                    size),
                u'errno': ER_NOT_POSITIVE_SIZE}
            Error.errorhandler_wrapper(
                self.connection, self, ProgrammingError, errorvalue)
        ret = []
        while size > 0:
            row = self.fetchone()
            if row is None:
                break
            ret.append(row)
            if size is not None:
                size -= 1

        return ret

    def fetchall(self):
        u"""
        Fetch all data
        """
        ret = []
        while True:
            row = self.fetchone()
            if row is None:
                break
            ret.append(row)
        return ret

    def nextset(self):
        u"""
        Not supporeted
        """
        self.logger.info(u'nop')
        return None

    def setinputsizes(self, sizes):
        u"""
        Not supported
        """
        del sizes
        self.logger.info(u'nop')

    def setoutputsize(self, size, column=None):
        u"""
        Not supported
        """
        del column, size
        self.logger.info(u'nop')

    def scroll(self, value, mode=u'relative'):
        Error.errorhandler_wrapper(
            self.connection, self,
            NotSupportedError,
            {
                u'msg': u"scroll is not supported.",
                u'errno': ER_UNSUPPORTED_METHOD,
                u'sqlstate': SQLSTATE_FEATURE_NOT_SUPPORTED})

    def reset(self):
        u"""
        Reset the result set
        """
        self._total_rowcount = -1  # reset the rowcount
        self._total_row_index = -1  # last fetched number of rows
        self._current_chunk_row_count = 0
        self._current_chunk_row = iter(())
        self._chunk_index = 0

        if hasattr(self, u'_chunk_count') and self._chunk_count > 0 and \
                        self._chunk_downloader is not None:
            self._chunk_downloader.terminate()

        self._chunk_count = 0
        self._chunk_downloader = None

    def __iter__(self):
        u"""
        Iteration over the result set
        """
        return iter(self.fetchone, None)

    def __cancel_query(self, query):
        if self._sequence_counter >= 0 and not self.is_closed():
            self.logger.debug(u'canceled : %s, %s',
                              query, self._sequence_counter)
            with self._lock_canceling:
                self._connection._cancel_query(
                    query,
                    self._sequence_counter,
                    self._request_id)

    def __process_params_dict(self, params):
        try:
            to_snowflake = self._connection.converter.to_snowflake
            escape = self._connection.converter.escape
            quote = self._connection.converter.quote
            res = {}
            for k, v in params.items():
                c = v
                c = to_snowflake(c)
                c = escape(c)
                c = quote(c)
                res[k] = c
            self.logger.debug(u'parameters: %s', res)
            return res
        except Exception as e:
            errorvalue = {
                u'msg': u"Failed processing pyformat-parameters; {0}".format(
                    e),
                u'errno': ER_FAILED_PROCESSING_PYFORMAT}
            Error.errorhandler_wrapper(
                self.connection, self, ProgrammingError, errorvalue)

    def __process_params(self, params):
        if params is None:
            return {}
        if isinstance(params, dict):
            return self.__process_params_dict(params)

        if not isinstance(params, (tuple, list)):
            params = [params, ]

        try:
            res = params
            res = map(self._connection.converter.to_snowflake, res)
            res = map(self._connection.converter.escape, res)
            res = map(self._connection.converter.quote, res)
            ret = tuple(res)
            self.logger.debug(u'parameters: %s', ret)
            return ret
        except Exception as e:
            errorvalue = {
                u'msg': u"Failed processing pyformat-parameters; {0}".format(
                    e),
                u'errno': ER_FAILED_PROCESSING_PYFORMAT}
            Error.errorhandler_wrapper(self.connection, self,
                                       ProgrammingError,
                                       errorvalue)

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
                col_desc = self._description[idx]
                msg = u'Failed to convert: ' \
                      u'field {name}: {type}::{value}, Error: ' \
                      u'{error}'.format(
                    name=col_desc[0],
                    type=FIELD_ID_TO_NAME[col_desc[1]],
                    value=col,
                    error=e
                )
                self.logger.exception(msg)
                Error.errorhandler_wrapper(
                    self.connection, self, InterfaceError, {
                        u'msg': msg,
                        u'errno': ER_FAILED_TO_CONVERT_ROW_TO_PYTHON_TYPE,
                    })
            idx += 1
        return tuple(row)

    def __enter__(self):
        """
        context manager
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        context manager with commit or rollback
        """
        self.close()


class DictCursor(SnowflakeCursor):
    """
    Cursor returning results in a dictionary
    """

    def __init__(self, connection):
        SnowflakeCursor.__init__(self, connection)

    def _row_to_python(self, row):
        # see the base class
        res = {}
        idx = 0
        for col in row:
            col_name = self._column_idx_to_name[idx]
            conv = self._column_converter[idx]
            try:
                res[col_name] = col if conv is None or col is None else conv(col)
            except Exception as e:
                col_desc = self._description[idx]
                msg = u'Failed to convert: ' \
                      u'field {name}: {type}::{value}, Error: ' \
                      u'{error}'.format(
                    name=col_desc[0],
                    type=FIELD_ID_TO_NAME[col_desc[1]],
                    value=col,
                    error=e
                )
                self.logger.exception(msg)
                Error.errorhandler_wrapper(
                    self.connection, self, InterfaceError, {
                        u'msg': msg,
                        u'errno': ER_FAILED_TO_CONVERT_ROW_TO_PYTHON_TYPE,
                    })
            idx += 1
        return res
