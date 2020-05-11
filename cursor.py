#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import logging
import re
import signal
import sys
import uuid
from logging import getLogger
from threading import (Timer, Lock)

MYPY = False
if MYPY:  # from typing import TYPE_CHECKING once 3.5 is deprecated
    from .connection import SnowflakeConnection
from .compat import (BASE_EXCEPTION_CLASS)
from .constants import (
    FIELD_NAME_TO_ID,
    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT
)
from .errorcode import (ER_UNSUPPORTED_METHOD,
                        ER_CURSOR_IS_CLOSED,
                        ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT,
                        ER_NOT_POSITIVE_SIZE,
                        ER_INVALID_VALUE,
                        ER_NO_PYARROW,
                        ER_NO_ARROW_RESULT,
                        ER_NO_PYARROW_SNOWSQL)
from .errors import (Error, ProgrammingError, NotSupportedError,
                     DatabaseError, InterfaceError)
from .file_transfer_agent import (SnowflakeFileTransferAgent)
from .json_result import JsonResult, DictJsonResult
from .sqlstate import (SQLSTATE_FEATURE_NOT_SUPPORTED)
from .telemetry import (TelemetryData, TelemetryField)
from .time_util import get_time_millis

logger = getLogger(__name__)

try:
    import pyarrow
except ImportError:
    logger.debug(u"Failed to import pyarrow. Cannot use pandas fetch API")
    pyarrow = None

try:
    from .arrow_result import ArrowResult
    CAN_USE_ARROW_RESULT = True
except ImportError as e:
    logger.debug(u"Failed to import ArrowResult. No Apache Arrow result set format can be used. ImportError: %s", e)
    CAN_USE_ARROW_RESULT = False

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

DESC_TABLE_RE = re.compile(r'desc(?:ribe)?\s+([\w_]+)\s*;?\s*$',
                           flags=re.IGNORECASE)

LOG_MAX_QUERY_LENGTH = 80


class SnowflakeCursor(object):
    u"""
    Implementation of Cursor object that is returned from Connection.cursor()
    method.
    """
    PUT_SQL_RE = re.compile(r'^(?:/\*.*\*/\s*)*put\s+', flags=re.IGNORECASE)
    GET_SQL_RE = re.compile(r'^(?:/\*.*\*/\s*)*get\s+', flags=re.IGNORECASE)
    INSERT_SQL_RE = re.compile(r'^insert\s+into', flags=re.IGNORECASE)
    COMMENT_SQL_RE = re.compile(r"/\*.*\*/")
    INSERT_SQL_VALUES_RE = re.compile(r'.*VALUES\s*(\(.*\)).*',
                                      re.IGNORECASE | re.MULTILINE | re.DOTALL)
    ALTER_SESSION_RE = re.compile(
        r'alter\s+session\s+set\s+(.*)=\'?([^\']+)\'?\s*;',
        flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)

    def __init__(self,
                 connection: 'SnowflakeConnection',
                 use_dict_result: bool = False,
                 json_result_class: object = JsonResult):
        """
        :param connection: connection created this cursor
        :param use_dict_result: whether use dict result or not. This variable only applied to
                                arrow result. When result in json, json_result_class will be
                                honored
        :param json_result_class: class that used in json result
        """
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
        self._result = None
        self._use_dict_result = use_dict_result
        self._json_result_class = json_result_class

        self._arraysize = 1  # PEP-0249: defaults to 1

        self._lock_canceling = Lock()

        self._first_chunk_time = None

        self._log_max_query_length = connection.log_max_query_length

        self.reset()

    def __del__(self):
        try:
            self.close()
        except BASE_EXCEPTION_CLASS as e:
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
        return self._result.total_row_index if self._result.total_row_index >= 0 else None

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
        logger.debug(u'setting errorhandler: %s', value)
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
        except Exception:
            pass

    def is_closed(self):
        return self._connection is None or self._connection.is_closed()

    def _execute_helper(
            self, query, timeout=0, statement_params=None,
            binding_params=None,
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

        # check if current installation include arrow extension or not,
        # if not, we set statement level query result format to be JSON
        if not CAN_USE_ARROW_RESULT:
            logger.debug(u"Cannot use arrow result format, fallback to json format")
            if statement_params is None:
                statement_params = {PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: 'JSON'}
            else:
                result_format_val = statement_params.get(PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT)
                if str(result_format_val).upper() == u'ARROW':
                    self.check_can_use_arrow_resultset()
                elif result_format_val is None:
                    statement_params[PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT] = 'JSON'

        self._sequence_counter = self._connection._next_sequence_counter()
        self._request_id = uuid.uuid4()

        if logger.getEffectiveLevel() <= logging.DEBUG:
            logger.debug(
                u'running query [%s]', self._format_query_for_log(query))
        if _is_put_get is not None:
            # if told the query is PUT or GET, use the information
            self._is_file_transfer = _is_put_get
        else:
            # or detect it.
            self._is_file_transfer = self.PUT_SQL_RE.match(
                query) or self.GET_SQL_RE.match(query)
        logger.debug(u'is_file_transfer: %s',
                     self._is_file_transfer is not None)

        real_timeout = timeout if timeout and timeout > 0 \
            else self._connection.network_timeout

        if real_timeout is not None:
            self._timebomb = Timer(
                real_timeout, self.__cancel_query, [query])
            self._timebomb.start()
            logger.debug(u'started timebomb in %ss', real_timeout)
        else:
            self._timebomb = None

        original_sigint = signal.getsignal(signal.SIGINT)

        def abort_exit(*_):
            try:
                signal.signal(signal.SIGINT, signal.SIG_IGN)
            except (ValueError, TypeError):
                # ignore failures
                pass
            try:
                if self._timebomb is not None:
                    self._timebomb.cancel()
                    logger.debug(u'cancelled timebomb in finally')
                    self._timebomb = None
                self.__cancel_query(query)
            finally:
                if original_sigint:
                    try:
                        signal.signal(signal.SIGINT, original_sigint)
                    except (ValueError, TypeError):
                        # ignore failures
                        pass
            raise KeyboardInterrupt

        try:
            signal.signal(signal.SIGINT, abort_exit)
        except ValueError:
            logger.debug(
                u'Failed to set SIGINT handler. '
                u'Not in main thread. Ignored...')
        ret = {u'data': {}}
        try:
            ret = self._connection.cmd_query(
                query,
                self._sequence_counter,
                self._request_id,
                binding_params=binding_params,
                is_file_transfer=self._is_file_transfer,
                statement_params=statement_params,
                is_internal=is_internal,
                _no_results=_no_results)
        finally:
            try:
                if original_sigint:
                    signal.signal(signal.SIGINT, original_sigint)
            except (ValueError, TypeError):
                logger.debug(
                    u'Failed to reset SIGINT handler. Not in main '
                    u'thread. Ignored...')
            except Exception:
                self.connection.incident.report_incident()
                raise
            if self._timebomb is not None:
                self._timebomb.cancel()
                logger.debug(u'cancelled timebomb in finally')

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
            self._connection._set_parameters(
                ret, self._connection._session_parameters)

        self._sequence_counter = -1
        return ret

    def execute(self, command, params=None, timeout=None,
                _do_reset=True,
                _put_callback=None,
                _put_azure_callback=None,
                _put_callback_output_stream=sys.stdout,
                _get_callback=None,
                _get_azure_callback=None,
                _get_callback_output_stream=sys.stdout,
                _show_progress_bar=True,
                _statement_params=None,
                _is_internal=False,
                _no_results=False,
                _use_ijson=False,
                _is_put_get=None,
                _raise_put_get_error=True,
                _force_put_overwrite=False):
        u"""
        Executes a command/query
        """
        logger.debug(u'executing SQL/command')
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
            logger.warning(u'execute: no query is given to execute')
            return

        try:
            if self._connection.is_pyformat:
                # pyformat/format paramstyle
                # client side binding
                processed_params = self._connection._process_params(params, self)
                if logger.getEffectiveLevel() <= logging.DEBUG:
                    logger.debug(u'binding: [%s] with input=[%s], processed=[%s]',
                                 self._format_query_for_log(command),
                                 params, processed_params)
                if len(processed_params) > 0:
                    query = command % processed_params
                else:
                    query = command
                processed_params = None  # reset to None
            else:
                # qmark and numeric paramstyle
                # server side binding
                query = command
                processed_params = self._connection._process_params_qmarks(
                    params, self)
        # Skip reporting Key, Value and Type errors
        except (KeyError, ValueError, TypeError):
            raise
        except Exception:
            self.connection.incident.report_incident()
            raise

        m = DESC_TABLE_RE.match(query)
        if m:
            query1 = u'describe table {}'.format(m.group(1))
            if logger.getEffectiveLevel() <= logging.WARNING:
                logger.info(
                    u'query was rewritten: org=%s, new=%s',
                    u' '.join(line.strip() for line in query.split(u'\n')),
                    query1
                )
            query = query1

        if logger.getEffectiveLevel() <= logging.INFO:
            logger.info(
                u'query: [%s]', self._format_query_for_log(query))
        ret = self._execute_helper(
            query,
            timeout=timeout,
            binding_params=processed_params,
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
        self._first_chunk_time = get_time_millis()

        # if server gives a send time, log the time it took to arrive
        if u'data' in ret and u'sendResultTime' in ret[u'data']:
            time_consume_first_result = self._first_chunk_time - ret[u'data'][
                u'sendResultTime']
            self._log_telemetry_job_data(
                TelemetryField.TIME_CONSUME_FIRST_RESULT,
                time_consume_first_result)
        logger.debug('sfqid: %s', self.sfqid)

        logger.info('query execution done')
        if ret[u'success']:
            logger.debug(u'SUCCESS')
            data = ret[u'data']

            # logger.debug(ret)
            logger.debug(u"PUT OR GET: %s", self.is_file_transfer)
            if self.is_file_transfer:
                sf_file_transfer_agent = SnowflakeFileTransferAgent(
                    self, query, ret,
                    put_callback=_put_callback,
                    put_azure_callback=_put_azure_callback,
                    put_callback_output_stream=_put_callback_output_stream,
                    get_callback=_get_callback,
                    get_azure_callback=_get_azure_callback,
                    get_callback_output_stream=_get_callback_output_stream,
                    show_progress_bar=_show_progress_bar,
                    raise_put_get_error=_raise_put_get_error,
                    force_put_overwrite=_force_put_overwrite or data.get('overwrite', False))
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
            self._init_result_and_meta(data)
        else:
            self._total_rowcount = ret[u'data'][
                u'total'] if u'data' in ret and u'total' in ret[u'data'] else -1
            logger.debug(ret)
            err = ret[u'message']
            code = ret.get(u'code', -1)
            if u'data' in ret:
                err += ret[u'data'].get(u'errorMessage', '')
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

    def _format_query_for_log(self, query):
        return self._connection._format_query_for_log(query)

    def _is_dml(self, data):
        return u'statementTypeId' in data \
               and int(data[u'statementTypeId']) in \
               STATEMENT_TYPE_ID_DML_SET

    def _init_result_and_meta(self, data):
        is_dml = self._is_dml(data)
        self._query_result_format = data.get(u'queryResultFormat', u'json')
        logger.debug(u"Query result format: %s", self._query_result_format)

        if self._total_rowcount == -1 and not is_dml and data.get(u'total') \
                is not None:
            self._total_rowcount = data['total']

        self._description = []

        for column in data[u'rowtype']:
            type_value = FIELD_NAME_TO_ID[column[u'type'].upper()]
            self._description.append((column[u'name'],
                                      type_value,
                                      None,
                                      column[u'length'],
                                      column[u'precision'],
                                      column[u'scale'],
                                      column[u'nullable']))

        if self._query_result_format == 'arrow':
            self.check_can_use_arrow_resultset()
            self._result = ArrowResult(data, self, use_dict_result=self._use_dict_result)
        else:
            self._result = self._json_result_class(data, self)

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

    def check_can_use_arrow_resultset(self):
        global CAN_USE_ARROW_RESULT

        if not CAN_USE_ARROW_RESULT:
            if self._connection.application == 'SnowSQL':
                msg = (
                    "Currently SnowSQL doesn't support the result set in Apache Arrow format."
                )
                errno = ER_NO_PYARROW_SNOWSQL
            else:
                msg = (
                    "The result set in Apache Arrow format is not supported for the platform."
                )
                errno = ER_NO_ARROW_RESULT

            Error.errorhandler_wrapper(
                self.connection, self,
                ProgrammingError,
                {
                    u'msg': msg,
                    u'errno': errno,
                }
            )

    def check_can_use_pandas(self):
        global pyarrow

        if pyarrow is None:
            msg = (
                "pyarrow package is missing. Install using pip if the platform is supported."
            )
            errno = ER_NO_PYARROW

            Error.errorhandler_wrapper(
                self.connection, self,
                ProgrammingError,
                {
                    u'msg': msg,
                    u'errno': errno,
                }
            )

    def query_result(self, qid):
        url = '/queries/{qid}/result'.format(qid=qid)
        ret = self._connection.rest.request(url=url, method='get')
        self._sfqid = ret[u'data'][
            u'queryId'] if u'data' in ret and u'queryId' in ret[
            u'data'] else None
        self._sqlstate = ret[u'data'][
            u'sqlState'] if u'data' in ret and u'sqlState' in ret[
            u'data'] else None
        logger.debug(u'sfqid=%s', self._sfqid)

        if ret.get(u'success'):
            data = ret.get(u'data')
            self._init_result_and_meta(data)
        else:
            logger.info(u'failed')
            logger.debug(ret)
            err = ret[u'message']
            code = ret.get(u'code', -1)
            if u'data' in ret:
                err += ret[u'data'].get(u'errorMessage', '')
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

    def fetch_pandas_batches(self, **kwargs):
        u"""
        Fetch a single Arrow Table
        @param kwargs: will be passed to pyarrow.Table.to_pandas() method
        """
        self.check_can_use_pandas()
        if self._query_result_format != 'arrow':  # TODO: or pandas isn't imported
            raise NotSupportedError
        for df in self._result._fetch_pandas_batches(**kwargs):
            yield df

    def fetch_pandas_all(self, **kwargs):
        u"""
        Fetch Pandas dataframes in batch, where 'batch' refers to Snowflake Chunk
        @param kwargs: will be passed to pyarrow.Table.to_pandas() method
        """
        self.check_can_use_pandas()
        if self._query_result_format != 'arrow':
            raise NotSupportedError
        return self._result._fetch_pandas_all(**kwargs)

    def abort_query(self, qid):
        url = '/queries/{qid}/abort-request'.format(qid=qid)
        ret = self._connection.rest.request(url=url, method='post')
        return ret.get(u'success')

    def executemany(self, command, seqparams):
        u"""
        Executes a command/query with the given set of parameters sequentially.
        """
        logger.debug(u'executing many SQLs/commands')
        command = command.strip(u' \t\n\r') if command else None

        if len(seqparams) == 0:
            errorvalue = {
                u'msg': u"No parameters are specified for the command: "
                        u"{}".format(command),
                u'errno': ER_INVALID_VALUE,
            }
            Error.errorhandler_wrapper(
                self.connection, self, InterfaceError, errorvalue
            )
            return self

        if self.INSERT_SQL_RE.match(command):
            if self._connection.is_pyformat:
                logger.debug(u'rewriting INSERT query')
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
                    logger.debug(u'parameter: %s', param)
                    values.append(fmt % self._connection._process_params(
                        param, self))
                command = command.replace(fmt, u','.join(values), 1)
                self.execute(command)
                return self
            else:
                logger.debug(u'bulk insert')
                num_params = len(seqparams[0])
                pivot_param = []
                for _ in range(num_params):
                    pivot_param.append([])
                for row in seqparams:
                    if len(row) != num_params:
                        errorvalue = {
                            u'msg':
                                u"Bulk data size don't match. expected: {}, "
                                u"got: {}, command: {}".format(
                                    num_params, len(row), command),
                            u'errno': ER_INVALID_VALUE,
                        }
                        Error.errorhandler_wrapper(
                            self.connection, self, InterfaceError, errorvalue
                        )
                        return self
                    for idx, value in enumerate(row):
                        pivot_param[idx].append(value)
                self.execute(command, params=pivot_param)
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
            return next(self._result)
        except StopIteration:
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
        logger.debug(u'nop')
        return None

    def setinputsizes(self, _):
        u"""
        Not supported
        """
        logger.debug(u'nop')

    def setoutputsize(self, _, column=None):
        u"""
        Not supported
        """
        del column
        logger.debug(u'nop')

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
        if self._result is not None:
            self._result._reset()

    def __iter__(self):
        u"""
        Iteration over the result set
        """
        return iter(self._result)

    def __cancel_query(self, query):
        if self._sequence_counter >= 0 and not self.is_closed():
            logger.debug(u'canceled. %s, request_id: %s',
                         query, self._request_id)
            with self._lock_canceling:
                self._connection._cancel_query(query, self._request_id)

    def _log_telemetry_job_data(self, telemetry_field, value):
        u"""
        Builds an instance of TelemetryData with the given field and logs it
        """
        obj = {
            'type': telemetry_field,
            'query_id': self._sfqid,
            'value': int(value)
        }
        ts = get_time_millis()
        try:
            self._connection._log_telemetry(TelemetryData(obj, ts))
        except AttributeError:
            logger.warning(
                "Cursor failed to log to telemetry. Connection object may be None.",
                exc_info=True)

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
        SnowflakeCursor.__init__(self, connection, use_dict_result=True, json_result_class=DictJsonResult)
