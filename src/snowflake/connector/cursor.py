#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import logging
import re
import signal
import sys
import uuid
from logging import getLogger
from threading import Lock, Timer
from typing import IO, TYPE_CHECKING, Dict, List, Optional, Tuple, Union

from .compat import BASE_EXCEPTION_CLASS
from .constants import FIELD_NAME_TO_ID, PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT
from .errorcode import (
    ER_CURSOR_IS_CLOSED,
    ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT,
    ER_INVALID_VALUE,
    ER_NO_ARROW_RESULT,
    ER_NO_PYARROW,
    ER_NO_PYARROW_SNOWSQL,
    ER_NOT_POSITIVE_SIZE,
    ER_UNSUPPORTED_METHOD,
)
from .errors import DatabaseError, Error, InterfaceError, NotSupportedError, ProgrammingError
from .file_transfer_agent import SnowflakeFileTransferAgent
from .json_result import DictJsonResult, JsonResult
from .sqlstate import SQLSTATE_FEATURE_NOT_SUPPORTED
from .telemetry import TelemetryData, TelemetryField
from .time_util import get_time_millis

if TYPE_CHECKING:  # pragma: no cover
    from .connection import SnowflakeConnection
    from .file_transfer_agent import SnowflakeProgressPercentage

logger = getLogger(__name__)

try:
    import pyarrow
except ImportError:
    logger.debug("Failed to import pyarrow. Cannot use pandas fetch API")
    pyarrow = None

try:
    from .arrow_result import ArrowResult
    CAN_USE_ARROW_RESULT = True
except ImportError as e:  # pragma: no cover
    logger.debug("Failed to import ArrowResult. No Apache Arrow result set format can be used. ImportError: %s", e)
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


def exit_handler(*_):  # pragma: no cover
    """Handler for signal. When called, it will raise SystemExit with exit code FORCE_EXIT."""
    print("\nForce exit")
    logger.info("Force exit")
    sys.exit(1)


class SnowflakeCursor(object):
    """Implementation of Cursor object that is returned from Connection.cursor() method.

    Attributes:
        description: tuple of name, type_code, display_size, internal_size, precisio, scale, null_ok
        rowcount: The number of records updated or selected. If not clear, -1 is returned.
        rownumber: The current 0-based index of the cursor in the result set or None if the index cannot be
            determined.
        sfqid: Snowflake query id in UUID form. Include this in the problem report to the customer support.
        sqlstate: Snowflake SQL State code.
        timestamp_output_format: Snowflake timestamp_output_format for timestamps.
        timestamp_ltz_output_format: Snowflake output format for LTZ timestamps.
        timestamp_tz_output_format: Snowflake output format for TZ timestamps.
        timestamp_ntz_output_format: Snowflake output format for NTZ timestamps.
        date_output_format: Snowflake output format for dates.
        time_output_format: Snowflake output format for times.
        timezone: Snowflake timezone.
        binary_output_format: Snowflake output format for binary fields.
        arraysize: The default number of rows fetched by fetchmany.
        connection: The connection object by which the cursor was created.
        errorhandle: The class that handles error handling.
        is_file_transfer: Whether, or not the current command is a put, or get.

    TODO:
        Most of these attributes have no reason to be properties, we could just store them in public variables.
        Calling a function is expensive in Python and most of these getters are unnecessary.
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
        """Inits a SnowflakeCursor with a connection.

        Args:
            connection: The connection that created this cursor.
            use_dict_result: Decides whether to use dict result or not. This variable only applied to
                arrow result. When result in json, json_result_class will be honored.
            json_result_class: The class that used in json result.
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

    def __del__(self):  # pragma: no cover
        try:
            self.close()
        except BASE_EXCEPTION_CLASS as e:
            if logger.getEffectiveLevel() <= logging.INFO:
                logger.info(e)

    @property
    def description(self):
        return self._description

    @property
    def rowcount(self):
        return self._total_rowcount if self._total_rowcount >= 0 else None

    @property
    def rownumber(self):
        return self._result.total_row_index if self._result.total_row_index >= 0 else None

    @property
    def sfqid(self):
        return self._sfqid

    @property
    def sqlstate(self):
        return self._sqlstate

    @property
    def timestamp_output_format(self):
        return self._timestamp_output_format

    @property
    def timestamp_ltz_output_format(self):
        return self._timestamp_ltz_output_format if \
            self._timestamp_ltz_output_format else \
            self._timestamp_output_format

    @property
    def timestamp_tz_output_format(self):
        return self._timestamp_tz_output_format if \
            self._timestamp_tz_output_format else \
            self._timestamp_output_format

    @property
    def timestamp_ntz_output_format(self):
        return self._timestamp_ntz_output_format if \
            self._timestamp_ntz_output_format else \
            self._timestamp_output_format

    @property
    def date_output_format(self):
        return self._date_output_format

    @property
    def time_output_format(self):
        return self._time_output_format

    @property
    def timezone(self):
        return self._timezone

    @property
    def binary_output_format(self):
        return self._binary_output_format

    @property
    def arraysize(self):
        return self._arraysize

    @arraysize.setter
    def arraysize(self, value):
        self._arraysize = int(value)

    @property
    def connection(self):
        return self._connection

    @property
    def errorhandler(self):
        return self._errorhandler

    @errorhandler.setter
    def errorhandler(self, value):
        logger.debug('setting errorhandler: %s', value)
        if value is None:
            raise ProgrammingError('Invalid errorhandler is specified')
        self._errorhandler = value

    @property
    def is_file_transfer(self):
        """Whether the command is PUT or GET."""
        return hasattr(self, '_is_file_transfer') and self._is_file_transfer

    def callproc(self, procname, args=()):
        """Not supported."""
        Error.errorhandler_wrapper(
            self.connection, self,
            NotSupportedError,
            {
                'msg': "callproc is not supported.",
                'errno': ER_UNSUPPORTED_METHOD,
                'sqlstate': SQLSTATE_FEATURE_NOT_SUPPORTED})

    def close(self) -> Optional[bool]:
        """Closes the cursor object.

        Returns whether the cursor was closed during this call.
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

    def _execute_helper(self,
                        query: str,
                        timeout: int = 0,
                        statement_params: Optional[Dict[str, str]] = None,
                        binding_params: Union[Tuple, Dict[str, Dict[str, str]]] = None,
                        is_internal: bool = False,
                        _no_results: bool = False,
                        _is_put_get=None):
        del self.messages[:]

        if statement_params is not None and not isinstance(
                statement_params, dict):
            Error.errorhandler_wrapper(
                self.connection, self,
                ProgrammingError,
                {
                    'msg': "The data type of statement params is invalid. It must be dict.",
                    'errno': ER_INVALID_VALUE,
                })

        # check if current installation include arrow extension or not,
        # if not, we set statement level query result format to be JSON
        if not CAN_USE_ARROW_RESULT:
            logger.debug("Cannot use arrow result format, fallback to json format")
            if statement_params is None:
                statement_params = {PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: 'JSON'}
            else:
                result_format_val = statement_params.get(PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT)
                if str(result_format_val).upper() == 'ARROW':
                    self.check_can_use_arrow_resultset()
                elif result_format_val is None:
                    statement_params[PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT] = 'JSON'

        self._sequence_counter = self._connection._next_sequence_counter()
        self._request_id = uuid.uuid4()

        if logger.getEffectiveLevel() <= logging.DEBUG:
            logger.debug(
                'running query [%s]', self._format_query_for_log(query))
        if _is_put_get is not None:
            # if told the query is PUT or GET, use the information
            self._is_file_transfer = _is_put_get
        else:
            # or detect it.
            self._is_file_transfer = self.PUT_SQL_RE.match(
                query) or self.GET_SQL_RE.match(query)
        logger.debug('is_file_transfer: %s',
                     self._is_file_transfer is not None)

        real_timeout = timeout if timeout and timeout > 0 \
            else self._connection.network_timeout

        if real_timeout is not None:
            self._timebomb = Timer(
                real_timeout, self.__cancel_query, [query])
            self._timebomb.start()
            logger.debug('started timebomb in %ss', real_timeout)
        else:
            self._timebomb = None

        original_sigint = signal.getsignal(signal.SIGINT)

        def interrupt_handler(*_):  # pragma: no cover
            try:
                signal.signal(signal.SIGINT, exit_handler)
            except (ValueError, TypeError):
                # ignore failures
                pass
            try:
                if self._timebomb is not None:
                    self._timebomb.cancel()
                    logger.debug('cancelled timebomb in finally')
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
            if not original_sigint == exit_handler:
                signal.signal(signal.SIGINT, interrupt_handler)
        except ValueError:  # pragma: no cover
            logger.debug(
                'Failed to set SIGINT handler. '
                'Not in main thread. Ignored...')
        ret = {'data': {}}
        try:
            ret = self._connection.cmd_query(
                query,
                self._sequence_counter,
                self._request_id,
                binding_params=binding_params,
                is_file_transfer=bool(self._is_file_transfer),
                statement_params=statement_params,
                is_internal=is_internal,
                _no_results=_no_results)
        finally:
            try:
                if original_sigint:
                    signal.signal(signal.SIGINT, original_sigint)
            except (ValueError, TypeError):  # pragma: no cover
                logger.debug(
                    'Failed to reset SIGINT handler. Not in main '
                    'thread. Ignored...')
            except Exception:
                self.connection.incident.report_incident()
                raise
            if self._timebomb is not None:
                self._timebomb.cancel()
                logger.debug('cancelled timebomb in finally')

        if 'data' in ret and 'parameters' in ret['data']:
            for kv in ret['data']['parameters']:
                if 'TIMESTAMP_OUTPUT_FORMAT' in kv['name']:
                    self._timestamp_output_format = kv['value']
                if 'TIMESTAMP_NTZ_OUTPUT_FORMAT' in kv['name']:
                    self._timestamp_ntz_output_format = kv['value']
                if 'TIMESTAMP_LTZ_OUTPUT_FORMAT' in kv['name']:
                    self._timestamp_ltz_output_format = kv['value']
                if 'TIMESTAMP_TZ_OUTPUT_FORMAT' in kv['name']:
                    self._timestamp_tz_output_format = kv['value']
                if 'DATE_OUTPUT_FORMAT' in kv['name']:
                    self._date_output_format = kv['value']
                if 'TIME_OUTPUT_FORMAT' in kv['name']:
                    self._time_output_format = kv['value']
                if 'TIMEZONE' in kv['name']:
                    self._timezone = kv['value']
                if 'BINARY_OUTPUT_FORMAT' in kv['name']:
                    self._binary_output_format = kv['value']
            self._connection._set_parameters(
                ret, self._connection._session_parameters)

        self._sequence_counter = -1
        return ret

    def execute(self,
                command: str,
                params: Union[List, Tuple, None] = None,
                timeout: Optional[int] = None,
                exec_async: bool = False,
                _do_reset: bool = True,
                _put_callback: 'SnowflakeProgressPercentage' = None,
                _put_azure_callback: 'SnowflakeProgressPercentage' = None,
                _put_callback_output_stream: IO[str] = sys.stdout,
                _get_callback: 'SnowflakeProgressPercentage' = None,
                _get_azure_callback: 'SnowflakeProgressPercentage' = None,
                _get_callback_output_stream: IO[str] = sys.stdout,
                _show_progress_bar: bool = True,
                _statement_params: Optional[Dict[str, str]] = None,
                _is_internal: bool = False,
                _no_results: bool = False,
                _use_ijson: bool = False,
                _is_put_get: Optional[bool] = None,
                _raise_put_get_error: bool = True,
                _force_put_overwrite: bool = False):
        """Executes a command/query.

        Args:
            command: The SQL command to be executed.
            params: Parameters to be bound into the SQL statement.
            timeout: Number of seconds after which to abort the query.
            exec_async: Whether to execute this query asynchronously.
            _do_reset: Whether or not the result set needs to be reset before executing query.
            _put_callback: Function to which GET command should call back to.
            _put_azure_callback: Function to which an Azure GET command should call back to.
            _put_callback_output_stream: The output stream a PUT command's callback should report on.
            _get_callback: Function to which GET command should call back to.
            _get_azure_callback: Function to which an Azure GET command should call back to.
            _get_callback_output_stream: The output stream a GET command's callback should report on.
            _show_progress_bar: Whether or not to show progress bar.
            _statement_params: Extra information that should be sent to Snowflake with query.
            _no_results: This flag tells the back-end to not return the result, just fire the query and return the
                query id of the running query.
            _use_ijson: This flag doesn't do anything as ijson support has ended.
            _is_put_get: Force decision of this SQL query being a PUT, or GET command. This is detected otherwise.
            _raise_put_get_error: Whether to raise PUT and GET errors.
            _force_put_overwrite: If the SQL query is a PUT, then this flag can force overwriting of an already
                existing file on stage.

        Returns:
            A result class with the results in it. This can either be json, or an arrow result class.
        """
        logger.debug('executing SQL/command')
        if self.is_closed():
            Error.errorhandler_wrapper(
                self.connection, self,
                DatabaseError,
                {'msg': "Cursor is closed in execute.",
                 'errno': ER_CURSOR_IS_CLOSED})

        if _do_reset:
            self.reset()
        command = command.strip(' \t\n\r') if command else None
        if not command:
            logger.warning('execute: no query is given to execute')
            return

        try:
            if self._connection.is_pyformat:
                # pyformat/format paramstyle
                # client side binding
                processed_params = self._connection._process_params(params, self)
                if logger.getEffectiveLevel() <= logging.DEBUG:
                    logger.debug('binding: [%s] with input=[%s], processed=[%s]',
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
                # TODO we could probably rework this to not make dicts like this: {'1': 'value', '2': '13'}
                processed_params = self._connection._process_params_qmarks(params, self)
        # Skip reporting Key, Value and Type errors
        except (KeyError, ValueError, TypeError):
            raise
        except Exception:
            self.connection.incident.report_incident()
            raise

        m = DESC_TABLE_RE.match(query)
        if m:
            query1 = 'describe table {}'.format(m.group(1))
            if logger.getEffectiveLevel() <= logging.WARNING:
                logger.info(
                    'query was rewritten: org=%s, new=%s',
                    ' '.join(line.strip() for line in query.split('\n')),
                    query1
                )
            query = query1

        if logger.getEffectiveLevel() <= logging.INFO:
            logger.info(
                'query: [%s]', self._format_query_for_log(query))
        ret = self._execute_helper(
            query,
            timeout=timeout,
            binding_params=processed_params,
            statement_params=_statement_params,
            is_internal=_is_internal,
            _no_results=_no_results,
            _is_put_get=_is_put_get)
        self._sfqid = ret['data']['queryId'] if 'data' in ret and 'queryId' in ret['data'] else None
        self._sqlstate = ret['data']['sqlState'] if 'data' in ret and 'sqlState' in ret['data'] else None
        self._first_chunk_time = get_time_millis()

        # if server gives a send time, log the time it took to arrive
        if 'data' in ret and 'sendResultTime' in ret['data']:
            time_consume_first_result = self._first_chunk_time - ret['data'][
                'sendResultTime']
            self._log_telemetry_job_data(
                TelemetryField.TIME_CONSUME_FIRST_RESULT,
                time_consume_first_result)
        logger.debug('sfqid: %s', self.sfqid)

        logger.info('query execution done')
        if ret['success']:
            logger.debug('SUCCESS')
            data = ret['data']

            # logger.debug(ret)
            logger.debug("PUT OR GET: %s", self.is_file_transfer)
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
                self._total_rowcount = len(data['rowset']) if \
                    'rowset' in data else -1
            m = self.ALTER_SESSION_RE.match(query)
            if m:
                # session parameters
                param = m.group(1).upper()
                value = m.group(2)
                self._connection.converter.set_parameter(param, value)

            if _no_results:
                self._total_rowcount = ret['data'][
                    'total'] if 'data' in ret and 'total' in ret[
                    'data'] else -1
                return data
            self._init_result_and_meta(data)
        else:
            self._total_rowcount = ret['data'][
                'total'] if 'data' in ret and 'total' in ret['data'] else -1
            logger.debug(ret)
            err = ret['message']
            code = ret.get('code', -1)
            if 'data' in ret:
                err += ret['data'].get('errorMessage', '')
            errvalue = {
                'msg': err,
                'errno': int(code),
                'sqlstate': self._sqlstate,
                'sfqid': self._sfqid
            }
            Error.errorhandler_wrapper(self.connection, self,
                                       ProgrammingError,
                                       errvalue)
        return self

    def _format_query_for_log(self, query):
        return self._connection._format_query_for_log(query)

    def _is_dml(self, data):
        return 'statementTypeId' in data \
               and int(data['statementTypeId']) in \
               STATEMENT_TYPE_ID_DML_SET

    def _init_result_and_meta(self, data):
        is_dml = self._is_dml(data)
        self._query_result_format = data.get('queryResultFormat', 'json')
        logger.debug("Query result format: %s", self._query_result_format)

        if self._total_rowcount == -1 and not is_dml and data.get('total') \
                is not None:
            self._total_rowcount = data['total']

        self._description = []

        for column in data['rowtype']:
            type_value = FIELD_NAME_TO_ID[column['type'].upper()]
            self._description.append((column['name'],
                                      type_value,
                                      None,
                                      column['length'],
                                      column['precision'],
                                      column['scale'],
                                      column['nullable']))

        if self._query_result_format == 'arrow':
            self.check_can_use_arrow_resultset()
            self._result = ArrowResult(data, self, use_dict_result=self._use_dict_result)
        else:
            self._result = self._json_result_class(data, self)

        if is_dml:
            updated_rows = 0
            for idx, desc in enumerate(self._description):
                if desc[0] in (
                        'number of rows updated',
                        'number of multi-joined rows updated',
                        'number of rows deleted') or \
                        desc[0].startswith('number of rows inserted'):
                    updated_rows += int(data['rowset'][0][idx])
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
                    'msg': msg,
                    'errno': errno,
                }
            )

    def check_can_use_pandas(self):
        global pyarrow

        if pyarrow is None:
            msg = ("Optional dependency: 'pyarrow' is not installed, please see the following link for install "
                   "instructions: https://docs.snowflake.com/en/user-guide/python-connector-pandas.html#installation")
            errno = ER_NO_PYARROW

            Error.errorhandler_wrapper(
                self.connection, self,
                ProgrammingError,
                {
                    'msg': msg,
                    'errno': errno,
                }
            )

    def query_result(self, qid):
        url = '/queries/{qid}/result'.format(qid=qid)
        ret = self._connection.rest.request(url=url, method='get')
        self._sfqid = ret['data'][
            'queryId'] if 'data' in ret and 'queryId' in ret[
            'data'] else None
        self._sqlstate = ret['data'][
            'sqlState'] if 'data' in ret and 'sqlState' in ret[
            'data'] else None
        logger.debug('sfqid=%s', self._sfqid)

        if ret.get('success'):
            data = ret.get('data')
            self._init_result_and_meta(data)
        else:
            logger.info('failed')
            logger.debug(ret)
            err = ret['message']
            code = ret.get('code', -1)
            if 'data' in ret:
                err += ret['data'].get('errorMessage', '')
            errvalue = {
                'msg': err,
                'errno': int(code),
                'sqlstate': self._sqlstate,
                'sfqid': self._sfqid
            }
            Error.errorhandler_wrapper(self.connection, self,
                                       ProgrammingError,
                                       errvalue)
        return self

    def fetch_pandas_batches(self, **kwargs):
        """Fetches a single Arrow Table."""
        self.check_can_use_pandas()
        if self._query_result_format != 'arrow':  # TODO: or pandas isn't imported
            raise NotSupportedError
        for df in self._result._fetch_pandas_batches(**kwargs):
            yield df

    def fetch_pandas_all(self, **kwargs):
        """Fetch Pandas dataframes in batches, where 'batch' refers to Snowflake Chunk."""
        self.check_can_use_pandas()
        if self._query_result_format != 'arrow':
            raise NotSupportedError
        return self._result._fetch_pandas_all(**kwargs)

    def abort_query(self, qid):
        url = '/queries/{qid}/abort-request'.format(qid=qid)
        ret = self._connection.rest.request(url=url, method='post')
        return ret.get('success')

    def executemany(self, command, seqparams):
        """Executes a command/query with the given set of parameters sequentially."""
        logger.debug('executing many SQLs/commands')
        command = command.strip(' \t\n\r') if command else None

        if len(seqparams) == 0:
            errorvalue = {
                'msg': "No parameters are specified for the command: "
                        "{}".format(command),
                'errno': ER_INVALID_VALUE,
            }
            Error.errorhandler_wrapper(
                self.connection, self, InterfaceError, errorvalue
            )
            return self

        if self.INSERT_SQL_RE.match(command):
            if self._connection.is_pyformat:
                logger.debug('rewriting INSERT query')
                command_wo_comments = re.sub(self.COMMENT_SQL_RE, '', command)
                m = self.INSERT_SQL_VALUES_RE.match(command_wo_comments)
                if not m:
                    errorvalue = {
                        'msg': "Failed to rewrite multi-row insert",
                        'errno': ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT
                    }
                    Error.errorhandler_wrapper(
                        self.connection, self, InterfaceError, errorvalue
                    )

                fmt = m.group(1)
                values = []
                for param in seqparams:
                    logger.debug('parameter: %s', param)
                    values.append(fmt % self._connection._process_params(
                        param, self))
                command = command.replace(fmt, ','.join(values), 1)
                self.execute(command)
                return self
            else:
                logger.debug('bulk insert')
                num_params = len(seqparams[0])
                pivot_param = []
                for _ in range(num_params):
                    pivot_param.append([])
                for row in seqparams:
                    if len(row) != num_params:
                        errorvalue = {
                            'msg':
                                "Bulk data size don't match. expected: {}, "
                                "got: {}, command: {}".format(
                                    num_params, len(row), command),
                            'errno': ER_INVALID_VALUE,
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
        """Fetches one row."""
        try:
            return next(self._result)
        except StopIteration:
            return None

    def fetchmany(self, size=None):
        """Fetches the number of specified rows."""
        if size is None:
            size = self.arraysize

        if size < 0:
            errorvalue = {
                'msg': ("The number of rows is not zero or "
                         "positive number: {}").format(size),
                'errno': ER_NOT_POSITIVE_SIZE}
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
        """Fetches all of the results."""
        ret = []
        while True:
            row = self.fetchone()
            if row is None:
                break
            ret.append(row)
        return ret

    def nextset(self):
        """Not supported."""
        logger.debug('nop')
        return None

    def setinputsizes(self, _):
        """Not supported."""
        logger.debug('nop')

    def setoutputsize(self, _, column=None):
        """Not supported."""
        del column
        logger.debug('nop')

    def scroll(self, value, mode='relative'):
        Error.errorhandler_wrapper(
            self.connection, self,
            NotSupportedError,
            {
                'msg': "scroll is not supported.",
                'errno': ER_UNSUPPORTED_METHOD,
                'sqlstate': SQLSTATE_FEATURE_NOT_SUPPORTED})

    def reset(self):
        """Resets the result set."""
        self._total_rowcount = -1  # reset the rowcount
        if self._result is not None:
            self._result._reset()

    def __iter__(self):
        """Iteration over the result set."""
        return iter(self._result)

    def __cancel_query(self, query):
        if self._sequence_counter >= 0 and not self.is_closed():
            logger.debug('canceled. %s, request_id: %s',
                         query, self._request_id)
            with self._lock_canceling:
                self._connection._cancel_query(query, self._request_id)

    def _log_telemetry_job_data(self, telemetry_field, value):
        """Builds an instance of TelemetryData with the given field and logs it."""
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
        """Context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager with commit or rollback."""
        self.close()


class DictCursor(SnowflakeCursor):
    """Cursor returning results in a dictionary."""

    def __init__(self, connection):
        SnowflakeCursor.__init__(self, connection, use_dict_result=True, json_result_class=DictJsonResult)
