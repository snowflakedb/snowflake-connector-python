#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import logging
import re
import signal
import sys
import time
import uuid
from enum import Enum
from logging import getLogger
from threading import Lock, Timer
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generator,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from snowflake.connector.result_batch import create_batches_from_response
from snowflake.connector.result_set import ResultSet

from .bind_upload_agent import BindUploadAgent, BindUploadError
from .compat import BASE_EXCEPTION_CLASS
from .constants import (
    FIELD_NAME_TO_ID,
    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT,
    FileTransferType,
    QueryStatus,
)
from .errorcode import (
    ER_CURSOR_IS_CLOSED,
    ER_FAILED_PROCESSING_PYFORMAT,
    ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT,
    ER_INVALID_VALUE,
    ER_NO_ARROW_RESULT,
    ER_NO_PYARROW,
    ER_NO_PYARROW_SNOWSQL,
    ER_NOT_POSITIVE_SIZE,
    ER_UNSUPPORTED_METHOD,
)
from .errors import (
    DatabaseError,
    Error,
    InterfaceError,
    NotSupportedError,
    ProgrammingError,
)
from .file_transfer_agent import SnowflakeFileTransferAgent
from .options import installed_pandas, pandas
from .sqlstate import SQLSTATE_FEATURE_NOT_SUPPORTED
from .telemetry import TelemetryData, TelemetryField
from .time_util import get_time_millis

if TYPE_CHECKING:  # pragma: no cover
    from .connection import SnowflakeConnection
    from .file_transfer_agent import SnowflakeProgressPercentage
    from .result_batch import ResultBatch


logger = getLogger(__name__)

if installed_pandas:
    from pyarrow import Table
else:
    logger.debug("Failed to import pyarrow. Cannot use pandas fetch API")
    Table = None

try:
    from .arrow_iterator import PyArrowIterator  # NOQA

    CAN_USE_ARROW_RESULT_FORMAT = True
except ImportError as e:  # pragma: no cover
    logger.debug(
        f"Failed to import ArrowResult. No Apache Arrow result set format can be used. ImportError: {e}",
    )
    CAN_USE_ARROW_RESULT_FORMAT = False

STATEMENT_TYPE_ID_DML = 0x3000
STATEMENT_TYPE_ID_INSERT = STATEMENT_TYPE_ID_DML + 0x100
STATEMENT_TYPE_ID_UPDATE = STATEMENT_TYPE_ID_DML + 0x200
STATEMENT_TYPE_ID_DELETE = STATEMENT_TYPE_ID_DML + 0x300
STATEMENT_TYPE_ID_MERGE = STATEMENT_TYPE_ID_DML + 0x400
STATEMENT_TYPE_ID_MULTI_TABLE_INSERT = STATEMENT_TYPE_ID_DML + 0x500

STATEMENT_TYPE_ID_DML_SET = frozenset(
    [
        STATEMENT_TYPE_ID_DML,
        STATEMENT_TYPE_ID_INSERT,
        STATEMENT_TYPE_ID_UPDATE,
        STATEMENT_TYPE_ID_DELETE,
        STATEMENT_TYPE_ID_MERGE,
        STATEMENT_TYPE_ID_MULTI_TABLE_INSERT,
    ]
)

DESC_TABLE_RE = re.compile(r"desc(?:ribe)?\s+([\w_]+)\s*;?\s*$", flags=re.IGNORECASE)

LOG_MAX_QUERY_LENGTH = 80

ASYNC_NO_DATA_MAX_RETRY = 24
ASYNC_RETRY_PATTERN = [1, 1, 2, 3, 4, 8, 10]
INCIDENT_BLACKLIST = (KeyError, ValueError, TypeError)


class ResultMetadata(NamedTuple):
    name: str
    type_code: int
    display_size: int
    internal_size: int
    precision: int
    scale: int
    is_nullable: bool

    @classmethod
    def from_column(cls, col: Dict[str, Any]):
        """Initializes a ResultMetadata object from the column description in the query response."""
        return cls(
            col["name"],
            FIELD_NAME_TO_ID[col["type"].upper()],
            None,
            col["length"],
            col["precision"],
            col["scale"],
            col["nullable"],
        )


# TODO: once we drop 3.6 support the return type becomes NoReturn
def exit_handler(*_) -> None:  # pragma: no cover
    """Handler for signal. When called, it will raise SystemExit with exit code FORCE_EXIT."""
    print("\nForce exit")
    logger.info("Force exit")
    sys.exit(1)


class ResultState(Enum):
    DEFAULT = 1
    VALID = 2
    RESET = 3


class SnowflakeCursor:
    """Implementation of Cursor object that is returned from Connection.cursor() method.

    Attributes:
        description: A list of namedtuples about metadata for all columns.
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

    PUT_SQL_RE = re.compile(r"^(?:/\*.*\*/\s*)*put\s+", flags=re.IGNORECASE)
    GET_SQL_RE = re.compile(r"^(?:/\*.*\*/\s*)*get\s+", flags=re.IGNORECASE)
    INSERT_SQL_RE = re.compile(r"^insert\s+into", flags=re.IGNORECASE)
    COMMENT_SQL_RE = re.compile(r"/\*.*\*/")
    INSERT_SQL_VALUES_RE = re.compile(
        r".*VALUES\s*(\(.*\)).*", re.IGNORECASE | re.MULTILINE | re.DOTALL
    )
    ALTER_SESSION_RE = re.compile(
        r"alter\s+session\s+set\s+(.*)=\'?([^\']+)\'?\s*;",
        flags=re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )

    @staticmethod
    def get_file_transfer_type(sql: str) -> Optional[FileTransferType]:
        """Decide whether a SQL is a file transfer and return its type.

        None is returned if the SQL isn't a file transfer so that this function can be
        used in an if-statement.
        """
        if SnowflakeCursor.PUT_SQL_RE.match(sql):
            return FileTransferType.PUT
        elif SnowflakeCursor.GET_SQL_RE.match(sql):
            return FileTransferType.GET
        return None

    def __init__(
        self,
        connection: "SnowflakeConnection",
        use_dict_result: bool = False,
    ) -> None:
        """Inits a SnowflakeCursor with a connection.

        Args:
            connection: The connection that created this cursor.
            use_dict_result: Decides whether to use dict result or not.
        """
        self._connection: "SnowflakeConnection" = connection

        self._errorhandler: Callable[
            ["SnowflakeConnection", "SnowflakeCursor", Type["Error"], Dict[str, str]],
            None,
        ] = Error.default_errorhandler
        self.messages: List[
            Tuple[Union[Type["Error"], Type[Exception]], Dict[str, Union[str, bool]]]
        ] = []
        self._timebomb: Optional[Timer] = None  # must be here for abort_exit method
        self._description: Optional[List[ResultMetadata]] = None
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
        self._result: Optional[Union[Iterator[Tuple], Iterator[Dict]]] = None
        self._result_set: Optional["ResultSet"] = None
        self._result_state: ResultState = ResultState.DEFAULT
        self._use_dict_result = use_dict_result
        # TODO: self._query_result_format could be defined as an enum
        self._query_result_format: Optional[str] = None

        self._arraysize = 1  # PEP-0249: defaults to 1

        self._lock_canceling = Lock()

        self._first_chunk_time = None

        self._log_max_query_length = connection.log_max_query_length
        self._inner_cursor: Optional["SnowflakeCursor"] = None
        self._prefetch_hook = None
        self._rownumber: Optional[int] = None

        self.reset()

    def __del__(self) -> None:  # pragma: no cover
        try:
            self.close()
        except BASE_EXCEPTION_CLASS as e:
            if logger.getEffectiveLevel() <= logging.INFO:
                logger.info(e)

    @property
    def description(self) -> List[ResultMetadata]:
        return self._description

    @property
    def rowcount(self):
        return self._total_rowcount if self._total_rowcount >= 0 else None

    @property
    def rownumber(self):
        return self._rownumber if self._rownumber >= 0 else None

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
        return (
            self._timestamp_ltz_output_format
            if self._timestamp_ltz_output_format
            else self._timestamp_output_format
        )

    @property
    def timestamp_tz_output_format(self):
        return (
            self._timestamp_tz_output_format
            if self._timestamp_tz_output_format
            else self._timestamp_output_format
        )

    @property
    def timestamp_ntz_output_format(self):
        return (
            self._timestamp_ntz_output_format
            if self._timestamp_ntz_output_format
            else self._timestamp_output_format
        )

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
        logger.debug("setting errorhandler: %s", value)
        if value is None:
            raise ProgrammingError("Invalid errorhandler is specified")
        self._errorhandler = value

    @property
    def is_file_transfer(self):
        """Whether the command is PUT or GET."""
        return hasattr(self, "_is_file_transfer") and self._is_file_transfer

    def callproc(self, procname, args=()):
        """Not supported."""
        Error.errorhandler_wrapper(
            self.connection,
            self,
            NotSupportedError,
            {
                "msg": "callproc is not supported.",
                "errno": ER_UNSUPPORTED_METHOD,
                "sqlstate": SQLSTATE_FEATURE_NOT_SUPPORTED,
            },
        )

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

    def _execute_helper(
        self,
        query: str,
        timeout: int = 0,
        statement_params: Optional[Dict[str, str]] = None,
        binding_params: Union[Tuple, Dict[str, Dict[str, str]]] = None,
        binding_stage: Optional[str] = None,
        is_internal: bool = False,
        describe_only: bool = False,
        _no_results: bool = False,
        _is_put_get=None,
    ):
        del self.messages[:]

        if statement_params is not None and not isinstance(statement_params, dict):
            Error.errorhandler_wrapper(
                self.connection,
                self,
                ProgrammingError,
                {
                    "msg": "The data type of statement params is invalid. It must be dict.",
                    "errno": ER_INVALID_VALUE,
                },
            )

        # check if current installation include arrow extension or not,
        # if not, we set statement level query result format to be JSON
        if not CAN_USE_ARROW_RESULT_FORMAT:
            logger.debug("Cannot use arrow result format, fallback to json format")
            if statement_params is None:
                statement_params = {
                    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: "JSON"
                }
            else:
                result_format_val = statement_params.get(
                    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT
                )
                if str(result_format_val).upper() == "ARROW":
                    self.check_can_use_arrow_resultset()
                elif result_format_val is None:
                    statement_params[
                        PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT
                    ] = "JSON"

        self._sequence_counter = self._connection._next_sequence_counter()
        self._request_id = uuid.uuid4()

        logger.debug(f"Request id: {self._request_id}")

        if logger.getEffectiveLevel() <= logging.DEBUG:
            logger.debug("running query [%s]", self._format_query_for_log(query))
        if _is_put_get is not None:
            # if told the query is PUT or GET, use the information
            self._is_file_transfer = _is_put_get
        else:
            # or detect it.
            self._is_file_transfer = self.PUT_SQL_RE.match(
                query
            ) or self.GET_SQL_RE.match(query)
        logger.debug("is_file_transfer: %s", self._is_file_transfer is not None)

        real_timeout = (
            timeout if timeout and timeout > 0 else self._connection.network_timeout
        )

        if real_timeout is not None:
            self._timebomb = Timer(real_timeout, self.__cancel_query, [query])
            self._timebomb.start()
            logger.debug("started timebomb in %ss", real_timeout)
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
                    logger.debug("cancelled timebomb in finally")
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
                "Failed to set SIGINT handler. " "Not in main thread. Ignored..."
            )
        ret = {"data": {}}
        try:
            ret = self._connection.cmd_query(
                query,
                self._sequence_counter,
                self._request_id,
                binding_params=binding_params,
                binding_stage=binding_stage,
                is_file_transfer=bool(self._is_file_transfer),
                statement_params=statement_params,
                is_internal=is_internal,
                describe_only=describe_only,
                _no_results=_no_results,
            )
        finally:
            try:
                if original_sigint:
                    signal.signal(signal.SIGINT, original_sigint)
            except (ValueError, TypeError):  # pragma: no cover
                logger.debug(
                    "Failed to reset SIGINT handler. Not in main " "thread. Ignored..."
                )
            except Exception:
                self.connection.incident.report_incident()
                raise
            if self._timebomb is not None:
                self._timebomb.cancel()
                logger.debug("cancelled timebomb in finally")

        if "data" in ret and "parameters" in ret["data"]:
            parameters = ret["data"]["parameters"]
            # Set session parameters for cursor object
            for kv in parameters:
                if "TIMESTAMP_OUTPUT_FORMAT" in kv["name"]:
                    self._timestamp_output_format = kv["value"]
                if "TIMESTAMP_NTZ_OUTPUT_FORMAT" in kv["name"]:
                    self._timestamp_ntz_output_format = kv["value"]
                if "TIMESTAMP_LTZ_OUTPUT_FORMAT" in kv["name"]:
                    self._timestamp_ltz_output_format = kv["value"]
                if "TIMESTAMP_TZ_OUTPUT_FORMAT" in kv["name"]:
                    self._timestamp_tz_output_format = kv["value"]
                if "DATE_OUTPUT_FORMAT" in kv["name"]:
                    self._date_output_format = kv["value"]
                if "TIME_OUTPUT_FORMAT" in kv["name"]:
                    self._time_output_format = kv["value"]
                if "TIMEZONE" in kv["name"]:
                    self._timezone = kv["value"]
                if "BINARY_OUTPUT_FORMAT" in kv["name"]:
                    self._binary_output_format = kv["value"]
            # Set session parameters for connection object
            self._connection._update_parameters(
                {p["name"]: p["value"] for p in parameters}
            )

        self._sequence_counter = -1
        return ret

    def execute(
        self,
        command: str,
        params: Optional[Union[Sequence[Any], Dict[Any, Any]]] = None,
        _bind_stage: Optional[str] = None,
        timeout: Optional[int] = None,
        _exec_async: bool = False,
        _do_reset: bool = True,
        _put_callback: "SnowflakeProgressPercentage" = None,
        _put_azure_callback: "SnowflakeProgressPercentage" = None,
        _put_callback_output_stream: IO[str] = sys.stdout,
        _get_callback: "SnowflakeProgressPercentage" = None,
        _get_azure_callback: "SnowflakeProgressPercentage" = None,
        _get_callback_output_stream: IO[str] = sys.stdout,
        _show_progress_bar: bool = True,
        _statement_params: Optional[Dict[str, str]] = None,
        _is_internal: bool = False,
        _describe_only: bool = False,
        _no_results: bool = False,
        _use_ijson: bool = False,
        _is_put_get: Optional[bool] = None,
        _raise_put_get_error: bool = True,
        _force_put_overwrite: bool = False,
        file_stream: Optional[IO[bytes]] = None,
    ) -> Optional[Union["SnowflakeCursor", None]]:
        """Executes a command/query.

        Args:
            command: The SQL command to be executed.
            params: Parameters to be bound into the SQL statement.
            _bind_stage: Path in temporary stage where binding parameters are uploaded as CSV files.
            timeout: Number of seconds after which to abort the query.
            _exec_async: Whether to execute this query asynchronously.
            _do_reset: Whether or not the result set needs to be reset before executing query.
            _put_callback: Function to which GET command should call back to.
            _put_azure_callback: Function to which an Azure GET command should call back to.
            _put_callback_output_stream: The output stream a PUT command's callback should report on.
            _get_callback: Function to which GET command should call back to.
            _get_azure_callback: Function to which an Azure GET command should call back to.
            _get_callback_output_stream: The output stream a GET command's callback should report on.
            _show_progress_bar: Whether or not to show progress bar.
            _statement_params: Extra information that should be sent to Snowflake with query.
            _is_internal: This flag indicates whether the query is issued internally by the connector.
            _describe_only: If true, the query will not be executed but return the schema/description of this query.
            _no_results: This flag tells the back-end to not return the result, just fire the query and return the
                response returned by Snowflake's server.
            _use_ijson: This flag doesn't do anything as ijson support has ended.
            _is_put_get: Force decision of this SQL query being a PUT, or GET command. This is detected otherwise.
            _raise_put_get_error: Whether to raise PUT and GET errors.
            _force_put_overwrite: If the SQL query is a PUT, then this flag can force overwriting of an already
                existing file on stage.
            file_stream: File-like object to be uploaded with PUT

        Returns:
            The cursor itself, or None if some error happened, or the response returned
            by Snowflake if the _no_results flag is on.
        """
        if _exec_async:
            _no_results = True
        logger.debug("executing SQL/command")
        if self.is_closed():
            Error.errorhandler_wrapper(
                self.connection,
                self,
                DatabaseError,
                {"msg": "Cursor is closed in execute.", "errno": ER_CURSOR_IS_CLOSED},
            )

        if _do_reset:
            self.reset()
        command = command.strip(" \t\n\r") if command else None
        if not command:
            logger.warning("execute: no query is given to execute")
            return

        kwargs = {
            "timeout": timeout,
            "statement_params": _statement_params,
            "is_internal": _is_internal,
            "describe_only": _describe_only,
            "_no_results": _no_results,
            "_is_put_get": _is_put_get,
        }

        try:
            if self._connection.is_pyformat:
                # pyformat/format paramstyle
                # client side binding
                processed_params = self._connection._process_params_pyformat(
                    params, self
                )
                if logger.getEffectiveLevel() <= logging.DEBUG:
                    logger.debug(
                        f"binding: [{self._format_query_for_log(command)}] "
                        f"with input=[{params}], "
                        f"processed=[{processed_params}]",
                    )
                if len(processed_params) > 0:
                    query = command % processed_params
                else:
                    query = command
            else:
                # qmark and numeric paramstyle
                query = command
                if _bind_stage:
                    kwargs["binding_stage"] = _bind_stage
                else:
                    if params is not None and not isinstance(params, (list, tuple)):
                        errorvalue = {
                            "msg": "Binding parameters must be a list: {}".format(
                                params
                            ),
                            "errno": ER_FAILED_PROCESSING_PYFORMAT,
                        }
                        Error.errorhandler_wrapper(
                            self.connection, self, ProgrammingError, errorvalue
                        )

                    kwargs["binding_params"] = self._connection._process_params_qmarks(
                        params, self
                    )
        # Skip reporting Key, Value and Type errors
        except Exception as exc:  # pragma: no cover
            if not isinstance(exc, INCIDENT_BLACKLIST):
                self.connection.incident.report_incident()
            raise

        m = DESC_TABLE_RE.match(query)
        if m:
            query1 = "describe table {}".format(m.group(1))
            if logger.getEffectiveLevel() <= logging.WARNING:
                logger.info(
                    "query was rewritten: org=%s, new=%s",
                    " ".join(line.strip() for line in query.split("\n")),
                    query1,
                )
            query = query1

        if logger.getEffectiveLevel() <= logging.INFO:
            logger.info("query: [%s]", self._format_query_for_log(query))
        ret = self._execute_helper(query, **kwargs)
        self._sfqid = (
            ret["data"]["queryId"]
            if "data" in ret and "queryId" in ret["data"]
            else None
        )
        self._sqlstate = (
            ret["data"]["sqlState"]
            if "data" in ret and "sqlState" in ret["data"]
            else None
        )
        self._first_chunk_time = get_time_millis()

        # if server gives a send time, log the time it took to arrive
        if "data" in ret and "sendResultTime" in ret["data"]:
            time_consume_first_result = (
                self._first_chunk_time - ret["data"]["sendResultTime"]
            )
            self._log_telemetry_job_data(
                TelemetryField.TIME_CONSUME_FIRST_RESULT, time_consume_first_result
            )
        logger.debug("sfqid: %s", self.sfqid)

        logger.info("query execution done")
        if ret["success"]:
            logger.debug("SUCCESS")
            data = ret["data"]

            logger.debug("PUT OR GET: %s", self.is_file_transfer)
            if self.is_file_transfer:
                # Decide whether to use the old, or new code path
                sf_file_transfer_agent = SnowflakeFileTransferAgent(
                    self,
                    query,
                    ret,
                    put_callback=_put_callback,
                    put_azure_callback=_put_azure_callback,
                    put_callback_output_stream=_put_callback_output_stream,
                    get_callback=_get_callback,
                    get_azure_callback=_get_azure_callback,
                    get_callback_output_stream=_get_callback_output_stream,
                    show_progress_bar=_show_progress_bar,
                    raise_put_get_error=_raise_put_get_error,
                    force_put_overwrite=_force_put_overwrite
                    or data.get("overwrite", False),
                    source_from_stream=file_stream,
                    multipart_threshold=data.get("threshold"),
                    use_s3_regional_url=self._connection.enable_stage_s3_privatelink_for_us_east_1,
                )
                sf_file_transfer_agent.execute()
                data = sf_file_transfer_agent.result()
                self._total_rowcount = len(data["rowset"]) if "rowset" in data else -1
            m = self.ALTER_SESSION_RE.match(query)
            if m:
                # session parameters
                param = m.group(1).upper()
                value = m.group(2)
                self._connection.converter.set_parameter(param, value)

            if _exec_async:
                self.connection._async_sfqids.add(self._sfqid)
            if _no_results:
                self._total_rowcount = (
                    ret["data"]["total"]
                    if "data" in ret and "total" in ret["data"]
                    else -1
                )
                return data
            self._init_result_and_meta(data)
        else:
            self._total_rowcount = (
                ret["data"]["total"] if "data" in ret and "total" in ret["data"] else -1
            )
            logger.debug(ret)
            err = ret["message"]
            code = ret.get("code", -1)
            if "data" in ret:
                err += ret["data"].get("errorMessage", "")
            errvalue = {
                "msg": err,
                "errno": int(code),
                "sqlstate": self._sqlstate,
                "sfqid": self._sfqid,
            }
            Error.errorhandler_wrapper(
                self.connection, self, ProgrammingError, errvalue
            )
        return self

    def execute_async(self, *args, **kwargs):
        """Convenience function to execute a query without waiting for results (asynchronously).

        This function takes the same arguments as execute, please refer to that function
        for documentation.
        """
        kwargs["_exec_async"] = True
        return self.execute(*args, **kwargs)

    def describe(self, *args, **kwargs) -> List[ResultMetadata]:
        """Obtain the schema of the result without executing the query.

        This function takes the same arguments as execute, please refer to that function
        for documentation.

        Returns:
            The schema of the result.
        """
        kwargs["_describe_only"] = kwargs["_is_internal"] = True
        self.execute(*args, **kwargs)
        return self._description

    def _format_query_for_log(self, query):
        return self._connection._format_query_for_log(query)

    def _is_dml(self, data):
        return (
            "statementTypeId" in data
            and int(data["statementTypeId"]) in STATEMENT_TYPE_ID_DML_SET
        )

    def _init_result_and_meta(self, data):
        is_dml = self._is_dml(data)
        self._query_result_format = data.get("queryResultFormat", "json")
        logger.debug("Query result format: %s", self._query_result_format)

        if self._total_rowcount == -1 and not is_dml and data.get("total") is not None:
            self._total_rowcount = data["total"]

        self._description: List[ResultMetadata] = [
            ResultMetadata.from_column(col) for col in data["rowtype"]
        ]

        result_chunks = create_batches_from_response(
            self, self._query_result_format, data, self._description
        )

        self._result_set = ResultSet(
            self,
            result_chunks,
            self._connection.client_prefetch_threads,
        )
        self._rownumber = -1
        self._result_state = ResultState.VALID

        # don't update the row count when the result is returned from `describe` method
        if is_dml and "rowset" in data and len(data["rowset"]) > 0:
            updated_rows = 0
            for idx, desc in enumerate(self._description):
                if (
                    desc[0]
                    in (
                        "number of rows updated",
                        "number of multi-joined rows updated",
                        "number of rows deleted",
                    )
                    or desc[0].startswith("number of rows inserted")
                ):
                    updated_rows += int(data["rowset"][0][idx])
            if self._total_rowcount == -1:
                self._total_rowcount = updated_rows
            else:
                self._total_rowcount += updated_rows

    def check_can_use_arrow_resultset(self):
        global CAN_USE_ARROW_RESULT_FORMAT

        if not CAN_USE_ARROW_RESULT_FORMAT:
            if self._connection.application == "SnowSQL":
                msg = "Currently SnowSQL doesn't support the result set in Apache Arrow format."
                errno = ER_NO_PYARROW_SNOWSQL
            else:
                msg = "The result set in Apache Arrow format is not supported for the platform."
                errno = ER_NO_ARROW_RESULT

            Error.errorhandler_wrapper(
                self.connection,
                self,
                ProgrammingError,
                {
                    "msg": msg,
                    "errno": errno,
                },
            )

    def check_can_use_pandas(self):
        if not installed_pandas:
            msg = (
                "Optional dependency: 'pyarrow' is not installed, please see the following link for install "
                "instructions: https://docs.snowflake.com/en/user-guide/python-connector-pandas.html#installation"
            )
            errno = ER_NO_PYARROW

            Error.errorhandler_wrapper(
                self.connection,
                self,
                ProgrammingError,
                {
                    "msg": msg,
                    "errno": errno,
                },
            )

    def query_result(self, qid):
        url = "/queries/{qid}/result".format(qid=qid)
        ret = self._connection.rest.request(url=url, method="get")
        self._sfqid = (
            ret["data"]["queryId"]
            if "data" in ret and "queryId" in ret["data"]
            else None
        )
        self._sqlstate = (
            ret["data"]["sqlState"]
            if "data" in ret and "sqlState" in ret["data"]
            else None
        )
        logger.debug("sfqid=%s", self._sfqid)

        if ret.get("success"):
            data = ret.get("data")
            self._init_result_and_meta(data)
        else:
            logger.info("failed")
            logger.debug(ret)
            err = ret["message"]
            code = ret.get("code", -1)
            if "data" in ret:
                err += ret["data"].get("errorMessage", "")
            errvalue = {
                "msg": err,
                "errno": int(code),
                "sqlstate": self._sqlstate,
                "sfqid": self._sfqid,
            }
            Error.errorhandler_wrapper(
                self.connection, self, ProgrammingError, errvalue
            )
        return self

    def fetch_arrow_batches(self) -> Iterator[Table]:
        self.check_can_use_arrow_resultset()
        if self._query_result_format != "arrow":
            raise NotSupportedError
        self._log_telemetry_job_data(
            TelemetryField.ARROW_FETCH_BATCHES, TelemetryData.TRUE
        )
        return self._result_set._fetch_arrow_batches()

    def fetch_arrow_all(self) -> Optional[Table]:
        self.check_can_use_arrow_resultset()
        if self._query_result_format != "arrow":
            raise NotSupportedError
        self._log_telemetry_job_data(TelemetryField.ARROW_FETCH_ALL, TelemetryData.TRUE)
        return self._result_set._fetch_arrow_all()

    def fetch_pandas_batches(self, **kwargs) -> Iterator["pandas.DataFrame"]:
        """Fetches a single Arrow Table."""
        self.check_can_use_pandas()
        if self._prefetch_hook is not None:
            self._prefetch_hook()
            raise NotSupportedError
        self._log_telemetry_job_data(
            TelemetryField.PANDAS_FETCH_BATCHES, TelemetryData.TRUE
        )
        return self._result_set._fetch_pandas_batches(**kwargs)

    def fetch_pandas_all(self, **kwargs) -> "pandas.DataFrame":
        """Fetch Pandas dataframes in batches, where 'batch' refers to Snowflake Chunk."""
        self.check_can_use_pandas()
        if self._prefetch_hook is not None:
            self._prefetch_hook()
        if self._query_result_format != "arrow":
            raise NotSupportedError
        self._log_telemetry_job_data(
            TelemetryField.PANDAS_FETCH_ALL, TelemetryData.TRUE
        )
        return self._result_set._fetch_pandas_all(**kwargs)

    def abort_query(self, qid):
        url = "/queries/{qid}/abort-request".format(qid=qid)
        ret = self._connection.rest.request(url=url, method="post")
        return ret.get("success")

    def executemany(
        self,
        command: str,
        seqparams: Union[Sequence[Any], Dict[str, Any]],
    ) -> "SnowflakeCursor":
        """Executes a command/query with the given set of parameters sequentially."""
        logger.debug("executing many SQLs/commands")
        command = command.strip(" \t\n\r") if command else None

        if len(seqparams) == 0:
            Error.errorhandler_wrapper(
                self.connection,
                self,
                InterfaceError,
                {
                    "msg": f"No parameters are specified for the command: {command}",
                    "errno": ER_INVALID_VALUE,
                },
            )
            return self

        if self.INSERT_SQL_RE.match(command):
            if self._connection.is_pyformat:
                logger.debug("rewriting INSERT query")
                command_wo_comments = re.sub(self.COMMENT_SQL_RE, "", command)
                m = self.INSERT_SQL_VALUES_RE.match(command_wo_comments)
                if not m:
                    Error.errorhandler_wrapper(
                        self.connection,
                        self,
                        InterfaceError,
                        {
                            "msg": "Failed to rewrite multi-row insert",
                            "errno": ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT,
                        },
                    )

                fmt = m.group(1)
                values = []
                for param in seqparams:
                    logger.debug(f"parameter: {param}")
                    values.append(
                        fmt % self._connection._process_params_pyformat(param, self)
                    )
                command = command.replace(fmt, ",".join(values), 1)
                self.execute(command)
                return self
            else:
                logger.debug("bulk insert")
                # sanity check
                row_size = len(seqparams[0])
                for row in seqparams:
                    if len(row) != row_size:
                        error_value = {
                            "msg": f"Bulk data size don't match. expected: {row_size}, "
                            f"got: {len(row)}, command: {command}",
                            "errno": ER_INVALID_VALUE,
                        }
                        Error.errorhandler_wrapper(
                            self.connection, self, InterfaceError, error_value
                        )
                        return self
                bind_size = len(seqparams) * row_size
                bind_stage = None
                if (
                    bind_size
                    > self.connection._session_parameters[
                        "CLIENT_STAGE_ARRAY_BINDING_THRESHOLD"
                    ]
                    > 0
                ):
                    # bind stage optimization
                    try:
                        rows = self.connection._write_params_to_byte_rows(seqparams)
                        bind_uploader = BindUploadAgent(self, rows)
                        bind_uploader.upload()
                        bind_stage = bind_uploader.stage_path
                    except BindUploadError:
                        logger.debug(
                            "Failed to upload binds to stage, sending binds to "
                            "Snowflake instead."
                        )
                    except Exception as exc:
                        if not isinstance(exc, INCIDENT_BLACKLIST):
                            self.connection.incident.report_incident()
                        raise
                binding_param = (
                    None if bind_stage else list(map(list, zip(*seqparams)))
                )  # transpose
                self.execute(command, params=binding_param, _bind_stage=bind_stage)
                return self

        self.reset()
        for param in seqparams:
            self.execute(command, param, _do_reset=False)
        return self

    def _result_iterator(
        self,
    ) -> Union[Generator[Dict, None, None], Generator[Tuple, None, None]]:
        """Yields the elements from _result and raises an exception when appropriate."""
        try:
            for _next in self._result:
                if isinstance(_next, Exception):
                    Error.errorhandler_wrapper_from_ready_exception(
                        self._connection,
                        self,
                        _next,
                    )
                self._rownumber += 1
                yield _next
        except TypeError as err:
            if self._result_state == ResultState.DEFAULT:
                raise err
            else:
                yield None

    def fetchone(self) -> Optional[Union[Dict, Tuple]]:
        """Fetches one row."""
        if self._prefetch_hook is not None:
            self._prefetch_hook()
        if self._result is None and self._result_set is not None:
            self._result = iter(self._result_set)
            self._result_state = ResultState.VALID
        try:
            return next(self._result_iterator())
        except StopIteration:
            return None

    def fetchmany(self, size=None):
        """Fetches the number of specified rows."""
        if size is None:
            size = self.arraysize

        if size < 0:
            errorvalue = {
                "msg": (
                    "The number of rows is not zero or " "positive number: {}"
                ).format(size),
                "errno": ER_NOT_POSITIVE_SIZE,
            }
            Error.errorhandler_wrapper(
                self.connection, self, ProgrammingError, errorvalue
            )
        ret = []
        while size > 0:
            row = self.fetchone()
            if row is None:
                break
            ret.append(row)
            if size is not None:
                size -= 1

        return ret

    def fetchall(self) -> Union[List[Tuple], List[Dict]]:
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
        logger.debug("nop")
        return None

    def setinputsizes(self, _):
        """Not supported."""
        logger.debug("nop")

    def setoutputsize(self, _, column=None):
        """Not supported."""
        del column
        logger.debug("nop")

    def scroll(self, value, mode="relative"):
        Error.errorhandler_wrapper(
            self.connection,
            self,
            NotSupportedError,
            {
                "msg": "scroll is not supported.",
                "errno": ER_UNSUPPORTED_METHOD,
                "sqlstate": SQLSTATE_FEATURE_NOT_SUPPORTED,
            },
        )

    def reset(self):
        """Resets the result set."""
        self._total_rowcount = -1  # reset the rowcount
        if self._result_state != ResultState.DEFAULT:
            self._result_state = ResultState.RESET
        if self._result is not None:
            self._result = None
        if self._inner_cursor is not None:
            self._inner_cursor.reset()
            self._result = None
            self._inner_cursor = None
        self._prefetch_hook = None
        if not self.connection._reuse_results:
            self._result_set = None

    def __iter__(self) -> Union[Iterator[Dict], Iterator[Tuple]]:
        """Iteration over the result set."""
        # set _result if _result_set is not None
        if self._result is None and self._result_set is not None:
            self._result = iter(self._result_set)
            self._result_state = ResultState.VALID
        return self._result_iterator()

    def __cancel_query(self, query):
        if self._sequence_counter >= 0 and not self.is_closed():
            logger.debug("canceled. %s, request_id: %s", query, self._request_id)
            with self._lock_canceling:
                self._connection._cancel_query(query, self._request_id)

    def _log_telemetry_job_data(self, telemetry_field, value):
        """Builds an instance of TelemetryData with the given field and logs it."""
        obj = {
            "type": telemetry_field,
            "query_id": self._sfqid,
            "value": int(value),
        }
        ts = get_time_millis()
        try:
            self._connection._log_telemetry(TelemetryData(obj, ts))
        except AttributeError:
            logger.warning(
                "Cursor failed to log to telemetry. Connection object may be None.",
                exc_info=True,
            )

    def __enter__(self):
        """Context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager with commit or rollback."""
        self.close()

    def get_results_from_sfqid(self, sfqid: str):
        """Gets the results from previously ran query."""

        def wait_until_ready():
            """Makes sure query has finished executing and once it has retrieves results."""
            no_data_counter = 0
            retry_pattern_pos = 0
            while True:
                status = self.connection.get_query_status(sfqid)
                if not self.connection.is_still_running(status):
                    break
                if status == QueryStatus.NO_DATA:  # pragma: no cover
                    no_data_counter += 1
                    if no_data_counter > ASYNC_NO_DATA_MAX_RETRY:
                        raise DatabaseError(
                            "Cannot retrieve data on the status of this query. No information returned "
                            "from server for query '{}'"
                        )
                time.sleep(
                    0.5 * ASYNC_RETRY_PATTERN[retry_pattern_pos]
                )  # Same wait as JDBC
                # If we can advance in ASYNC_RETRY_PATTERN then do so
                if retry_pattern_pos < (len(ASYNC_RETRY_PATTERN) - 1):
                    retry_pattern_pos += 1
            if status != QueryStatus.SUCCESS:
                raise DatabaseError(
                    "Status of query '{}' is {}, results are unavailable".format(
                        sfqid, status.name
                    )
                )
            self._inner_cursor.execute(
                "select * from table(result_scan('{}'))".format(sfqid)
            )
            self._result = self._inner_cursor._result
            self._query_result_format = self._inner_cursor._query_result_format
            self._total_rowcount = self._inner_cursor._total_rowcount
            self._description = self._inner_cursor._description
            self._result_set = self._inner_cursor._result_set
            self._result_state = ResultState.VALID
            self._rownumber = 0
            # Unset this function, so that we don't block anymore
            self._prefetch_hook = None

        self.connection.get_query_status_throw_if_error(
            sfqid
        )  # Trigger an exception if query failed
        klass = self.__class__
        self._inner_cursor = klass(self.connection)
        self._sfqid = sfqid
        self._prefetch_hook = wait_until_ready

    def get_result_batches(self) -> Optional[List["ResultBatch"]]:
        """Get the previously executed query's ``ResultBatch`` s if available.

        If they are unavailable, in case nothing has been executed yet None will
        be returned.

        For a detailed description of ``ResultBatch`` s please see the docstring of:
        ``snowflake.connector.result_batches.ResultBatch``
        """
        if self._result_set is None:
            return None
        self._log_telemetry_job_data(
            TelemetryField.GET_PARTITIONS_USED, TelemetryData.TRUE
        )
        return self._result_set.batches


class DictCursor(SnowflakeCursor):
    """Cursor returning results in a dictionary."""

    def __init__(self, connection):
        super().__init__(
            connection,
            use_dict_result=True,
        )
