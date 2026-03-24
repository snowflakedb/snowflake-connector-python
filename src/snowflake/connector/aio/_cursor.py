from __future__ import annotations

import abc
import asyncio
import collections
import logging
import re
import signal
import sys
import typing
import uuid
from logging import getLogger
from types import TracebackType
from typing import IO, TYPE_CHECKING, Any, AsyncIterator, Literal, Sequence, overload

from typing_extensions import Self

import snowflake.connector.cursor
from snowflake.connector import (
    Error,
    IntegrityError,
    InterfaceError,
    NotSupportedError,
    ProgrammingError,
)
from snowflake.connector._sql_util import get_file_transfer_type
from snowflake.connector.aio._bind_upload_agent import BindUploadAgent
from snowflake.connector.aio._result_batch import (
    ResultBatch,
    create_batches_from_response,
)
from snowflake.connector.aio._result_set import ResultSet, ResultSetIterator
from snowflake.connector.constants import (
    CMD_TYPE_DOWNLOAD,
    CMD_TYPE_UPLOAD,
    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT,
    QueryStatus,
)
from snowflake.connector.cursor import (
    ASYNC_NO_DATA_MAX_RETRY,
    ASYNC_RETRY_PATTERN,
    DESC_TABLE_RE,
    ResultMetadata,
    ResultMetadataV2,
    ResultState,
)
from snowflake.connector.cursor import SnowflakeCursorBase as SnowflakeCursorBaseSync
from snowflake.connector.cursor import T
from snowflake.connector.errorcode import (
    ER_CURSOR_IS_CLOSED,
    ER_FAILED_PROCESSING_PYFORMAT,
    ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT,
    ER_INVALID_VALUE,
    ER_NOT_POSITIVE_SIZE,
)
from snowflake.connector.errors import BindUploadError, DatabaseError
from snowflake.connector.file_transfer_agent import SnowflakeProgressPercentage
from snowflake.connector.telemetry import TelemetryData, TelemetryField
from snowflake.connector.time_util import get_time_millis

from .._utils import REQUEST_ID_STATEMENT_PARAM_NAME, is_uuid4

if TYPE_CHECKING:
    from pandas import DataFrame
    from pyarrow import Table

    from snowflake.connector.aio import SnowflakeConnection

logger = getLogger(__name__)

FetchRow = typing.TypeVar(
    "FetchRow", bound=typing.Union[typing.Tuple[Any, ...], typing.Dict[str, Any]]
)


class SnowflakeCursorBase(SnowflakeCursorBaseSync, abc.ABC, typing.Generic[FetchRow]):
    def __init__(
        self,
        connection: SnowflakeConnection,
    ):
        super().__init__(connection)
        # the following fixes type hint
        self._connection = typing.cast("SnowflakeConnection", self._connection)
        self._inner_cursor: SnowflakeCursorBase | None = None
        self._lock_canceling = asyncio.Lock()
        self._timebomb: asyncio.Task | None = None
        self._prefetch_hook: typing.Callable[[], typing.Awaitable] | None = None

    def __aiter__(self):
        return self

    def __iter__(self):
        raise TypeError(
            "'snowflake.connector.aio.SnowflakeCursor' only supports async iteration."
        )

    async def __anext__(self):
        while True:
            _next = await self.fetchone()
            if _next is None:
                raise StopAsyncIteration
            return _next

    async def __aenter__(self):
        return self

    def __enter__(self):
        # async cursor does not support sync context manager
        raise TypeError(
            "'SnowflakeCursor' object does not support the context manager protocol"
        )

    def __exit__(self, exc_type, exc_val, exc_tb):
        # async cursor does not support sync context manager
        raise TypeError(
            "'SnowflakeCursor' object does not support the context manager protocol"
        )

    def __del__(self):
        # do nothing in async, __del__ is unreliable
        pass

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager with commit or rollback."""
        await self.close()

    async def _timebomb_task(self, timeout, query):
        try:
            logger.debug("started timebomb in %ss", timeout)
            await asyncio.sleep(timeout)
            await self.__cancel_query(query)
            return True
        except asyncio.CancelledError:
            logger.debug("cancelled timebomb in timebomb task")
            return False

    async def __cancel_query(self, query) -> None:
        if self._sequence_counter >= 0 and not self.is_closed():
            logger.debug("canceled. %s, request_id: %s", query, self._request_id)
            async with self._lock_canceling:
                await self._connection._cancel_query(query, self._request_id)

    async def _describe_internal(
        self, *args: Any, **kwargs: Any
    ) -> list[ResultMetadataV2]:
        """Obtain the schema of the result without executing the query.

        This function takes the same arguments as execute, please refer to that function
        for documentation.

        This function is for internal use only

        Returns:
            The schema of the result, in the new result metadata format.
        """
        kwargs["_describe_only"] = kwargs["_is_internal"] = True
        await self.execute(*args, **kwargs)
        return self._description

    async def _execute_helper(
        self,
        query: str,
        timeout: int = 0,
        statement_params: dict[str, str] | None = None,
        binding_params: tuple | dict[str, dict[str, str]] = None,
        binding_stage: str | None = None,
        is_internal: bool = False,
        describe_only: bool = False,
        _no_results: bool = False,
        _is_put_get=None,
        _no_retry: bool = False,
        dataframe_ast: str | None = None,
    ) -> dict[str, Any]:
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
        if not snowflake.connector.cursor.CAN_USE_ARROW_RESULT_FORMAT:
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
                    statement_params[PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT] = (
                        "JSON"
                    )

        self._sequence_counter = await self._connection._next_sequence_counter()

        # If requestId is contained in statement parameters, use it to set request id. Verify here it is a valid uuid4
        # identifier.
        if (
            statement_params is not None
            and REQUEST_ID_STATEMENT_PARAM_NAME in statement_params
        ):
            request_id = statement_params[REQUEST_ID_STATEMENT_PARAM_NAME]

            if not is_uuid4(request_id):
                # uuid.UUID will throw an error if invalid, but we explicitly check and throw here.
                raise ValueError(f"requestId {request_id} is not a valid UUID4.")
            self._request_id = uuid.UUID(str(request_id), version=4)

            # Create a (deep copy) and remove the statement param, there is no need to encode it as extra parameter
            # one more time.
            statement_params = statement_params.copy()
            statement_params.pop(REQUEST_ID_STATEMENT_PARAM_NAME)
        else:
            # Generate UUID for query.
            self._request_id = uuid.uuid4()

        logger.debug(f"Request id: {self._request_id}")

        logger.debug("running query [%s]", self._format_query_for_log(query))
        if _is_put_get is not None:
            # if told the query is PUT or GET, use the information
            self._is_file_transfer = _is_put_get
        else:
            # or detect it.
            self._is_file_transfer = get_file_transfer_type(query) is not None
        logger.debug(
            "is_file_transfer: %s",
            self._is_file_transfer if self._is_file_transfer is not None else "None",
        )

        real_timeout = (
            timeout if timeout and timeout > 0 else self._connection.network_timeout
        )

        if real_timeout is not None:
            self._timebomb = asyncio.create_task(
                self._timebomb_task(real_timeout, query)
            )
            logger.debug("started timebomb in %ss", real_timeout)
        else:
            self._timebomb = None

        original_sigint = signal.getsignal(signal.SIGINT)

        def interrupt_handler(*_):  # pragma: no cover
            try:
                signal.signal(signal.SIGINT, snowflake.connector.cursor.exit_handler)
            except (ValueError, TypeError):
                # ignore failures
                pass
            try:
                if self._timebomb is not None:
                    self._timebomb.cancel()
                    self._timebomb = None
                    logger.debug("cancelled timebomb in finally")
                asyncio.create_task(self.__cancel_query(query))
            finally:
                if original_sigint:
                    try:
                        signal.signal(signal.SIGINT, original_sigint)
                    except (ValueError, TypeError):
                        # ignore failures
                        pass
            raise KeyboardInterrupt

        try:
            if not original_sigint == snowflake.connector.cursor.exit_handler:
                signal.signal(signal.SIGINT, interrupt_handler)
        except ValueError:  # pragma: no cover
            logger.debug(
                "Failed to set SIGINT handler. " "Not in main thread. Ignored..."
            )
        ret: dict[str, Any] = {"data": {}}
        try:
            ret = await self._connection.cmd_query(
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
                _no_retry=_no_retry,
                timeout=real_timeout,
                dataframe_ast=dataframe_ast,
            )
        finally:
            try:
                if original_sigint:
                    signal.signal(signal.SIGINT, original_sigint)
            except (ValueError, TypeError):  # pragma: no cover
                logger.debug(
                    "Failed to reset SIGINT handler. Not in main " "thread. Ignored..."
                )
            if self._timebomb is not None:
                self._timebomb.cancel()
                try:
                    await self._timebomb
                except asyncio.CancelledError:
                    pass
                logger.debug("cancelled timebomb in finally")

        if "data" in ret and "parameters" in ret["data"]:
            parameters = ret["data"].get("parameters", list())
            # Set session parameters for cursor object
            for kv in parameters:
                if "TIMESTAMP_OUTPUT_FORMAT" in kv["name"]:
                    self._timestamp_output_format = kv["value"]
                elif "TIMESTAMP_NTZ_OUTPUT_FORMAT" in kv["name"]:
                    self._timestamp_ntz_output_format = kv["value"]
                elif "TIMESTAMP_LTZ_OUTPUT_FORMAT" in kv["name"]:
                    self._timestamp_ltz_output_format = kv["value"]
                elif "TIMESTAMP_TZ_OUTPUT_FORMAT" in kv["name"]:
                    self._timestamp_tz_output_format = kv["value"]
                elif "DATE_OUTPUT_FORMAT" in kv["name"]:
                    self._date_output_format = kv["value"]
                elif "TIME_OUTPUT_FORMAT" in kv["name"]:
                    self._time_output_format = kv["value"]
                elif "TIMEZONE" in kv["name"]:
                    self._timezone = kv["value"]
                elif "BINARY_OUTPUT_FORMAT" in kv["name"]:
                    self._binary_output_format = kv["value"]
            # Set session parameters for connection object
            await self._connection._update_parameters(
                {p["name"]: p["value"] for p in parameters}
            )

        self.query = query
        self._sequence_counter = -1
        return ret

    async def _init_result_and_meta(self, data: dict[Any, Any]) -> None:
        is_dml = self._is_dml(data)
        self._query_result_format = data.get("queryResultFormat", "json")
        logger.debug("Query result format: %s", self._query_result_format)

        if self._total_rowcount == -1 and not is_dml and data.get("total") is not None:
            self._total_rowcount = data["total"]

        self._description: list[ResultMetadataV2] = [
            ResultMetadataV2.from_column(col) for col in data["rowtype"]
        ]

        result_chunks = create_batches_from_response(
            self, self._query_result_format, data, self._description
        )

        if not (is_dml or self.is_file_transfer):
            logger.debug(
                "Number of results in first chunk: %s", result_chunks[0].rowcount
            )

        self._result_set = ResultSet(
            self,
            result_chunks,
            self._connection.client_prefetch_threads,
        )
        self._rownumber = -1
        self._result_state = ResultState.VALID

        # Extract stats object if available (for DML operations like CTAS, INSERT, UPDATE, DELETE)
        self._stats_data = data.get("stats", None)
        logger.debug("Execution DML stats: %s", self.stats)

        # don't update the row count when the result is returned from `describe` method
        if is_dml and "rowset" in data and len(data["rowset"]) > 0:
            updated_rows = 0
            for idx, desc in enumerate(self._description):
                if desc.name in (
                    "number of rows updated",
                    "number of multi-joined rows updated",
                    "number of rows deleted",
                ) or desc.name.startswith("number of rows inserted"):
                    updated_rows += int(data["rowset"][0][idx])
            if self._total_rowcount == -1:
                self._total_rowcount = updated_rows
            else:
                self._total_rowcount += updated_rows

    async def _init_multi_statement_results(self, data: dict) -> None:
        await self._log_telemetry_job_data(
            TelemetryField.MULTI_STATEMENT, TelemetryData.TRUE
        )
        self.multi_statement_savedIds = data["resultIds"].split(",")
        self._multi_statement_resultIds = collections.deque(
            self.multi_statement_savedIds
        )
        if self._is_file_transfer:
            Error.errorhandler_wrapper(
                self.connection,
                self,
                ProgrammingError,
                {
                    "msg": "PUT/GET commands are not supported for multi-statement queries and cannot be executed.",
                    "errno": ER_INVALID_VALUE,
                },
            )
        await self.nextset()

    async def _log_telemetry_job_data(
        self, telemetry_field: TelemetryField, value: Any
    ) -> None:
        ts = get_time_millis()
        try:
            await self._connection._log_telemetry(
                TelemetryData.from_telemetry_data_dict(
                    from_dict={
                        TelemetryField.KEY_TYPE.value: telemetry_field.value,
                        TelemetryField.KEY_SFQID.value: self._sfqid,
                        TelemetryField.KEY_VALUE.value: value,
                    },
                    timestamp=ts,
                    connection=self._connection,
                )
            )
        except AttributeError:
            logger.warning(
                "Cursor failed to log to telemetry. Connection object may be None.",
                exc_info=True,
            )

    async def _preprocess_pyformat_query(
        self,
        command: str,
        params: Sequence[Any] | dict[Any, Any] | None = None,
    ) -> str:
        # pyformat/format paramstyle
        # client side binding
        processed_params = self._connection._process_params_pyformat(params, self)
        # SNOW-513061 collect telemetry for empty sequence usage before we make the breaking change announcement
        if params is not None and len(params) == 0:
            await self._log_telemetry_job_data(
                TelemetryField.EMPTY_SEQ_INTERPOLATION,
                (
                    TelemetryData.TRUE
                    if self.connection._interpolate_empty_sequences
                    else TelemetryData.FALSE
                ),
            )
        if logger.getEffectiveLevel() <= logging.DEBUG:
            logger.debug(
                f"binding: [{self._format_query_for_log(command)}] "
                f"with input=[{params}], "
                f"processed=[{processed_params}]",
            )
        if (
            self.connection._interpolate_empty_sequences
            and processed_params is not None
        ) or (
            not self.connection._interpolate_empty_sequences
            and len(processed_params) > 0
        ):
            query = command % processed_params
        else:
            query = command
        return query

    async def abort_query(self, qid: str) -> bool:
        url = f"/queries/{qid}/abort-request"
        ret = await self._connection.rest.request(url=url, method="post")
        return ret.get("success")

    @overload
    async def callproc(self, procname: str) -> tuple: ...

    @overload
    async def callproc(self, procname: str, args: T) -> T: ...

    async def callproc(self, procname: str, args=tuple()):
        """Call a stored procedure.

        Args:
            procname: The stored procedure to be called.
            args: Parameters to be passed into the stored procedure.

        Returns:
            The input parameters.
        """
        marker_format = "%s" if self._connection.is_pyformat else "?"
        command = (
            f"CALL {procname}({', '.join([marker_format for _ in range(len(args))])})"
        )
        await self.execute(command, args)
        return args

    @property
    def connection(self) -> SnowflakeConnection:
        return self._connection

    async def close(self):
        """Closes the cursor object.

        Returns whether the cursor was closed during this call.
        """
        try:
            if self.is_closed():
                return False
            async with self._lock_canceling:
                self.reset(closing=True)
                self._connection = None
                del self.messages[:]
                return True
        except Exception:
            return None

    async def execute(
        self,
        command: str,
        params: Sequence[Any] | dict[Any, Any] | None = None,
        _bind_stage: str | None = None,
        timeout: int | None = None,
        _exec_async: bool = False,
        _no_retry: bool = False,
        _do_reset: bool = True,
        _put_callback: SnowflakeProgressPercentage = None,
        _put_azure_callback: SnowflakeProgressPercentage = None,
        _put_callback_output_stream: IO[str] = sys.stdout,
        _get_callback: SnowflakeProgressPercentage = None,
        _get_azure_callback: SnowflakeProgressPercentage = None,
        _get_callback_output_stream: IO[str] = sys.stdout,
        _show_progress_bar: bool = True,
        _statement_params: dict[str, str] | None = None,
        _is_internal: bool = False,
        _describe_only: bool = False,
        _no_results: bool = False,
        _is_put_get: bool | None = None,
        _raise_put_get_error: bool = True,
        _force_put_overwrite: bool = False,
        _skip_upload_on_content_match: bool = False,
        file_stream: IO[bytes] | None = None,
        num_statements: int | None = None,
        _force_qmark_paramstyle: bool = False,
        _dataframe_ast: str | None = None,
    ) -> Self | dict[str, Any] | None:
        if _exec_async:
            _no_results = True
        logger.debug("executing SQL/command")
        if self.is_closed():
            Error.errorhandler_wrapper(
                self.connection,
                self,
                InterfaceError,
                {"msg": "Cursor is closed in execute.", "errno": ER_CURSOR_IS_CLOSED},
            )

        if _do_reset:
            self.reset()
        command = command.strip(" \t\n\r") if command else ""
        if not command:
            if _dataframe_ast:
                logger.debug("dataframe ast: [%s]", _dataframe_ast)
            else:
                logger.warning("execute: no query is given to execute")
                return None

        logger.debug("query: [%s]", self._format_query_for_log(command))

        _statement_params = _statement_params or dict()
        # If we need to add another parameter, please consider introducing a dict for all extra params
        # See discussion in https://github.com/snowflakedb/snowflake-connector-python/pull/1524#discussion_r1174061775
        if num_statements is not None:
            _statement_params = {
                **_statement_params,
                "MULTI_STATEMENT_COUNT": num_statements,
            }

        kwargs: dict[str, Any] = {
            "timeout": timeout,
            "statement_params": _statement_params,
            "is_internal": _is_internal,
            "describe_only": _describe_only,
            "_no_results": _no_results,
            "_is_put_get": _is_put_get,
            "_no_retry": _no_retry,
            "dataframe_ast": _dataframe_ast,
        }

        if self._connection.is_pyformat and not _force_qmark_paramstyle:
            query = await self._preprocess_pyformat_query(command, params)
        else:
            # qmark and numeric paramstyle
            query = command
            if _bind_stage:
                kwargs["binding_stage"] = _bind_stage
            else:
                if params is not None and not isinstance(params, (list, tuple)):
                    errorvalue = {
                        "msg": f"Binding parameters must be a list: {params}",
                        "errno": ER_FAILED_PROCESSING_PYFORMAT,
                    }
                    Error.errorhandler_wrapper(
                        self.connection, self, ProgrammingError, errorvalue
                    )

                kwargs["binding_params"] = self._connection._process_params_qmarks(
                    params, self
                )

        m = DESC_TABLE_RE.match(query)
        if m:
            query1 = f"describe table {m.group(1)}"
            logger.debug(
                "query was rewritten: org=%s, new=%s",
                " ".join(line.strip() for line in query.split("\n")),
                query1,
            )
            query = query1

        ret = await self._execute_helper(query, **kwargs)
        self._sfqid = (
            ret["data"]["queryId"]
            if "data" in ret and "queryId" in ret["data"]
            else None
        )
        logger.debug(f"sfqid: {self.sfqid}")
        self._sqlstate = (
            ret["data"]["sqlState"]
            if "data" in ret and "sqlState" in ret["data"]
            else None
        )
        logger.debug("query execution done")

        self._first_chunk_time = get_time_millis()

        # if server gives a send time, log the time it took to arrive
        if "data" in ret and "sendResultTime" in ret["data"]:
            time_consume_first_result = (
                self._first_chunk_time - ret["data"]["sendResultTime"]
            )
            await self._log_telemetry_job_data(
                TelemetryField.TIME_CONSUME_FIRST_RESULT, time_consume_first_result
            )

        if ret["success"]:
            logger.debug("SUCCESS")
            data = ret["data"]

            for m in self.ALTER_SESSION_RE.finditer(query):
                # session parameters
                param = m.group(1).upper()
                value = m.group(2)
                self._connection.converter.set_parameter(param, value)

            if "resultIds" in data:
                await self._init_multi_statement_results(data)
                return self
            else:
                self.multi_statement_savedIds = []

            self._is_file_transfer = "command" in data and data["command"] in (
                "UPLOAD",
                "DOWNLOAD",
            )
            logger.debug("PUT OR GET: %s", self.is_file_transfer)
            if self.is_file_transfer:
                # Decide whether to use the old, or new code path
                sf_file_transfer_agent = self._create_file_transfer_agent(
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
                    skip_upload_on_content_match=_skip_upload_on_content_match,
                    source_from_stream=file_stream,
                    multipart_threshold=data.get("threshold"),
                )
                await sf_file_transfer_agent.execute()
                data = sf_file_transfer_agent.result()
                self._total_rowcount = len(data["rowset"]) if "rowset" in data else -1

            if _exec_async:
                self.connection._async_sfqids[self._sfqid] = None
            if _no_results:
                self._total_rowcount = (
                    ret["data"]["total"]
                    if "data" in ret and "total" in ret["data"]
                    else -1
                )
                return data
            await self._init_result_and_meta(data)
        else:
            self._total_rowcount = (
                ret["data"]["total"] if "data" in ret and "total" in ret["data"] else -1
            )
            logger.debug(ret)
            err = ret["message"]
            code = ret.get("code", -1)
            if (
                self._timebomb
                and self._timebomb.result()
                and "SQL execution canceled" in err
            ):
                # Modify the error message only if the server error response indicates the query was canceled.
                # If the error occurs before the cancellation request reaches the backend
                # (e.g., due to a very short timeout), we retain the original error message
                # as the query might have encountered an issue prior to cancellation.
                err = (
                    f"SQL execution was cancelled by the client due to a timeout. "
                    f"Error message received from the server: {err}"
                )
            if "data" in ret:
                err += ret["data"].get("errorMessage", "")
            errvalue = {
                "msg": err,
                "errno": int(code),
                "sqlstate": self._sqlstate,
                "sfqid": self._sfqid,
                "query": query,
            }
            is_integrity_error = (
                code == "100072"
            )  # NULL result in a non-nullable column
            error_class = IntegrityError if is_integrity_error else ProgrammingError
            Error.errorhandler_wrapper(self.connection, self, error_class, errvalue)
        return self

    async def executemany(
        self,
        command: str,
        seqparams: Sequence[Any] | dict[str, Any],
        **kwargs: Any,
    ) -> SnowflakeCursor:
        """Executes a command/query with the given set of parameters sequentially."""
        logger.debug("executing many SQLs/commands")
        command = command.strip(" \t\n\r") if command else None

        if not seqparams:
            logger.warning(
                "No parameters provided to executemany, returning without doing anything."
            )
            return self

        if self.INSERT_SQL_RE.match(command) and (
            "num_statements" not in kwargs or kwargs.get("num_statements") == 1
        ):
            if self._connection.is_pyformat:
                # TODO(SNOW-940692) - utilize multi-statement instead of rewriting the query and
                #  accumulate results to mock the result from a single insert statement as formatted below
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
                await self.execute(command, **kwargs)
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
                    >= self.connection._session_parameters[
                        "CLIENT_STAGE_ARRAY_BINDING_THRESHOLD"
                    ]
                    > 0
                ):
                    # bind stage optimization
                    try:
                        rows = self.connection._write_params_to_byte_rows(seqparams)
                        bind_uploader = BindUploadAgent(self, rows)
                        await bind_uploader.upload()
                        bind_stage = bind_uploader.stage_path
                    except BindUploadError:
                        logger.debug(
                            "Failed to upload binds to stage, sending binds to "
                            "Snowflake instead."
                        )
                binding_param = (
                    None if bind_stage else list(map(list, zip(*seqparams)))
                )  # transpose
                await self.execute(
                    command, params=binding_param, _bind_stage=bind_stage, **kwargs
                )
                return self

        self.reset()
        if "num_statements" not in kwargs:
            # fall back to old driver behavior when the user does not provide the parameter to enable
            #  multi-statement optimizations for executemany
            for param in seqparams:
                await self.execute(command, params=param, _do_reset=False, **kwargs)
        else:
            if re.search(";/s*$", command) is None:
                command = command + "; "
            if self._connection.is_pyformat and not kwargs.get(
                "_force_qmark_paramstyle", False
            ):
                processed_queries = [
                    await self._preprocess_pyformat_query(command, params)
                    for params in seqparams
                ]
                query = "".join(processed_queries)
                params = None
            else:
                query = command * len(seqparams)
                params = [param for parameters in seqparams for param in parameters]

            kwargs["num_statements"]: int = kwargs.get("num_statements") * len(
                seqparams
            )

            await self.execute(query, params, _do_reset=False, **kwargs)

        return self

    async def execute_async(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Convenience function to execute a query without waiting for results (asynchronously).

        This function takes the same arguments as execute, please refer to that function
        for documentation. Please note that PUT and GET statements are not supported by this method.
        """
        kwargs["_exec_async"] = True
        return await self.execute(*args, **kwargs)

    @property
    def errorhandler(self):
        # TODO: SNOW-1763103 for async error handler
        raise NotImplementedError(
            "Async Snowflake Python Connector does not support errorhandler. "
            "Please open a feature request issue in github if your want this feature: "
            "https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose."
        )

    @errorhandler.setter
    def errorhandler(self, value):
        # TODO: SNOW-1763103 for async error handler
        raise NotImplementedError(
            "Async Snowflake Python Connector does not support errorhandler. "
            "Please open a feature request issue in github if your want this feature: "
            "https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose."
        )

    async def describe(self, *args: Any, **kwargs: Any) -> list[ResultMetadata]:
        """Obtain the schema of the result without executing the query.

        This function takes the same arguments as execute, please refer to that function
        for documentation.

        Returns:
            The schema of the result.
        """
        kwargs["_describe_only"] = kwargs["_is_internal"] = True
        await self.execute(*args, **kwargs)

        if self._description is None:
            return None
        return [meta._to_result_metadata_v1() for meta in self._description]

    @abc.abstractmethod
    async def fetchone(self) -> FetchRow:
        pass

    async def _fetchone(self) -> dict[str, Any] | tuple[Any, ...] | None:
        """
        Fetches one row.

        Returns a dict if self._use_dict_result is True, otherwise
        returns tuple.
        """
        if self._prefetch_hook is not None:
            await self._prefetch_hook()
        if self._result is None and self._result_set is not None:
            self._result: ResultSetIterator = await self._result_set._create_iter()
            self._result_state = ResultState.VALID
        try:
            if self._result is None:
                raise TypeError("'NoneType' object is not an iterator")
            _next = await self._result.get_next()
            if isinstance(_next, Exception):
                Error.errorhandler_wrapper_from_ready_exception(
                    self._connection,
                    self,
                    _next,
                )
            if _next is not None:
                self._rownumber += 1
            return _next
        except TypeError as err:
            if self._result_state == ResultState.DEFAULT:
                raise err
            else:
                return None

    async def fetchmany(self, size: int | None = None) -> list[FetchRow]:
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
            row = await self.fetchone()
            if row is None:
                break
            ret.append(row)
            if size is not None:
                size -= 1

        return ret

    async def fetchall(self) -> list[tuple] | list[dict]:
        """Fetches all of the results."""
        if self._prefetch_hook is not None:
            await self._prefetch_hook()
        if self._result is None and self._result_set is not None:
            self._result: ResultSetIterator = await self._result_set._create_iter(
                is_fetch_all=True,
            )
            self._result_state = ResultState.VALID

        if self._result is None:
            if self._result_state == ResultState.DEFAULT:
                raise TypeError("'NoneType' object is not an iterator")
            else:
                return []

        return await self._result.fetch_all_data()

    async def fetch_arrow_batches(self) -> AsyncIterator[Table]:
        self.check_can_use_arrow_resultset()
        if self._prefetch_hook is not None:
            await self._prefetch_hook()
        if self._query_result_format != "arrow":
            raise NotSupportedError
        await self._log_telemetry_job_data(
            TelemetryField.ARROW_FETCH_BATCHES, TelemetryData.TRUE
        )
        return await self._result_set._fetch_arrow_batches()

    @overload
    async def fetch_arrow_all(
        self, force_return_table: Literal[False]
    ) -> Table | None: ...

    @overload
    async def fetch_arrow_all(self, force_return_table: Literal[True]) -> Table: ...

    async def fetch_arrow_all(self, force_return_table: bool = False) -> Table | None:
        """
        Args:
            force_return_table: Set to True so that when the query returns zero rows,
                an empty pyarrow table will be returned with schema using the highest bit length for each column.
                Default value is False in which case None is returned in case of zero rows.
        """
        self.check_can_use_arrow_resultset()

        if self._prefetch_hook is not None:
            await self._prefetch_hook()
        if self._query_result_format != "arrow":
            raise NotSupportedError
        await self._log_telemetry_job_data(
            TelemetryField.ARROW_FETCH_ALL, TelemetryData.TRUE
        )
        return await self._result_set._fetch_arrow_all(
            force_return_table=force_return_table
        )

    async def fetch_pandas_batches(self, **kwargs: Any) -> AsyncIterator[DataFrame]:
        """Fetches a single Arrow Table."""
        self.check_can_use_pandas()
        if self._prefetch_hook is not None:
            await self._prefetch_hook()
        if self._query_result_format != "arrow":
            raise NotSupportedError
        await self._log_telemetry_job_data(
            TelemetryField.PANDAS_FETCH_BATCHES, TelemetryData.TRUE
        )
        return await self._result_set._fetch_pandas_batches(**kwargs)

    async def fetch_pandas_all(self, **kwargs: Any) -> DataFrame:
        self.check_can_use_pandas()
        if self._prefetch_hook is not None:
            await self._prefetch_hook()
        if self._query_result_format != "arrow":
            raise NotSupportedError
        await self._log_telemetry_job_data(
            TelemetryField.PANDAS_FETCH_ALL, TelemetryData.TRUE
        )
        return await self._result_set._fetch_pandas_all(**kwargs)

    async def nextset(self) -> SnowflakeCursor | None:
        """
        Fetches the next set of results if the previously executed query was multi-statement so that subsequent calls
        to any of the fetch*() methods will return rows from the next query's set of results. Returns None if no more
        query results are available.
        """
        if self._prefetch_hook is not None:
            await self._prefetch_hook()
        self.reset()
        if self._multi_statement_resultIds:
            await self.query_result(self._multi_statement_resultIds[0])
            logger.info(
                f"Retrieved results for query ID: {self._multi_statement_resultIds.popleft()}"
            )
            return self

        return None

    async def get_result_batches(self) -> list[ResultBatch] | None:
        """Get the previously executed query's ``ResultBatch`` s if available.

        If they are unavailable, in case nothing has been executed yet None will
        be returned.

        For a detailed description of ``ResultBatch`` s please see the docstring of:
        ``snowflake.connector.result_batches.ResultBatch``
        """
        if self._result_set is None:
            return None
        await self._log_telemetry_job_data(
            TelemetryField.GET_PARTITIONS_USED, TelemetryData.TRUE
        )
        return self._result_set.batches

    async def _download(
        self,
        stage_location: str,
        target_directory: str,
        options: dict[str, Any],
        _do_reset: bool = True,
    ) -> None:
        """Downloads from the stage location to the target directory.

        Args:
            stage_location (str): The location of the stage to download from.
            target_directory (str): The destination directory to download into.
            options (dict[str, Any]): The download options.
            _do_reset (bool, optional): Whether to reset the cursor before
                downloading, by default we will reset the cursor.
        """
        if _do_reset:
            self.reset()

        # Interpret the file operation.
        ret = await self.connection._file_operation_parser.parse_file_operation(
            stage_location=stage_location,
            local_file_name=None,
            target_directory=target_directory,
            command_type=CMD_TYPE_DOWNLOAD,
            options=options,
        )

        # Execute the file operation based on the interpretation above.
        file_transfer_agent = self._create_file_transfer_agent(
            "",  # empty command because it is triggered by directly calling this util not by a SQL query
            ret,
        )
        await file_transfer_agent.execute()
        await self._init_result_and_meta(file_transfer_agent.result())

    async def _upload(
        self,
        local_file_name: str,
        stage_location: str,
        options: dict[str, Any],
        _do_reset: bool = True,
    ) -> None:
        """Uploads the local file to the stage location.

        Args:
            local_file_name (str): The local file to be uploaded.
            stage_location (str): The stage location to upload the local file to.
            options (dict[str, Any]): The upload options.
            _do_reset (bool, optional): Whether to reset the cursor before
                uploading, by default we will reset the cursor.
        """
        if _do_reset:
            self.reset()

        # Interpret the file operation.
        ret = await self.connection._file_operation_parser.parse_file_operation(
            stage_location=stage_location,
            local_file_name=local_file_name,
            target_directory=None,
            command_type=CMD_TYPE_UPLOAD,
            options=options,
        )

        # Execute the file operation based on the interpretation above.
        file_transfer_agent = self._create_file_transfer_agent(
            "",  # empty command because it is triggered by directly calling this util not by a SQL query
            ret,
            force_put_overwrite=False,  # _upload should respect user decision on overwriting
        )
        await file_transfer_agent.execute()
        await self._init_result_and_meta(file_transfer_agent.result())

    async def _download_stream(
        self, stage_location: str, decompress: bool = False
    ) -> IO[bytes]:
        """Downloads from the stage location as a stream.

        Args:
            stage_location (str): The location of the stage to download from.
            decompress (bool, optional): Whether to decompress the file, by
                default we do not decompress.

        Returns:
            IO[bytes]: A stream to read from.
        """
        # Interpret the file operation.
        ret = await self.connection._file_operation_parser.parse_file_operation(
            stage_location=stage_location,
            local_file_name=None,
            target_directory=None,
            command_type=CMD_TYPE_DOWNLOAD,
            options=None,
            has_source_from_stream=True,
        )

        # Set up stream downloading based on the interpretation and return the stream for reading.
        return await self.connection._stream_downloader.download_as_stream(
            ret, decompress
        )

    async def _upload_stream(
        self,
        input_stream: IO[bytes],
        stage_location: str,
        options: dict[str, Any],
        _do_reset: bool = True,
    ) -> None:
        """Uploads content in the input stream to the stage location.

        Args:
            input_stream (IO[bytes]): A stream to read from.
            stage_location (str): The location of the stage to upload to.
            options (dict[str, Any]): The upload options.
            _do_reset (bool, optional): Whether to reset the cursor before
                uploading, by default we will reset the cursor.
        """
        if _do_reset:
            self.reset()

        # Interpret the file operation.
        ret = await self.connection._file_operation_parser.parse_file_operation(
            stage_location=stage_location,
            local_file_name=None,
            target_directory=None,
            command_type=CMD_TYPE_UPLOAD,
            options=options,
            has_source_from_stream=input_stream,
        )

        # Execute the file operation based on the interpretation above.
        file_transfer_agent = self._create_file_transfer_agent(
            "",  # empty command because it is triggered by directly calling this util not by a SQL query
            ret,
            source_from_stream=input_stream,
            force_put_overwrite=False,  # _upload should respect user decision on overwriting
        )
        await file_transfer_agent.execute()
        await self._init_result_and_meta(file_transfer_agent.result())

    async def get_results_from_sfqid(self, sfqid: str) -> None:
        """Gets the results from previously ran query. This methods differs from ``SnowflakeCursor.query_result``
        in that it monitors the ``sfqid`` until it is no longer running, and then retrieves the results.
        """

        async def wait_until_ready() -> None:
            """Makes sure query has finished executing and once it has retrieves results."""
            no_data_counter = 0
            retry_pattern_pos = 0
            while True:
                status, status_resp = await self.connection._get_query_status(sfqid)
                self.connection._cache_query_status(sfqid, status)
                if not self.connection.is_still_running(status):
                    break
                if status == QueryStatus.NO_DATA:  # pragma: no cover
                    no_data_counter += 1
                    if no_data_counter > ASYNC_NO_DATA_MAX_RETRY:
                        raise DatabaseError(
                            "Cannot retrieve data on the status of this query. No information returned "
                            "from server for query '{}'"
                        )
                await asyncio.sleep(
                    0.5 * ASYNC_RETRY_PATTERN[retry_pattern_pos]
                )  # Same wait as JDBC
                # If we can advance in ASYNC_RETRY_PATTERN then do so
                if retry_pattern_pos < (len(ASYNC_RETRY_PATTERN) - 1):
                    retry_pattern_pos += 1
            if status != QueryStatus.SUCCESS:
                logger.info(f"Status of query '{sfqid}' is {status.name}")
                self.connection._process_error_query_status(
                    sfqid,
                    status_resp,
                    error_message=f"Status of query '{sfqid}' is {status.name}, results are unavailable",
                    error_cls=DatabaseError,
                )
            await self._inner_cursor.execute(
                f"select * from table(result_scan('{sfqid}'))"
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

            if self._inner_cursor._total_rowcount == 1 and _is_successful_multi_stmt(
                await self._inner_cursor.fetchall()
            ):
                url = f"/queries/{sfqid}/result"
                ret = await self._connection.rest.request(url=url, method="get")
                if "data" in ret and "resultIds" in ret["data"]:
                    await self._init_multi_statement_results(ret["data"])

        def _is_successful_multi_stmt(rows: list[Any]) -> bool:
            if len(rows) != 1:
                return False
            row = rows[0]
            if isinstance(row, tuple):
                return row == ("Multiple statements executed successfully.",)
            elif isinstance(row, dict):
                return row == {
                    "multiple statement execution": "Multiple statements executed successfully."
                }
            else:
                return False

        await self.connection.get_query_status_throw_if_error(
            sfqid
        )  # Trigger an exception if query failed
        self._inner_cursor = self.__class__(self.connection)
        self._sfqid = sfqid
        self._prefetch_hook = wait_until_ready

    async def query_result(self, qid: str) -> SnowflakeCursor:
        """Query the result of a previously executed query."""
        url = f"/queries/{qid}/result"
        ret = await self._connection.rest.request(url=url, method="get")
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
            await self._init_result_and_meta(data)
        else:
            logger.debug("failed")
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

    def _create_file_transfer_agent(
        self,
        command: str,
        ret: dict[str, Any],
        /,
        **kwargs,
    ) -> SnowflakeFileTransferAgent:
        from snowflake.connector.aio._file_transfer_agent import (
            SnowflakeFileTransferAgent,
        )

        return SnowflakeFileTransferAgent(
            self,
            command,
            ret,
            use_s3_regional_url=self._connection.enable_stage_s3_privatelink_for_us_east_1,
            unsafe_file_write=self._connection.unsafe_file_write,
            reraise_error_in_file_transfer_work_function=self._connection._reraise_error_in_file_transfer_work_function,
            **kwargs,
        )


class SnowflakeCursor(SnowflakeCursorBase[tuple[Any, ...]]):
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
    """

    @property
    def _use_dict_result(self) -> bool:
        return False

    async def fetchone(self) -> tuple[Any, ...] | None:
        row = await self._fetchone()
        if not (row is None or isinstance(row, tuple)):
            raise TypeError(f"fetchone got unexpected result: {row}")
        return row


class DictCursor(SnowflakeCursorBase[dict[str, Any]]):
    """Cursor returning results in a dictionary."""

    @property
    def _use_dict_result(self) -> bool:
        return True

    async def fetchone(self) -> dict[str, Any] | None:
        row = await self._fetchone()
        if not (row is None or isinstance(row, dict)):
            raise TypeError(f"fetchone got unexpected result: {row}")
        return row
