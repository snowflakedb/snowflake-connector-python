#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import sys
import uuid
from logging import getLogger
from typing import IO, TYPE_CHECKING, Any, Sequence

from typing_extensions import Self

from snowflake.connector import Error, IntegrityError, InterfaceError, ProgrammingError
from snowflake.connector._sql_util import get_file_transfer_type
from snowflake.connector.aio._file_transfer_agent import SnowflakeProgressPercentage
from snowflake.connector.constants import PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT
from snowflake.connector.cursor import (
    CAN_USE_ARROW_RESULT_FORMAT,
    DESC_TABLE_RE,
    ResultState,
)
from snowflake.connector.cursor import SnowflakeCursor as SnowflakeCursorSync
from snowflake.connector.errorcode import (
    ER_CURSOR_IS_CLOSED,
    ER_FAILED_PROCESSING_PYFORMAT,
    ER_INVALID_VALUE,
)
from snowflake.connector.time_util import get_time_millis

if TYPE_CHECKING:
    from snowflake.connector.aio import SnowflakeConnection

logger = getLogger(__name__)


class SnowflakeCursor(SnowflakeCursorSync):
    def __init__(
        self,
        connection: SnowflakeConnection,
        use_dict_result: bool = False,
    ):
        super().__init__(connection, use_dict_result)
        # the following fixes type hint
        self._connection: SnowflakeConnection = connection

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
        command = command.strip(" \t\n\r") if command else None
        if not command:
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

        if self._connection.is_pyformat:
            query = self._preprocess_pyformat_query(command, params)
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
        # TODO: telemetry support in asyncio
        # if "data" in ret and "sendResultTime" in ret["data"]:
        #     time_consume_first_result = (
        #         self._first_chunk_time - ret["data"]["sendResultTime"]
        #     )
        #     self._log_telemetry_job_data(
        #         TelemetryField.TIME_CONSUME_FIRST_RESULT, time_consume_first_result
        #     )

        if ret["success"]:
            logger.debug("SUCCESS")
            data = ret["data"]

            for m in self.ALTER_SESSION_RE.finditer(query):
                # session parameters
                param = m.group(1).upper()
                value = m.group(2)
                self._connection.converter.set_parameter(param, value)

            if "resultIds" in data:
                self._init_multi_statement_results(data)
                return self
            else:
                self.multi_statement_savedIds = []

            self._is_file_transfer = "command" in data and data["command"] in (
                "UPLOAD",
                "DOWNLOAD",
            )
            logger.debug("PUT OR GET: %s", self.is_file_transfer)
            if self.is_file_transfer:
                from ._file_transfer_agent import SnowflakeFileTransferAgent

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
                    skip_upload_on_content_match=_skip_upload_on_content_match,
                    source_from_stream=file_stream,
                    multipart_threshold=data.get("threshold"),
                    use_s3_regional_url=self._connection.enable_stage_s3_privatelink_for_us_east_1,
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
                "query": query,
            }
            is_integrity_error = (
                code == "100072"
            )  # NULL result in a non-nullable column
            error_class = IntegrityError if is_integrity_error else ProgrammingError
            Error.errorhandler_wrapper(self.connection, self, error_class, errvalue)
        return self

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
                    statement_params[PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT] = (
                        "JSON"
                    )

        self._sequence_counter = await self._connection._next_sequence_counter()
        self._request_id = uuid.uuid4()

        logger.debug(f"Request id: {self._request_id}")

        logger.debug("running query [%s]", self._format_query_for_log(query))
        if _is_put_get is not None:
            # if told the query is PUT or GET, use the information
            self._is_file_transfer = _is_put_get
        else:
            # or detect it.
            self._is_file_transfer = get_file_transfer_type(query) is not None
        logger.debug("is_file_transfer: %s", self._is_file_transfer is not None)

        real_timeout = (
            timeout if timeout and timeout > 0 else self._connection.network_timeout
        )

        # TODO: asyncio timer bomb
        # if real_timeout is not None:
        #     self._timebomb = Timer(real_timeout, self.__cancel_query, [query])
        #     self._timebomb.start()
        #     logger.debug("started timebomb in %ss", real_timeout)
        # else:
        #     self._timebomb = None
        #
        # original_sigint = signal.getsignal(signal.SIGINT)
        #
        # def interrupt_handler(*_):  # pragma: no cover
        #     try:
        #         signal.signal(signal.SIGINT, exit_handler)
        #     except (ValueError, TypeError):
        #         # ignore failures
        #         pass
        #     try:
        #         if self._timebomb is not None:
        #             self._timebomb.cancel()
        #             logger.debug("cancelled timebomb in finally")
        #             self._timebomb = None
        #         self.__cancel_query(query)
        #     finally:
        #         if original_sigint:
        #             try:
        #                 signal.signal(signal.SIGINT, original_sigint)
        #             except (ValueError, TypeError):
        #                 # ignore failures
        #                 pass
        #     raise KeyboardInterrupt
        #
        # try:
        #     if not original_sigint == exit_handler:
        #         signal.signal(signal.SIGINT, interrupt_handler)
        # except ValueError:  # pragma: no cover
        #     logger.debug(
        #         "Failed to set SIGINT handler. " "Not in main thread. Ignored..."
        #     )
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
            pass
            # TODO: async timer bomb
            # try:
            #     if original_sigint:
            #         signal.signal(signal.SIGINT, original_sigint)
            # except (ValueError, TypeError):  # pragma: no cover
            #     logger.debug(
            #         "Failed to reset SIGINT handler. Not in main " "thread. Ignored..."
            #     )
            # if self._timebomb is not None:
            #     self._timebomb.cancel()
            #     logger.debug("cancelled timebomb in finally")

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

    async def fetchone(self) -> dict | tuple | None:
        """Fetches one row."""
        if self._prefetch_hook is not None:
            self._prefetch_hook()
        # TODO: aio result set
        if self._result is None and self._result_set is not None:
            self._result = iter(self._result_set)
            self._result_state = ResultState.VALID

        try:
            # TODO: aio result set / asyncio generator
            _next = next(self._result, None)
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

    async def fetchall(self) -> list[tuple] | list[dict]:
        """Fetches all of the results."""
        ret = []
        while True:
            row = await self.fetchone()
            if row is None:
                break
            ret.append(row)
        return ret

    @property
    def connection(self) -> SnowflakeConnection:
        return self._connection
