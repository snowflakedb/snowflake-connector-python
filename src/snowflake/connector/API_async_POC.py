#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import copy
import json
from collections import deque
from typing import IO, Self

from . import IntegrityError
from ._sql_util import get_file_transfer_type
from .config_manager import _get_default_connection_params
from .connection import *
from .constants import (
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_SERVICE_NAME,
    HTTP_HEADER_USER_AGENT,
    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT,
)
from .converter import SnowflakeConverterType
from .cursor import (
    CAN_USE_ARROW_RESULT_FORMAT,
    DESC_TABLE_RE,
    ResultMetadata,
    ResultState,
)
from .file_transfer_agent import SnowflakeProgressPercentage
from .network import (
    ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
    CONTENT_TYPE_APPLICATION_JSON,
    PYTHON_CONNECTOR_USER_AGENT,
    QUERY_IN_PROGRESS_ASYNC_CODE,
    QUERY_IN_PROGRESS_CODE,
    SESSION_EXPIRED_GS_CODE,
)
from .network_async import SnowflakeRestfulAsync
from .result_batch import (
    SSE_C_AES,
    SSE_C_ALGORITHM,
    SSE_C_KEY,
    DownloadMetrics,
    RemoteChunkInfo,
)
from .result_batch_async import JSONResultBatchAsync
from .result_set import ResultSet
from .secret_detector import SecretDetector
from .time_util import TimerContextManager
from .tool.probe_connection import probe_connection

# YICHUAN: This file is cobbled together for a quick demo of an async API. It consists almost entirely of copy & pasted
# code with async and await keywords slapped on everywhere. Most telemetry related code has been stripped.
# EVERYTHING IN HERE IS FOR POC ONLY. THE TYPE HINTS ARE ALL WRONG AND YOU WILL SEE HORRIBLE CODE. I AM SORRY.

# !!!!!!!!!!!!!!!!!!!!!!!!
# REPEATING THIS WARNING: What I've done to get async iteration working in the cursor, result set, and result batch
# classes is absolutely horrific and should NOT be copied under any circumstance in the future. You can get an idea of
# what things need to be changed to async by looking at my code, but PLEASE do not actually use it. The biggest problem
# is that after consuming the initially downloaded batch, the result set will block while downloading EVERY REMAINING
# BATCH because I used asyncio.gather for convenience. The download for all batches should be started, and iteration
# should only block when the next batch immediately needed isn't finished downloading yet (use asyncio tasks for this).
# !!!!!!!!!!!!!!!!!!!!!!!!


class SnowflakeConnectionAsyncPOC(SnowflakeConnection):
    def __init__(self, **kwargs) -> None:
        # YICHUAN: Init methods usually can't be async. Use connect_async instead.
        self._temporary_kwargs = kwargs

    async def __aenter__(self):
        await self.connect_async(**self._temporary_kwargs)
        return self

    async def __aexit__(self, *_):
        await self.close_async()

    async def connect_async(
        self,
        connection_name: str | None = None,
        connections_file_path: pathlib.Path | None = None,
        **kwargs,
    ) -> None:
        self._lock_sequence_counter = Lock()
        self.sequence_counter = 0
        self._errorhandler = Error.default_errorhandler
        self._lock_converter = Lock()
        self.messages = []
        self._async_sfqids: dict[str, None] = {}
        self._done_async_sfqids: dict[str, None] = {}
        self.telemetry_enabled = False
        self._session_parameters: dict[str, str | int | bool] = {}
        logger.info(
            "Snowflake Connector for Python Version: %s, "
            "Python Version: %s, Platform: %s",
            SNOWFLAKE_CONNECTOR_VERSION,
            PYTHON_VERSION,
            PLATFORM,
        )

        self._rest = None
        for name, (value, _) in DEFAULT_CONFIGURATION.items():
            setattr(self, f"_{name}", value)

        self.heartbeat_thread = None
        is_kwargs_empty = not kwargs

        if "application" not in kwargs:
            if ENV_VAR_PARTNER in os.environ.keys():
                kwargs["application"] = os.environ[ENV_VAR_PARTNER]
            elif "streamlit" in sys.modules:
                kwargs["application"] = "streamlit"

        self.converter = None
        self.query_context_cache: QueryContextCache | None = None
        self.query_context_cache_size = 5
        if connections_file_path is not None:
            # Change config file path and force update cache
            for i, s in enumerate(CONFIG_MANAGER._slices):
                if s.section == "connections":
                    CONFIG_MANAGER._slices[i] = s._replace(path=connections_file_path)
                    CONFIG_MANAGER.read_config()
                    break
        if connection_name is not None:
            connections = CONFIG_MANAGER["connections"]
            if connection_name not in connections:
                raise Error(
                    f"Invalid connection_name '{connection_name}',"
                    f" known ones are {list(connections.keys())}"
                )
            kwargs = {**connections[connection_name], **kwargs}
        elif is_kwargs_empty:
            # connection_name is None and kwargs was empty when called
            kwargs = _get_default_connection_params()
        self._SnowflakeConnection__set_error_attributes()

        if len(kwargs) > 0:
            self._SnowflakeConnection__config(**kwargs)
        try:
            await self.__open_connection_async()
        except Exception:
            if self.rest:
                await self.rest.close_async()
            raise

    async def __open_connection_async(self):
        """Opens a new network connection."""
        self.converter = self._converter_class(
            use_numpy=self._numpy, support_negative_year=self._support_negative_year
        )

        proxy.set_proxies(
            self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_password
        )

        self._rest = SnowflakeRestfulAsyncPOC(
            host=self.host,
            port=self.port,
            protocol=self._protocol,
            inject_client_pause=self._inject_client_pause,
            connection=self,
        )
        logger.debug("REST API object was created: %s:%s", self.host, self.port)

        if "SF_OCSP_RESPONSE_CACHE_SERVER_URL" in os.environ:
            logger.debug(
                "Custom OCSP Cache Server URL found in environment - %s",
                os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"],
            )

        if self.host.endswith(".privatelink.snowflakecomputing.com"):
            SnowflakeConnection.setup_ocsp_privatelink(self.application, self.host)
        else:
            if "SF_OCSP_RESPONSE_CACHE_SERVER_URL" in os.environ:
                del os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"]

        if self._session_parameters is None:
            self._session_parameters = {}
        if self._autocommit is not None:
            self._session_parameters[PARAMETER_AUTOCOMMIT] = self._autocommit

        if self._timezone is not None:
            self._session_parameters[PARAMETER_TIMEZONE] = self._timezone

        if self._validate_default_parameters:
            # Snowflake will validate the requested database, schema, and warehouse
            self._session_parameters[
                PARAMETER_CLIENT_VALIDATE_DEFAULT_PARAMETERS
            ] = True

        if self.client_session_keep_alive is not None:
            self._session_parameters[
                PARAMETER_CLIENT_SESSION_KEEP_ALIVE
            ] = self._client_session_keep_alive

        if self.client_session_keep_alive_heartbeat_frequency is not None:
            raise Exception("YICHUAN: No heartbeat for POC")

        if self.client_prefetch_threads:
            self._session_parameters[
                PARAMETER_CLIENT_PREFETCH_THREADS
            ] = self._validate_client_prefetch_threads()

        if self._authenticator == DEFAULT_AUTHENTICATOR:
            self.auth_class = AuthByDefault(
                password=self._password,
                timeout=self._login_timeout,
                backoff_generator=self._backoff_generator,
            )
        else:
            raise Exception("YICHUAN: Bad authenticator for POC!")

        await self.authenticate_with_retry_async(self.auth_class)

        self._password = None  # ensure password won't persist
        self.auth_class.reset_secrets()

        self.initialize_query_context_cache()

        if self.client_session_keep_alive:
            raise Exception("YICHUAN: No heartbeat for POC")

    async def authenticate_with_retry_async(self, auth_instance) -> None:
        # make some changes if needed before real __authenticate
        try:
            await self._authenticate_async(auth_instance)
        except ReauthenticationRequest as ex:
            raise Exception(f"YICHUAN: Died during authenticate in POC: {ex}")

    async def _authenticate_async(self, auth_instance: AuthByPlugin):
        auth_instance.prepare(
            conn=self,
            authenticator=self._authenticator,
            service_name=self.service_name,
            account=self.account,
            user=self.user,
            password=self._password,
        )
        self._consent_cache_id_token = getattr(
            auth_instance, "consent_cache_id_token", True
        )

        auth = AuthAsyncPOC(self.rest)
        # record start time for computing timeout
        auth_instance._retry_ctx.set_start_time()
        try:
            await auth.authenticate_async(
                auth_instance=auth_instance,
                account=self.account,
                user=self.user,
                database=self.database,
                schema=self.schema,
                warehouse=self.warehouse,
                role=self.role,
                passcode=self._passcode,
                passcode_in_password=self._passcode_in_password,
                mfa_callback=self._mfa_callback,
                password_callback=self._password_callback,
                session_parameters=self._session_parameters,
            )
        except OperationalError as e:
            raise Exception(f"YICHUAN: Died during authenticate in POC: {e}")

    async def close_async(self, retry: bool = True) -> None:
        """Closes the connection."""
        try:
            if not self.rest:
                logger.debug("Rest object has been destroyed, cannot close session")
                return

            await self.rest.close_async()
            self._rest = None
            if self.query_context_cache:
                self.query_context_cache.clear_cache()
            del self.messages[:]
            logger.debug("Session is closed")
        except Exception as e:
            raise Exception("YICHUAN: Couldn't close connection in POC")

    def cursor(
        self,
    ):
        """Creates a cursor object. Each statement will be executed in a new cursor object."""
        logger.debug("cursor")
        if not self.rest:
            raise Exception(
                "YICHUAN: Connection closed when attempting to get cursor in POC"
            )
        return SnowflakeCursorAsyncPOC(self)

    async def cmd_query_async(
        self,
        sql: str,
        sequence_counter: int,
        request_id: uuid.UUID,
        binding_params: None | tuple | dict[str, dict[str, str]] = None,
        binding_stage: str | None = None,
        is_file_transfer: bool = False,
        statement_params: dict[str, str] | None = None,
        is_internal: bool = False,
        describe_only: bool = False,
        _no_results: bool = False,
        _update_current_object: bool = True,
        _no_retry: bool = False,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Executes a query with a sequence counter."""
        logger.debug("_cmd_query")
        data = {
            "sqlText": sql,
            "asyncExec": _no_results,
            "sequenceId": sequence_counter,
            "querySubmissionTime": get_time_millis(),
        }
        if statement_params is not None:
            data["parameters"] = statement_params
        if is_internal:
            data["isInternal"] = is_internal
        if describe_only:
            data["describeOnly"] = describe_only
        if binding_stage is not None:
            # binding stage for bulk array binding
            data["bindStage"] = binding_stage
        if binding_params is not None:
            # binding parameters. This is for qmarks paramstyle.
            data["bindings"] = binding_params
        if not _no_results:
            # not an async query.
            queryContext = self.get_query_context()
            #  Here queryContextDTO should be a dict object field, same with `parameters` field
            data["queryContextDTO"] = queryContext
        client = "sfsql_file_transfer" if is_file_transfer else "sfsql"

        if logger.getEffectiveLevel() <= logging.DEBUG:
            logger.debug(
                "sql=[%s], sequence_id=[%s], is_file_transfer=[%s]",
                self._format_query_for_log(data["sqlText"]),
                data["sequenceId"],
                is_file_transfer,
            )

        url_parameters = {REQUEST_ID: request_id}

        ret = await self.rest.request_async(
            "/queries/v1/query-request?" + urlencode(url_parameters),
            data,
            client=client,
            _no_results=_no_results,
            _include_retry_params=True,
            _no_retry=_no_retry,
            timeout=timeout,
        )

        if ret is None:
            ret = {"data": {}}
        if ret.get("data") is None:
            ret["data"] = {}
        if _update_current_object:
            data = ret["data"]
            if "finalDatabaseName" in data and data["finalDatabaseName"] is not None:
                self._database = data["finalDatabaseName"]
            if "finalSchemaName" in data and data["finalSchemaName"] is not None:
                self._schema = data["finalSchemaName"]
            if "finalWarehouseName" in data and data["finalWarehouseName"] is not None:
                self._warehouse = data["finalWarehouseName"]
            if "finalRoleName" in data:
                self._role = data["finalRoleName"]
            if "queryContext" in data and not _no_results:
                # here the data["queryContext"] field has been automatically converted from JSON into a dict type
                self.set_query_context(data["queryContext"])

        return ret


class AuthAsyncPOC(Auth):
    async def authenticate_async(
        self,
        auth_instance: AuthByPlugin,
        account: str,
        user: str,
        database: str | None = None,
        schema: str | None = None,
        warehouse: str | None = None,
        role: str | None = None,
        passcode: str | None = None,
        passcode_in_password: bool = False,
        mfa_callback: Callable[[], None] | None = None,
        password_callback: Callable[[], str] | None = None,
        session_parameters: dict[Any, Any] | None = None,
        # max time waiting for MFA response, currently unused
        timeout: int | None = None,
    ) -> dict[str, str | int | bool]:
        logger.debug("authenticate")

        if timeout is None:
            timeout = auth_instance.timeout

        if session_parameters is None:
            session_parameters = {}

        request_id = str(uuid.uuid4())
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if HTTP_HEADER_SERVICE_NAME in session_parameters:
            headers[HTTP_HEADER_SERVICE_NAME] = session_parameters[
                HTTP_HEADER_SERVICE_NAME
            ]
        url = "/session/v1/login-request"

        body_template = Auth.base_auth_data(
            user,
            account,
            self._rest._connection.application,
            self._rest._connection._internal_application_name,
            self._rest._connection._internal_application_version,
            self._rest._connection._ocsp_mode(),
            self._rest._connection._login_timeout,
            self._rest._connection._network_timeout,
            self._rest._connection._socket_timeout,
        )

        body = copy.deepcopy(body_template)
        # updating request body
        logger.debug("assertion content: %s", auth_instance.assertion_content)
        auth_instance.update_body(body)

        logger.debug(
            "account=%s, user=%s, database=%s, schema=%s, "
            "warehouse=%s, role=%s, request_id=%s",
            account,
            user,
            database,
            schema,
            warehouse,
            role,
            request_id,
        )
        url_parameters = {"request_id": request_id}
        if database is not None:
            url_parameters["databaseName"] = database
        if schema is not None:
            url_parameters["schemaName"] = schema
        if warehouse is not None:
            url_parameters["warehouse"] = warehouse
        if role is not None:
            url_parameters["roleName"] = role

        url = url + "?" + urlencode(url_parameters)

        # first auth request
        if passcode_in_password:
            body["data"]["EXT_AUTHN_DUO_METHOD"] = "passcode"
        elif passcode:
            body["data"]["EXT_AUTHN_DUO_METHOD"] = "passcode"
            body["data"]["PASSCODE"] = passcode

        if session_parameters:
            body["data"]["SESSION_PARAMETERS"] = session_parameters

        logger.debug(
            "body['data']: %s",
            {k: v for (k, v) in body["data"].items() if k != "PASSWORD"},
        )

        try:
            ret = await self._rest._post_request_async(
                url,
                headers,
                json.dumps(body),
                socket_timeout=auth_instance._socket_timeout,
            )
        except Exception as e:
            raise Exception(f"YICHUAN: Died during authenticate in POC: {e}")

        logger.debug("completed authentication")
        if not ret["success"]:
            raise Exception(f"YICHUAN: Unknown failure during authenticate in POC")
        else:
            if not ret["data"]:
                raise Exception(f"YICHUAN: Empty return data authenticate in POC")
            self._rest.update_tokens(
                ret["data"].get("token"),
                ret["data"].get("masterToken"),
                master_validity_in_seconds=ret["data"].get("masterValidityInSeconds"),
                id_token=ret["data"].get("idToken"),
                mfa_token=ret["data"].get("mfaToken"),
            )
            self.write_temporary_credentials(
                self._rest._host, user, session_parameters, ret
            )
            if ret["data"] and "sessionId" in ret["data"]:
                self._rest._connection._session_id = ret["data"].get("sessionId")
            if ret["data"] and "sessionInfo" in ret["data"]:
                session_info = ret["data"].get("sessionInfo")
                self._rest._connection._database = session_info.get("databaseName")
                self._rest._connection._schema = session_info.get("schemaName")
                self._rest._connection._warehouse = session_info.get("warehouseName")
                self._rest._connection._role = session_info.get("roleName")
            if ret["data"] and "parameters" in ret["data"]:
                session_parameters.update(
                    {p["name"]: p["value"] for p in ret["data"].get("parameters")}
                )
            self._rest._connection._update_parameters(session_parameters)
            return session_parameters


class SnowflakeRestfulAsyncPOC(SnowflakeRestfulAsync):
    async def request_async(
        self,
        url,
        body=None,
        method: str = "post",
        client: str = "sfsql",
        timeout: int | None = None,
        _no_results: bool = False,
        _include_retry_params: bool = False,
        _no_retry: bool = False,
    ):
        if body is None:
            body = {}
        if self.master_token is None and self.token is None:
            Error.errorhandler_wrapper(
                self._connection,
                None,
                DatabaseError,
                {
                    "msg": "Connection is closed",
                    "errno": ER_CONNECTION_IS_CLOSED,
                    "sqlstate": SQLSTATE_CONNECTION_NOT_EXISTS,
                },
            )

        if client == "sfsql":
            accept_type = ACCEPT_TYPE_APPLICATION_SNOWFLAKE
        else:
            accept_type = CONTENT_TYPE_APPLICATION_JSON

        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: accept_type,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if self._connection.service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = self._connection.service_name
        if method == "post":
            return await self._post_request_async(
                url,
                headers,
                json.dumps(body),
                token=self.token,
                _no_results=_no_results,
                timeout=timeout,
                _include_retry_params=_include_retry_params,
                no_retry=_no_retry,
            )
        else:
            return await self._get_request_async(
                url,
                headers,
                token=self.token,
                timeout=timeout,
            )

    async def _post_request_async(
        self,
        url,
        headers,
        body,
        token=None,
        timeout: int | None = None,
        socket_timeout: int | None = None,
        _no_results: bool = False,
        no_retry: bool = False,
        _include_retry_params: bool = False,
    ):
        full_url = f"{self._protocol}://{self._host}:{self._port}{url}"
        if self._connection._probe_connection:
            from pprint import pprint

            ret = probe_connection(full_url)
            pprint(ret)

        ret = await self.fetch_async(
            "post",
            full_url,
            headers,
            data=body,
            timeout=timeout,
            token=token,
            no_retry=no_retry,
            _include_retry_params=_include_retry_params,
            socket_timeout=socket_timeout,
        )
        logger.debug(
            "ret[code] = {code}, after post request".format(
                code=(ret.get("code", "N/A"))
            )
        )

        if ret.get("code") == SESSION_EXPIRED_GS_CODE:
            raise Exception(f"YICHUAN: Session expired for request in POC")

        if isinstance(ret.get("data"), dict) and ret["data"].get("queryId"):
            logger.debug("Query id: {}".format(ret["data"]["queryId"]))

        if ret.get("code") == QUERY_IN_PROGRESS_ASYNC_CODE and _no_results:
            return ret

        while ret.get("code") in (QUERY_IN_PROGRESS_CODE, QUERY_IN_PROGRESS_ASYNC_CODE):
            if self._inject_client_pause > 0:
                logger.debug("waiting for %s...", self._inject_client_pause)
                await asyncio.sleep(self._inject_client_pause)
            # ping pong
            result_url = ret["data"]["getResultUrl"]
            logger.debug("ping pong starting...")
            ret = await self._get_request_async(
                result_url, headers, token=self.token, timeout=timeout
            )
            logger.debug("ret[code] = %s", ret.get("code", "N/A"))
            logger.debug("ping pong done")

        return ret

    async def _get_request_async(
        self,
        url: str,
        headers: dict[str, str],
        token: str = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        if "Content-Encoding" in headers:
            del headers["Content-Encoding"]
        if "Content-Length" in headers:
            del headers["Content-Length"]

        full_url = f"{self._protocol}://{self._host}:{self._port}{url}"
        ret = await self.fetch_async(
            "get",
            full_url,
            headers,
            timeout=timeout,
            token=token,
        )
        if ret.get("code") == SESSION_EXPIRED_GS_CODE:
            raise Exception(f"YICHUAN: Session expired for request in POC")

        return ret


class SnowflakeCursorAsyncPOC(SnowflakeCursor):
    async def __aiter__(self):
        while True:
            _next = await self.fetchone_async()
            if _next is None:
                break
            yield _next

    async def fetchone_async(self) -> dict | tuple | None:
        if self._result is None and self._result_set is not None:
            self._result = await self._result_set._create_iter_async()
            self._result_state = ResultState.VALID

        try:
            _next = await anext(self._result, None)
            if isinstance(_next, Exception):
                raise Exception("YICHUAN: Unknown iterator exception in POC")
            if _next is not None:
                self._rownumber += 1
            return _next
        except TypeError as err:
            if self._result_state == ResultState.DEFAULT:
                raise err
            else:
                return None

    # YICHUAN: execute_async already exists and isn't actually async so let's use a different name
    async def execute_real_async(
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
    ) -> Self | dict[str, Any] | None:
        if _exec_async:
            raise Exception(
                "YICHUAN: THIS METHOD IS ALREADY ASYNC STOP MIXING UP YOUR ASYNC!"
            )
        logger.debug("executing SQL/command")
        if self.is_closed():
            raise Exception(
                "YICHUAN: Connection closed when attempting to execute with cursor in POC"
            )

        if _do_reset:
            self.reset()
        command = command.strip(" \t\n\r") if command else None
        if not command:
            logger.warning("execute: no query is given to execute")
            return None

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
            if logger.getEffectiveLevel() <= logging.WARNING:
                logger.info(
                    "query was rewritten: org=%s, new=%s",
                    " ".join(line.strip() for line in query.split("\n")),
                    query1,
                )
            query = query1

        if logger.getEffectiveLevel() <= logging.INFO:
            logger.info("query: [%s]", self._format_query_for_log(query))
        ret = await self._execute_helper_async(query, **kwargs)
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
        logger.info("query execution done")

        self._first_chunk_time = get_time_millis()

        # if server gives a send time, log the time it took to arrive
        if "data" in ret and "sendResultTime" in ret["data"]:
            time_consume_first_result = (
                self._first_chunk_time - ret["data"]["sendResultTime"]
            )
            self._log_telemetry_job_data(
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
                raise Exception("YICHUAN: No file transfer for POC")

            if _no_results:
                self._total_rowcount = (
                    ret["data"]["total"]
                    if "data" in ret and "total" in ret["data"]
                    else -1
                )
                return data
            self._init_result_and_meta_USE_ASYNC_RESULT_SET(data)
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

    def _init_result_and_meta_USE_ASYNC_RESULT_SET(self, data: dict[Any, Any]) -> None:
        is_dml = self._is_dml(data)
        self._query_result_format = data.get("queryResultFormat", "json")
        logger.debug("Query result format: %s", self._query_result_format)

        if self._total_rowcount == -1 and not is_dml and data.get("total") is not None:
            self._total_rowcount = data["total"]

        self._description: list[ResultMetadata] = [
            ResultMetadata.from_column(col) for col in data["rowtype"]
        ]

        result_chunks = create_batches_from_response_async_POC(
            self, self._query_result_format, data, self._description
        )

        if not (is_dml or self.is_file_transfer):
            logger.info(
                "Number of results in first chunk: %s", result_chunks[0].rowcount
            )

        self._result_set = ResultSetAsyncPOC(
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
                if desc[0] in (
                    "number of rows updated",
                    "number of multi-joined rows updated",
                    "number of rows deleted",
                ) or desc[0].startswith("number of rows inserted"):
                    updated_rows += int(data["rowset"][0][idx])
            if self._total_rowcount == -1:
                self._total_rowcount = updated_rows
            else:
                self._total_rowcount += updated_rows

    async def _execute_helper_async(
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
                    statement_params[
                        PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT
                    ] = "JSON"

        self._sequence_counter = self._connection._next_sequence_counter()
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

        ret: dict[str, Any] = {"data": {}}
        try:
            ret = await self._connection.cmd_query_async(
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
            )
        finally:
            pass

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
            self._connection._update_parameters(
                {p["name"]: p["value"] for p in parameters}
            )

        self.query = query
        self._sequence_counter = -1
        return ret


class JSONResultBatchAsyncPOC(JSONResultBatchAsync):
    # YICHUAN: create_iter_async creates a list iterator, but we need something that creates an async iterator for POC
    async def create_async_iter_async(
        self, connection: SnowflakeConnection | None = None, **kwargs
    ) -> Iterator[dict | Exception] | Iterator[tuple | Exception]:
        # YICHUAN: DON'T DO THIS, THIS RUINS THE WHOLE POINT OF ASYNC, FOR POC ONLY
        async def list_to_aiter(l):
            for e in l:
                yield e

        if self._local:
            return list_to_aiter(self._data)

        response = await self._download_async(connection=connection)

        # Load data to a intermediate form
        logger.debug(f"started loading result batch id: {self.id}")
        with TimerContextManager() as load_metric:
            downloaded_data = await self._load_async(response)

        logger.debug(f"finished loading result batch id: {self.id}")
        self._metrics[DownloadMetrics.load.value] = load_metric.get_timing_millis()
        # Process downloaded data
        with TimerContextManager() as parse_metric:
            parsed_data = self._parse(downloaded_data)
        self._metrics[DownloadMetrics.parse.value] = parse_metric.get_timing_millis()
        return list_to_aiter(parsed_data)


class ResultSetAsyncPOC(ResultSet):
    async def _create_iter_async(
        self,
        **kwargs,
    ) -> (Iterator[dict | Exception] | Iterator[tuple | Exception]):
        """Set up a new iterator through all batches with first 5 chunks downloaded.

        This function is a helper function to ``__iter__`` and it was introduced for the
        cases where we need to propagate some values to later ``_download`` calls.
        """
        # add connection so that result batches can use sessions
        kwargs["connection"] = self._cursor.connection

        first_batch_iter = await self.batches[0].create_async_iter_async(**kwargs)

        # batches that have not been fetched
        unfetched_batches = deque(self.batches[1:])
        for num, batch in enumerate(unfetched_batches):
            logger.debug(f"result batch {num + 1} has id: {batch.id}")

        return result_set_iterator_async(
            first_batch_iter,
            unfetched_batches,
            **kwargs,
        )


async def result_set_iterator_async(
    first_batch_iter: Iterator[tuple],
    unfetched_batches,
    **kw: Any,
) -> Iterator[dict | Exception] | Iterator[tuple | Exception]:
    async for e in first_batch_iter:
        yield e

    # YICHUAN: This is obviously going to block while trying to fetch every batch, but it's just for POC; when actually
    # implementing we should use asyncio task semantics to get things downloading concurrently
    unconsumed_batches = await asyncio.gather(
        *[b.create_async_iter_async(**kw) for b in unfetched_batches]
    )

    for i in unconsumed_batches:
        async for e in i:
            yield e


def create_batches_from_response_async_POC(
    cursor: SnowflakeCursor,
    _format: str,
    data: dict[str, Any],
    schema: Sequence[ResultMetadata],
) -> list[JSONResultBatchAsyncPOC]:
    rowtypes = data["rowtype"]
    total_len: int = data.get("total", 0)
    first_chunk_len = total_len
    rest_of_chunks: list[JSONResultBatchAsyncPOC] = []
    if _format != "json":
        raise Exception("Non-JSON formats not supported for ResultBatchAsync")

    def col_to_converter(col: dict[str, Any]) -> tuple[str, SnowflakeConverterType]:
        type_name = col["type"].upper()
        python_method = cursor._connection.converter.to_python_method(type_name, col)
        return type_name, python_method

    column_converters = [col_to_converter(c) for c in rowtypes]

    if "chunks" in data:
        chunks = data["chunks"]
        logger.debug(f"chunk size={len(chunks)}")
        # prepare the downloader for further fetch
        qrmk = data.get("qrmk")
        chunk_headers: dict[str, Any] = {}
        if "chunkHeaders" in data:
            chunk_headers = {}
            for header_key, header_value in data["chunkHeaders"].items():
                chunk_headers[header_key] = header_value
                if "encryption" not in header_key:
                    logger.debug(
                        f"added chunk header: key={header_key}, value={header_value}"
                    )
        elif qrmk is not None:
            logger.debug(f"qrmk={SecretDetector.mask_secrets(qrmk)}")
            chunk_headers[SSE_C_ALGORITHM] = SSE_C_AES
            chunk_headers[SSE_C_KEY] = qrmk

        def remote_chunk_info(c: dict[str, Any]) -> RemoteChunkInfo:
            return RemoteChunkInfo(
                url=c["url"],
                uncompressedSize=c["uncompressedSize"],
                compressedSize=c["compressedSize"],
            )

        rest_of_chunks = [
            JSONResultBatchAsyncPOC(
                c["rowCount"],
                chunk_headers,
                remote_chunk_info(c),
                schema,
                column_converters,
                cursor._use_dict_result,
                json_result_force_utf8_decoding=cursor._connection._json_result_force_utf8_decoding,
            )
            for c in chunks
        ]

    for c in rest_of_chunks:
        first_chunk_len -= c.rowcount

    first_chunk = JSONResultBatchAsyncPOC.from_data(
        data.get("rowset"),
        first_chunk_len,
        schema,
        column_converters,
        cursor._use_dict_result,
    )

    return [first_chunk] + rest_of_chunks
