#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations

import asyncio
import atexit
import logging
import os
import pathlib
import sys
import traceback
import uuid
from contextlib import suppress
from logging import getLogger
from typing import Any

from .. import (
    DatabaseError,
    EasyLoggingConfigPython,
    Error,
    OperationalError,
    ProgrammingError,
    proxy,
)
from .._query_context_cache import QueryContextCache
from ..auth import AuthByIdToken
from ..compat import urlencode
from ..config_manager import CONFIG_MANAGER, _get_default_connection_params
from ..connection import DEFAULT_CONFIGURATION
from ..connection import SnowflakeConnection as SnowflakeConnectionSync
from ..connection_diagnostic import ConnectionDiagnostic
from ..constants import (
    ENV_VAR_PARTNER,
    PARAMETER_AUTOCOMMIT,
    PARAMETER_CLIENT_PREFETCH_THREADS,
    PARAMETER_CLIENT_SESSION_KEEP_ALIVE,
    PARAMETER_CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY,
    PARAMETER_CLIENT_TELEMETRY_ENABLED,
    PARAMETER_CLIENT_VALIDATE_DEFAULT_PARAMETERS,
    PARAMETER_ENABLE_STAGE_S3_PRIVATELINK_FOR_US_EAST_1,
    PARAMETER_QUERY_CONTEXT_CACHE_SIZE,
    PARAMETER_SERVICE_NAME,
    PARAMETER_TIMEZONE,
)
from ..description import PLATFORM, PYTHON_VERSION, SNOWFLAKE_CONNECTOR_VERSION
from ..errorcode import (
    ER_CONNECTION_IS_CLOSED,
    ER_FAILED_TO_CONNECT_TO_DB,
    ER_INVALID_VALUE,
)
from ..network import DEFAULT_AUTHENTICATOR, REQUEST_ID, ReauthenticationRequest
from ..sqlstate import SQLSTATE_CONNECTION_NOT_EXISTS
from ..time_util import get_time_millis
from ._cursor import SnowflakeCursor
from ._network import SnowflakeRestful
from .auth import Auth, AuthByDefault, AuthByPlugin

logger = getLogger(__name__)


class SnowflakeConnection(SnowflakeConnectionSync):
    OCSP_ENV_LOCK = asyncio.Lock()

    def __init__(
        self,
        connection_name: str | None = None,
        connections_file_path: pathlib.Path | None = None,
        **kwargs,
    ) -> None:
        # note we don't call super here because asyncio can not/is not recommended
        # to perform async operation in the __init__ while in the sync connection we
        # perform connect
        self._conn_parameters = self._init_connection_parameters(
            kwargs, connection_name, connections_file_path
        )
        self._connected = False
        # TODO: async telemetry support
        self._telemetry = None
        self.expired = False
        # get the imported modules from sys.modules
        # self._log_telemetry_imported_packages() # TODO: async telemetry support
        # check SNOW-1218851 for long term improvement plan to refactor ocsp code
        # atexit.register(self._close_at_exit) # TODO: async atexit support/test

    def _init_connection_parameters(
        self,
        connection_init_kwargs: dict,
        connection_name: str | None = None,
        connections_file_path: pathlib.Path | None = None,
    ) -> dict:
        ret_kwargs = connection_init_kwargs
        easy_logging = EasyLoggingConfigPython()
        easy_logging.create_log()
        self._lock_sequence_counter = asyncio.Lock()
        self.sequence_counter = 0
        self._errorhandler = Error.default_errorhandler
        self._lock_converter = asyncio.Lock()
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
        is_kwargs_empty = not connection_init_kwargs

        if "application" not in connection_init_kwargs:
            if ENV_VAR_PARTNER in os.environ.keys():
                connection_init_kwargs["application"] = os.environ[ENV_VAR_PARTNER]
            elif "streamlit" in sys.modules:
                connection_init_kwargs["application"] = "streamlit"

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
            ret_kwargs = {**connections[connection_name], **connection_init_kwargs}
        elif is_kwargs_empty:
            # connection_name is None and kwargs was empty when called
            ret_kwargs = _get_default_connection_params()
        self.__set_error_attributes()  # TODO: error attributes async?
        return ret_kwargs

    @property
    def client_prefetch_threads(self) -> int:
        # TODO: use client_prefetch_threads as numbers for coroutines? how to communicate to users
        logger.warning("asyncio does not support client_prefetch_threads")
        return self._client_prefetch_threads

    @client_prefetch_threads.setter
    def client_prefetch_threads(self, value) -> None:
        # TODO: use client_prefetch_threads as numbers for coroutines? how to communicate to users
        logger.warning("asyncio does not support client_prefetch_threads")
        self._client_prefetch_threads = value

    @property
    def rest(self) -> SnowflakeRestful | None:
        return self._rest

    async def connect(self) -> None:
        """Establishes connection to Snowflake."""
        logger.debug("connect")
        if len(self._conn_parameters) > 0:
            self.__config(**self._conn_parameters)

        if self.enable_connection_diag:
            exceptions_dict = {}
            # TODO: we can make ConnectionDiagnostic async, do we need?
            connection_diag = ConnectionDiagnostic(
                account=self.account,
                host=self.host,
                connection_diag_log_path=self.connection_diag_log_path,
                connection_diag_allowlist_path=(
                    self.connection_diag_allowlist_path
                    if self.connection_diag_allowlist_path is not None
                    else self.connection_diag_whitelist_path
                ),
                proxy_host=self.proxy_host,
                proxy_port=self.proxy_port,
                proxy_user=self.proxy_user,
                proxy_password=self.proxy_password,
            )
            try:
                connection_diag.run_test()
                await self.__open_connection()
                connection_diag.cursor = self.cursor()
            except Exception:
                exceptions_dict["connection_test"] = traceback.format_exc()
                logger.warning(
                    f"""Exception during connection test:\n{exceptions_dict["connection_test"]} """
                )
            try:
                connection_diag.run_post_test()
            except Exception:
                exceptions_dict["post_test"] = traceback.format_exc()
                logger.warning(
                    f"""Exception during post connection test:\n{exceptions_dict["post_test"]} """
                )
            finally:
                connection_diag.generate_report()
                if exceptions_dict:
                    raise Exception(str(exceptions_dict))
        else:
            await self.__open_connection()

    def _close_at_exit(self):
        with suppress(Exception):
            asyncio.get_event_loop().run_until_complete(self.close(retry=False))

    async def __open_connection(self):
        """Opens a new network connection."""
        self.converter = self._converter_class(
            use_numpy=self._numpy, support_negative_year=self._support_negative_year
        )

        proxy.set_proxies(
            self.proxy_host, self.proxy_port, self.proxy_user, self.proxy_password
        )

        self._rest = SnowflakeRestful(
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

        if ".privatelink.snowflakecomputing." in self.host:
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
            self._session_parameters[PARAMETER_CLIENT_VALIDATE_DEFAULT_PARAMETERS] = (
                True
            )

        if self.client_session_keep_alive is not None:
            self._session_parameters[PARAMETER_CLIENT_SESSION_KEEP_ALIVE] = (
                self._client_session_keep_alive
            )

        if self.client_session_keep_alive_heartbeat_frequency is not None:
            self._session_parameters[
                PARAMETER_CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY
            ] = self._validate_client_session_keep_alive_heartbeat_frequency()

        # TODO: client_prefetch_threads support
        # if self.client_prefetch_threads:
        #     self._session_parameters[PARAMETER_CLIENT_PREFETCH_THREADS] = (
        #         self._validate_client_prefetch_threads()
        #     )

        # Setup authenticator
        auth = Auth(self.rest)

        if self._session_token and self._master_token:
            await auth._rest.update_tokens(
                self._session_token,
                self._master_token,
                self._master_validity_in_seconds,
            )
            heartbeat_ret = await auth._rest._heartbeat()
            logger.debug(heartbeat_ret)
            if not heartbeat_ret or not heartbeat_ret.get("success"):
                # TODO: errorhandler could be async?
                Error.errorhandler_wrapper(
                    self,
                    None,
                    ProgrammingError,
                    {
                        "msg": "Session and master tokens invalid",
                        "errno": ER_INVALID_VALUE,
                    },
                )
            else:
                logger.debug("Session and master token validation successful.")

        else:
            if self.auth_class is not None:
                raise NotImplementedError(
                    "asyncio support for auth_class is not supported"
                )
            elif self._authenticator == DEFAULT_AUTHENTICATOR:
                self.auth_class = AuthByDefault(
                    password=self._password,
                    timeout=self._login_timeout,
                    backoff_generator=self._backoff_generator,
                )
            else:
                raise NotImplementedError(
                    f"asyncio support for authenticator is not supported {self._authenticator}"
                )
            # TODO: asyncio support for other authenticators
            await self.authenticate_with_retry(self.auth_class)

            self._password = None  # ensure password won't persist
            await self.auth_class.reset_secrets()

        self.initialize_query_context_cache()

        if self.client_session_keep_alive:
            # This will be called after the heartbeat frequency has actually been set.
            # By this point it should have been decided if the heartbeat has to be enabled
            # and what would the heartbeat frequency be
            # TODO: implement asyncio heartbeat/timer
            raise NotImplementedError(
                "asyncio client_session_keep_alive is not supported"
            )

    def cursor(
        self, cursor_class: type[SnowflakeCursor] = SnowflakeCursor
    ) -> SnowflakeCursor:
        logger.debug("cursor")
        if not self.rest:
            Error.errorhandler_wrapper(
                self,
                None,
                DatabaseError,
                {
                    "msg": "Connection is closed",
                    "errno": ER_CONNECTION_IS_CLOSED,
                    "sqlstate": SQLSTATE_CONNECTION_NOT_EXISTS,
                },
            )
        return cursor_class(self)

    @property
    def auth_class(self) -> AuthByPlugin | None:
        return self._auth_class

    @auth_class.setter
    def auth_class(self, value: AuthByPlugin) -> None:
        if isinstance(value, AuthByPlugin):
            self._auth_class = value
        else:
            raise TypeError("auth_class must subclass AuthByPluginAsync")

    async def _reauthenticate(self):
        return await self._auth_class.reauthenticate(conn=self)

    async def _update_parameters(
        self,
        parameters: dict[str, str | int | bool],
    ) -> None:
        """Update session parameters."""
        async with self._lock_converter:
            self.converter.set_parameters(parameters)
        for name, value in parameters.items():
            self._session_parameters[name] = value
            if PARAMETER_CLIENT_TELEMETRY_ENABLED == name:
                self.telemetry_enabled = value
            elif PARAMETER_CLIENT_SESSION_KEEP_ALIVE == name:
                # Only set if the local config is None.
                # Always give preference to user config.
                if self.client_session_keep_alive is None:
                    self.client_session_keep_alive = value
            elif (
                PARAMETER_CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY == name
                and self.client_session_keep_alive_heartbeat_frequency is None
            ):
                # Only set if local value hasn't been set already.
                self.client_session_keep_alive_heartbeat_frequency = value
            elif PARAMETER_SERVICE_NAME == name:
                self.service_name = value
            elif PARAMETER_CLIENT_PREFETCH_THREADS == name:
                self.client_prefetch_threads = value
            elif PARAMETER_ENABLE_STAGE_S3_PRIVATELINK_FOR_US_EAST_1 == name:
                self.enable_stage_s3_privatelink_for_us_east_1 = value
            elif PARAMETER_QUERY_CONTEXT_CACHE_SIZE == name:
                self.query_context_cache_size = value

    async def authenticate_with_retry(self, auth_instance) -> None:
        # make some changes if needed before real __authenticate
        try:
            await self._authenticate(auth_instance)
        except ReauthenticationRequest as ex:
            # cached id_token expiration error, we have cleaned id_token and try to authenticate again
            logger.debug("ID token expired. Reauthenticating...: %s", ex)
            if isinstance(auth_instance, AuthByIdToken):
                # Note: SNOW-733835 IDToken auth needs to authenticate through
                #  SSO if it has expired
                await self._reauthenticate()
            else:
                await self._authenticate(auth_instance)

    async def _authenticate(self, auth_instance: AuthByPlugin):
        await auth_instance.prepare(
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

        auth = Auth(self.rest)
        # record start time for computing timeout
        auth_instance._retry_ctx.set_start_time()
        try:
            await auth.authenticate(
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
            logger.debug(
                "Operational Error raised at authentication"
                f"for authenticator: {type(auth_instance).__name__}"
            )
            while True:
                try:
                    await auth_instance.handle_timeout(
                        authenticator=self._authenticator,
                        service_name=self.service_name,
                        account=self.account,
                        user=self.user,
                        password=self._password,
                    )
                    await auth.authenticate(
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
                except OperationalError as auth_op:
                    if auth_op.errno == ER_FAILED_TO_CONNECT_TO_DB:
                        raise auth_op from e
                    logger.debug("Continuing authenticator specific timeout handling")
                    continue
                break

    async def close(self, retry: bool = True) -> None:
        """Closes the connection."""
        # unregister to dereference connection object as it's already closed after the execution
        atexit.unregister(self._close_at_exit)
        try:
            if not self.rest:
                logger.debug("Rest object has been destroyed, cannot close session")
                return

            # will hang if the application doesn't close the connection and
            # CLIENT_SESSION_KEEP_ALIVE is set, because the heartbeat runs on
            # a separate thread.
            # TODO: async heartbeat support
            # self._cancel_heartbeat()

            # close telemetry first, since it needs rest to send remaining data
            logger.info("closed")

            # TODO: async telemetry support
            # self._telemetry.close(send_on_close=retry)
            if (
                self._all_async_queries_finished()
                and not self._server_session_keep_alive
            ):
                logger.info("No async queries seem to be running, deleting session")
                await self.rest.delete_session(retry=retry)
            else:
                logger.info(
                    "There are {} async queries still running, not deleting session".format(
                        len(self._async_sfqids)
                    )
                )
            await self.rest.close()
            self._rest = None
            if self.query_context_cache:
                self.query_context_cache.clear_cache()
            del self.messages[:]
            logger.debug("Session is closed")
        except Exception as e:
            logger.debug(
                "Exception encountered in closing connection. ignoring...: %s", e
            )

    async def cmd_query(
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
        dataframe_ast: str | None = None,
    ) -> dict[str, Any]:
        """Executes a query with a sequence counter."""
        logger.debug("_cmd_query")
        data = {
            "sqlText": sql,
            "asyncExec": _no_results,
            "sequenceId": sequence_counter,
            "querySubmissionTime": get_time_millis(),
        }
        if dataframe_ast is not None:
            data["dataframeAst"] = dataframe_ast
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

        ret = await self.rest.request(
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

    async def _next_sequence_counter(self) -> int:
        """Gets next sequence counter. Used internally."""
        async with self._lock_sequence_counter:
            self.sequence_counter += 1
            logger.debug("sequence counter: %s", self.sequence_counter)
            return self.sequence_counter
