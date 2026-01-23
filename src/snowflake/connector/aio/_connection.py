from __future__ import annotations

import asyncio
import atexit
import copy
import logging
import os
import pathlib
import sys
import typing
import uuid
import warnings
from contextlib import suppress
from io import StringIO
from logging import getLogger
from types import TracebackType
from typing import Any, AsyncIterator, Iterable, TypeVar

from snowflake.connector import (
    DatabaseError,
    EasyLoggingConfigPython,
    Error,
    OperationalError,
    ProgrammingError,
)

from .._query_context_cache import QueryContextCache
from ..compat import IS_LINUX, quote, urlencode
from ..config_manager import CONFIG_MANAGER, _get_default_connection_params
from ..connection import DEFAULT_CONFIGURATION as DEFAULT_CONFIGURATION_SYNC
from ..connection import SnowflakeConnection as SnowflakeConnectionSync
from ..connection import _get_private_bytes_from_file
from ..constants import (
    _CONNECTIVITY_ERR_MSG,
    _OAUTH_DEFAULT_SCOPE,
    PARAMETER_AUTOCOMMIT,
    PARAMETER_CLIENT_PREFETCH_THREADS,
    PARAMETER_CLIENT_REQUEST_MFA_TOKEN,
    PARAMETER_CLIENT_SESSION_KEEP_ALIVE,
    PARAMETER_CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY,
    PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL,
    PARAMETER_CLIENT_TELEMETRY_ENABLED,
    PARAMETER_CLIENT_VALIDATE_DEFAULT_PARAMETERS,
    PARAMETER_ENABLE_STAGE_S3_PRIVATELINK_FOR_US_EAST_1,
    PARAMETER_QUERY_CONTEXT_CACHE_SIZE,
    PARAMETER_SERVICE_NAME,
    PARAMETER_TIMEZONE,
    QueryStatus,
)
from ..description import PLATFORM, PYTHON_VERSION, SNOWFLAKE_CONNECTOR_VERSION
from ..errorcode import (
    ER_CONNECTION_IS_CLOSED,
    ER_FAILED_TO_CONNECT_TO_DB,
    ER_INVALID_VALUE,
    ER_INVALID_WIF_SETTINGS,
)
from ..network import (
    DEFAULT_AUTHENTICATOR,
    EXTERNAL_BROWSER_AUTHENTICATOR,
    KEY_PAIR_AUTHENTICATOR,
    OAUTH_AUTHENTICATOR,
    OAUTH_AUTHORIZATION_CODE,
    OAUTH_CLIENT_CREDENTIALS,
    PAT_WITH_EXTERNAL_SESSION,
    PROGRAMMATIC_ACCESS_TOKEN,
    REQUEST_ID,
    USR_PWD_MFA_AUTHENTICATOR,
    WORKLOAD_IDENTITY_AUTHENTICATOR,
    ReauthenticationRequest,
)
from ..sqlstate import SQLSTATE_CONNECTION_NOT_EXISTS, SQLSTATE_FEATURE_NOT_SUPPORTED
from ..telemetry import TelemetryData, TelemetryField
from ..time_util import get_time_millis
from ..util_text import split_statements
from ..wif_util import AttestationProvider
from ._cursor import SnowflakeCursor, SnowflakeCursorBase
from ._description import CLIENT_NAME
from ._direct_file_operation_utils import FileOperationParser, StreamDownloader
from ._network import SnowflakeRestful
from ._session_manager import (
    AioHttpConfig,
    SessionManager,
    SessionManagerFactory,
    SnowflakeSSLConnectorFactory,
)
from ._telemetry import TelemetryClient
from ._time_util import HeartBeatTimer
from .auth import (
    FIRST_PARTY_AUTHENTICATORS,
    Auth,
    AuthByDefault,
    AuthByIdToken,
    AuthByKeyPair,
    AuthByOAuth,
    AuthByOauthCode,
    AuthByOauthCredentials,
    AuthByOkta,
    AuthByPAT,
    AuthByPlugin,
    AuthByUsrPwdMfa,
    AuthByWebBrowser,
    AuthByWorkloadIdentity,
)

logger = getLogger(__name__)

# deep copy to avoid pollute sync config
DEFAULT_CONFIGURATION = copy.deepcopy(DEFAULT_CONFIGURATION_SYNC)
DEFAULT_CONFIGURATION["application"] = (CLIENT_NAME, (type(None), str))

if sys.version_info >= (3, 13) or typing.TYPE_CHECKING:
    CursorCls = TypeVar("CursorCls", bound=SnowflakeCursorBase, default=SnowflakeCursor)
else:
    CursorCls = TypeVar("CursorCls", bound=SnowflakeCursorBase)


class SnowflakeConnection(SnowflakeConnectionSync):
    OCSP_ENV_LOCK = asyncio.Lock()

    def __init__(
        self,
        connection_name: str | None = None,
        connections_file_path: pathlib.Path | None = None,
        **kwargs,
    ) -> None:
        """Create a new SnowflakeConnection.

        Connections can be loaded from the TOML file located at
        snowflake.connector.constants.CONNECTIONS_FILE.

        When connection_name is supplied we will first load that connection
        and then override any other values supplied.

        When no arguments are given (other than connection_file_path) the
        default connection will be loaded first. Note that no overwriting is
        supported in this case.

        If overwriting values from the default connection is desirable, supply
        the name explicitly.
        """
        # note we don't call super here because asyncio can not/is not recommended
        # to perform async operation in the __init__ while in the sync connection we
        # perform connect

        self._conn_parameters = self._init_connection_parameters(
            kwargs, connection_name, connections_file_path
        )
        # SNOW-2352456: disable endpoint-based platform detection queries for async connection
        if "platform_detection_timeout_seconds" not in kwargs:
            self._platform_detection_timeout_seconds = 0.0

        self.expired = False
        # check SNOW-1218851 for long term improvement plan to refactor ocsp code
        atexit.register(self._close_at_exit)

        # Set up the file operation parser and stream downloader.
        self._file_operation_parser = FileOperationParser(self)
        self._stream_downloader = StreamDownloader(self)
        self._snowflake_version: str | None = None

        # CRL is disabled for async connection
        self._crl_config = None  # default value = disabled

    @property
    async def snowflake_version(self) -> str:
        # The result from SELECT CURRENT_VERSION() is `<version> <internal hash>`,
        # and we only need the first part
        if self._snowflake_version is None:
            self._snowflake_version = str(
                (
                    await (
                        await self.cursor().execute("SELECT CURRENT_VERSION()")
                    ).fetchall()
                )[0][0]
            ).split(" ")[0]

        return self._snowflake_version

    def __enter__(self):
        # async connection does not support sync context manager
        raise TypeError(
            "'SnowflakeConnection' object does not support the context manager protocol"
        )

    def __exit__(self, exc_type, exc_val, exc_tb):
        # async connection does not support sync context manager
        raise TypeError(
            "'SnowflakeConnection' object does not support the context manager protocol"
        )

    async def __aenter__(self) -> SnowflakeConnection:
        """Context manager."""
        # Idempotent __aenter__ - required to be able to use both:
        #   - with snowflake.connector.aio.SnowflakeConnection(**k)
        #   - with snowflake.connector.aio.connect(**k)
        if self.is_closed():
            await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager with commit or rollback teardown."""
        if not self._session_parameters.get("AUTOCOMMIT", False):
            # Either AUTOCOMMIT is turned off, or is not set so we default to old behavior
            if exc_tb is None:
                await self.commit()
            else:
                await self.rollback()
        await self.close()

    async def __open_connection(self):
        """Opens a new network connection."""
        self.converter = self._converter_class(
            use_numpy=self._numpy, support_negative_year=self._support_negative_year
        )

        self._rest = SnowflakeRestful(
            host=self.host,
            port=self.port,
            protocol=self._protocol,
            inject_client_pause=self._inject_client_pause,
            connection=self,
            session_manager=self._session_manager,  # connection shares the session pool used for making Backend related requests
        )
        logger.debug("REST API object was created: %s:%s", self.host, self.port)

        if "SF_OCSP_RESPONSE_CACHE_SERVER_URL" in os.environ:
            logger.debug(
                "Custom OCSP Cache Server URL found in environment - %s",
                os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"],
            )

        if ".privatelink.snowflakecomputing." in self.host.lower():
            await SnowflakeConnection.setup_ocsp_privatelink(
                self.application, self.host
            )
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

        if self.client_prefetch_threads:
            self._session_parameters[PARAMETER_CLIENT_PREFETCH_THREADS] = (
                self._validate_client_prefetch_threads()
            )

        # Setup authenticator - validation happens in __config
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
                if type(
                    self.auth_class
                ) not in FIRST_PARTY_AUTHENTICATORS and not issubclass(
                    type(self.auth_class), AuthByKeyPair
                ):
                    raise TypeError("auth_class must be a child class of AuthByKeyPair")
                self.auth_class = self.auth_class
            elif self._authenticator == DEFAULT_AUTHENTICATOR:
                self.auth_class = AuthByDefault(
                    password=self._password,
                    timeout=self.login_timeout,
                    backoff_generator=self._backoff_generator,
                )
            elif self._authenticator == EXTERNAL_BROWSER_AUTHENTICATOR:
                self._session_parameters[
                    PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL
                ] = (self._client_store_temporary_credential if IS_LINUX else True)
                auth.read_temporary_credentials(
                    self.host,
                    self.user,
                    self._session_parameters,
                )
                # Depending on whether self._rest.id_token is available we do different
                #  auth_instance
                if self._rest.id_token is None:
                    self.auth_class = AuthByWebBrowser(
                        application=self.application,
                        protocol=self._protocol,
                        host=self.host,
                        port=self.port,
                        timeout=self.login_timeout,
                        backoff_generator=self._backoff_generator,
                    )
                else:
                    self.auth_class = AuthByIdToken(
                        id_token=self._rest.id_token,
                        application=self.application,
                        protocol=self._protocol,
                        host=self.host,
                        port=self.port,
                        timeout=self.login_timeout,
                        backoff_generator=self._backoff_generator,
                    )

            elif self._authenticator == KEY_PAIR_AUTHENTICATOR:
                private_key = self._private_key
                private_key_passphrase = self._private_key_passphrase

                if self._private_key_file:
                    private_key = _get_private_bytes_from_file(
                        self._private_key_file,
                        self._private_key_file_pwd,
                    )

                self.auth_class = AuthByKeyPair(
                    private_key=private_key,
                    private_key_passphrase=private_key_passphrase,
                    timeout=self.login_timeout,
                    backoff_generator=self._backoff_generator,
                )
            elif self._authenticator == OAUTH_AUTHENTICATOR:
                self.auth_class = AuthByOAuth(
                    oauth_token=self._token,
                    timeout=self.login_timeout,
                    backoff_generator=self._backoff_generator,
                )
            elif self._authenticator == OAUTH_AUTHORIZATION_CODE:
                if self._role and (self._oauth_scope == ""):
                    # if role is known then let's inject it into scope
                    self._oauth_scope = _OAUTH_DEFAULT_SCOPE.format(role=self._role)
                self.auth_class = AuthByOauthCode(
                    application=self.application,
                    client_id=self._oauth_client_id,
                    client_secret=self._oauth_client_secret,
                    host=self.host,
                    authentication_url=self._oauth_authorization_url.format(
                        host=self.host, port=self.port
                    ),
                    token_request_url=self._oauth_token_request_url.format(
                        host=self.host, port=self.port
                    ),
                    redirect_uri=self._oauth_redirect_uri,
                    uri=self._oauth_socket_uri,
                    scope=self._oauth_scope,
                    pkce_enabled=not self._oauth_disable_pkce,
                    token_cache=(
                        auth.get_token_cache()
                        if self._client_store_temporary_credential
                        else None
                    ),
                    refresh_token_enabled=self._oauth_enable_refresh_tokens,
                    external_browser_timeout=self._external_browser_timeout,
                    enable_single_use_refresh_tokens=self._oauth_enable_single_use_refresh_tokens,
                )
            elif self._authenticator == OAUTH_CLIENT_CREDENTIALS:
                if self._role and (self._oauth_scope == ""):
                    # if role is known then let's inject it into scope
                    self._oauth_scope = _OAUTH_DEFAULT_SCOPE.format(role=self._role)
                self.auth_class = AuthByOauthCredentials(
                    application=self.application,
                    client_id=self._oauth_client_id,
                    client_secret=self._oauth_client_secret,
                    token_request_url=self._oauth_token_request_url.format(
                        host=self.host, port=self.port
                    ),
                    scope=self._oauth_scope,
                    connection=self,
                    credentials_in_body=self._oauth_credentials_in_body,
                )
            elif self._authenticator == PROGRAMMATIC_ACCESS_TOKEN:
                self.auth_class = AuthByPAT(self._token)
            elif self._authenticator == PAT_WITH_EXTERNAL_SESSION:
                # TODO: SNOW-2344581: add support for PAT with external session ID for async connection
                raise ProgrammingError(
                    msg="PAT with external session ID is not supported for async connection.",
                    errno=ER_INVALID_VALUE,
                )
            elif self._authenticator == USR_PWD_MFA_AUTHENTICATOR:
                self._session_parameters[PARAMETER_CLIENT_REQUEST_MFA_TOKEN] = (
                    self._client_request_mfa_token if IS_LINUX else True
                )
                if self._session_parameters[PARAMETER_CLIENT_REQUEST_MFA_TOKEN]:
                    auth.read_temporary_credentials(
                        self.host,
                        self.user,
                        self._session_parameters,
                    )
                self.auth_class = AuthByUsrPwdMfa(
                    password=self._password,
                    mfa_token=self.rest.mfa_token,
                    timeout=self.login_timeout,
                    backoff_generator=self._backoff_generator,
                )
            elif self._authenticator == WORKLOAD_IDENTITY_AUTHENTICATOR:
                if isinstance(self._workload_identity_provider, str):
                    self._workload_identity_provider = AttestationProvider.from_string(
                        self._workload_identity_provider
                    )
                if not self._workload_identity_provider:
                    Error.errorhandler_wrapper(
                        self,
                        None,
                        ProgrammingError,
                        {
                            "msg": f"workload_identity_provider must be set to one of {','.join(AttestationProvider.all_string_values())} when authenticator is WORKLOAD_IDENTITY.",
                            "errno": ER_INVALID_WIF_SETTINGS,
                        },
                    )
                if (
                    self._workload_identity_impersonation_path
                    and self._workload_identity_provider
                    not in (
                        AttestationProvider.GCP,
                        AttestationProvider.AWS,
                    )
                ):
                    Error.errorhandler_wrapper(
                        self,
                        None,
                        ProgrammingError,
                        {
                            "msg": "workload_identity_impersonation_path is currently only supported for GCP and AWS.",
                            "errno": ER_INVALID_WIF_SETTINGS,
                        },
                    )
                self.auth_class = AuthByWorkloadIdentity(
                    provider=self._workload_identity_provider,
                    token=self._token,
                    entra_resource=self._workload_identity_entra_resource,
                    impersonation_path=self._workload_identity_impersonation_path,
                )
            else:
                # okta URL, e.g., https://<account>.okta.com/
                self.auth_class = AuthByOkta(
                    application=self.application,
                    timeout=self.login_timeout,
                    backoff_generator=self._backoff_generator,
                )

            await self.authenticate_with_retry(self.auth_class)

            self._password = None  # ensure password won't persist
            await self.auth_class.reset_secrets()

        self.initialize_query_context_cache()

        if self.client_session_keep_alive:
            # This will be called after the heartbeat frequency has actually been set.
            # By this point it should have been decided if the heartbeat has to be enabled
            # and what would the heartbeat frequency be
            await self._add_heartbeat()

    async def _add_heartbeat(self) -> None:
        """Add a periodic heartbeat query in order to keep connection alive."""
        if not self._heartbeat_task:
            self._heartbeat_task = HeartBeatTimer(
                self.client_session_keep_alive_heartbeat_frequency, self._heartbeat_tick
            )
        await self._heartbeat_task.start()
        logger.debug("started heartbeat")

    async def _heartbeat_tick(self) -> None:
        """Execute a heartbeat if connection isn't closed yet."""
        if not self.is_closed():
            logger.debug("heartbeating!")
            await self.rest._heartbeat()

    async def _all_async_queries_finished(self) -> bool:
        """Checks whether all async queries started by this Connection have finished executing."""

        if not self._async_sfqids:
            return True

        queries = list(reversed(self._async_sfqids.keys()))

        found_unfinished_query = False

        async def async_query_check_helper(
            sfq_id: str,
        ) -> bool:
            try:
                nonlocal found_unfinished_query
                return found_unfinished_query or self.is_still_running(
                    await self.get_query_status(sfq_id)
                )
            except asyncio.CancelledError:
                pass

        tasks = [
            asyncio.create_task(async_query_check_helper(sfqid)) for sfqid in queries
        ]
        for task in asyncio.as_completed(tasks):
            if await task:
                found_unfinished_query = True
                break
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks)
        return not found_unfinished_query

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
                        if _CONNECTIVITY_ERR_MSG in e.msg:
                            auth_op.msg += f"\n{_CONNECTIVITY_ERR_MSG}"
                        raise auth_op from e
                    logger.debug("Continuing authenticator specific timeout handling")
                    continue
                break

    async def _cancel_heartbeat(self) -> None:
        """Cancel a heartbeat thread."""
        if self._heartbeat_task:
            await self._heartbeat_task.stop()
            self._heartbeat_task = None
            logger.debug("stopped heartbeat")

    def _init_connection_parameters(
        self,
        connection_init_kwargs: dict,
        connection_name: str | None = None,
        connections_file_path: pathlib.Path | None = None,
    ) -> dict:
        ret_kwargs = connection_init_kwargs
        self._unsafe_skip_file_permissions_check = ret_kwargs.get(
            "unsafe_skip_file_permissions_check", False
        )
        easy_logging = EasyLoggingConfigPython(
            skip_config_file_permissions_check=self._unsafe_skip_file_permissions_check
        )
        easy_logging.create_log()
        self._lock_sequence_counter = asyncio.Lock()
        self.sequence_counter = 0
        self._errorhandler = Error.default_errorhandler
        self._lock_converter = asyncio.Lock()
        self.messages = []
        self._async_sfqids: dict[str, None] = {}
        self._done_async_sfqids: dict[str, None] = {}
        self._client_param_telemetry_enabled = True
        self._server_param_telemetry_enabled = False
        self._session_parameters: dict[str, str | int | bool] = {}
        logger.info(
            "Snowflake Connector for Python Version: %s, "
            "Python Version: %s, Platform: %s",
            SNOWFLAKE_CONNECTOR_VERSION,
            PYTHON_VERSION,
            PLATFORM,
        )

        # Placeholder attributes; will be initialized in connect()
        self._http_config: AioHttpConfig | None = None
        self._session_manager: SessionManager | None = None
        self._rest = None
        for name, (value, _) in DEFAULT_CONFIGURATION.items():
            setattr(self, f"_{name}", value)

        self._heartbeat_task = None
        is_kwargs_empty = not connection_init_kwargs

        if "application" not in connection_init_kwargs:
            app = self._detect_application()
            if app:
                connection_init_kwargs["application"] = app

        if "insecure_mode" in connection_init_kwargs:
            warn_message = "The 'insecure_mode' connection property is deprecated. Please use 'disable_ocsp_checks' instead"
            warnings.warn(
                warn_message,
                DeprecationWarning,
                stacklevel=2,
            )

            if (
                "disable_ocsp_checks" in connection_init_kwargs
                and connection_init_kwargs["disable_ocsp_checks"]
                != connection_init_kwargs["insecure_mode"]
            ):
                logger.warning(
                    "The values for 'disable_ocsp_checks' and 'insecure_mode' differ. "
                    "Using the value of 'disable_ocsp_checks."
                )
            else:
                self._disable_ocsp_checks = connection_init_kwargs["insecure_mode"]

        self.converter = None
        self.query_context_cache: QueryContextCache | None = None
        self.query_context_cache_size = 5
        if connections_file_path is not None:
            # Change config file path and force update cache
            for i, s in enumerate(CONFIG_MANAGER._slices):
                if s.section == "connections":
                    CONFIG_MANAGER._slices[i] = s._replace(path=connections_file_path)
                    CONFIG_MANAGER.read_config(
                        skip_file_permissions_check=self._unsafe_skip_file_permissions_check
                    )
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
        # TODO: SNOW-1770153 on self.__set_error_attributes()
        return ret_kwargs

    async def _cancel_query(
        self, sql: str, request_id: uuid.UUID
    ) -> dict[str, bool | None]:
        """Cancels the query with the exact SQL query and requestId."""
        logger.debug("_cancel_query sql=[%s], request_id=[%s]", sql, request_id)
        url_parameters = {REQUEST_ID: str(uuid.uuid4())}

        return await self.rest.request(
            "/queries/v1/abort-request?" + urlencode(url_parameters),
            {
                "sqlText": sql,
                REQUEST_ID: str(request_id),
            },
        )

    def _close_at_exit(self):
        with suppress(Exception):
            asyncio.run(self.close(retry=False))

    async def _get_query_status(
        self, sf_qid: str
    ) -> tuple[QueryStatus, dict[str, Any]]:
        """Retrieves the status of query with sf_qid and returns it with the raw response.

        This is the underlying function used by the public get_status functions.

        Args:
            sf_qid: Snowflake query id of interest.

        Raises:
            ValueError: if sf_qid is not a valid UUID string.
        """
        try:
            uuid.UUID(sf_qid)
        except ValueError:
            raise ValueError(f"Invalid UUID: '{sf_qid}'")
        logger.debug(f"get_query_status sf_qid='{sf_qid}'")

        status = "NO_DATA"
        if self.is_closed():
            return QueryStatus.DISCONNECTED, {"data": {"queries": []}}
        status_resp = await self.rest.request(
            "/monitoring/queries/" + quote(sf_qid), method="get", client="rest"
        )
        if "queries" not in status_resp["data"]:
            return QueryStatus.FAILED_WITH_ERROR, status_resp
        queries = status_resp["data"]["queries"]
        if len(queries) > 0:
            status = queries[0]["status"]
        status_ret = QueryStatus[status]
        return status_ret, status_resp

    async def _log_telemetry(self, telemetry_data) -> None:
        if self.telemetry_enabled:
            await self._telemetry.try_add_log_to_batch(telemetry_data)

    async def _log_telemetry_imported_packages(self) -> None:
        if self._log_imported_packages_in_telemetry:
            # filter out duplicates caused by submodules
            # and internal modules with names starting with an underscore
            imported_modules = {
                k.split(".", maxsplit=1)[0]
                for k in list(sys.modules)
                if not k.startswith("_")
            }
            ts = get_time_millis()
            await self._log_telemetry(
                TelemetryData.from_telemetry_data_dict(
                    from_dict={
                        TelemetryField.KEY_TYPE.value: TelemetryField.IMPORTED_PACKAGES.value,
                        TelemetryField.KEY_VALUE.value: str(imported_modules),
                    },
                    timestamp=ts,
                    connection=self,
                )
            )

    async def _next_sequence_counter(self) -> int:
        """Gets next sequence counter. Used internally."""
        async with self._lock_sequence_counter:
            self.sequence_counter += 1
            logger.debug("sequence counter: %s", self.sequence_counter)
            return self.sequence_counter

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
                self._server_param_telemetry_enabled = value
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

    async def _reauthenticate(self):
        return await self._auth_class.reauthenticate(conn=self)

    @property
    def auth_class(self) -> AuthByPlugin | None:
        return self._auth_class

    @auth_class.setter
    def auth_class(self, value: AuthByPlugin) -> None:
        if isinstance(value, AuthByPlugin):
            self._auth_class = value
        else:
            raise TypeError("auth_class must subclass AuthByPluginAsync")

    @property
    def client_prefetch_threads(self) -> int:
        return self._client_prefetch_threads

    @client_prefetch_threads.setter
    def client_prefetch_threads(self, value) -> None:
        self._client_prefetch_threads = value

    @property
    def errorhandler(self) -> None:
        # check SNOW-1763103
        raise NotImplementedError(
            "Async Snowflake Python Connector does not support errorhandler. "
            "Please open a feature request issue in github if your want this feature: "
            "https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose."
        )

    @errorhandler.setter
    def errorhandler(self, value) -> None:
        # check SNOW-1763103
        raise NotImplementedError(
            "Async Snowflake Python Connector does not support errorhandler. "
            "Please open a feature request issue in github if your want this feature: "
            "https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose."
        )

    @property
    def rest(self) -> SnowflakeRestful | None:
        return self._rest

    async def authenticate_with_retry(self, auth_instance) -> None:
        # make some changes if needed before real __authenticate
        try:
            await self._authenticate(auth_instance)
        except ReauthenticationRequest as ex:
            # cached id_token expiration error, we have cleaned id_token and try to authenticate again
            logger.debug("ID token expired. Reauthenticating...: %s", ex)
            if type(auth_instance) in (
                AuthByIdToken,
                AuthByOauthCode,
                AuthByOauthCredentials,
            ):
                # Note: SNOW-733835 IDToken auth needs to authenticate through
                #  SSO if it has expired
                await self._reauthenticate()
            else:
                await self._authenticate(auth_instance)

    async def autocommit(self, mode) -> None:
        """Sets autocommit mode to True, or False. Defaults to True."""
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
        if not isinstance(mode, bool):
            Error.errorhandler_wrapper(
                self,
                None,
                ProgrammingError,
                {
                    "msg": f"Invalid parameter: {mode}",
                    "errno": ER_INVALID_VALUE,
                },
            )
        try:
            await self.cursor().execute(f"ALTER SESSION SET autocommit={mode}")
        except Error as e:
            if e.sqlstate == SQLSTATE_FEATURE_NOT_SUPPORTED:
                logger.debug(
                    "Autocommit feature is not enabled for this " "connection. Ignored"
                )

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
            await self._cancel_heartbeat()

            # close telemetry first, since it needs rest to send remaining data
            logger.debug("closed")

            if self.telemetry_enabled:
                await self._telemetry.close(retry=retry)

            if not self._server_session_keep_alive:
                if await self._all_async_queries_finished():
                    logger.debug(
                        "No async queries seem to be running, deleting session"
                    )
                    try:
                        await self.rest.delete_session(retry=retry)
                    except Exception as e:
                        logger.debug(
                            "Exception encountered in deleting session. ignoring...: %s",
                            e,
                        )
                else:
                    logger.debug(
                        "There are {} async queries still running, not deleting session".format(
                            len(self._async_sfqids)
                        )
                    )
            else:
                logger.info(
                    "Parameter server_session_keep_alive was set to True - skipping session logout. "
                    "If there are any not-finished queries in the current session (session_id: %s) - "
                    "they will continue to live in Snowflake and consume credits until they finish. "
                    "To cancel them use Monitoring tab in Snowsight or plain SQL.",
                    self.session_id,
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

    async def commit(self) -> None:
        """Commits the current transaction."""
        await self.cursor().execute("COMMIT")

    async def connect(self, **kwargs) -> None:
        """Establishes connection to Snowflake."""
        logger.debug("connect")
        if len(kwargs) > 0:
            self.__config(**kwargs)
        else:
            self.__config(**self._conn_parameters)

        no_proxy_csv_str = (
            ",".join(str(x) for x in self.no_proxy)
            if (
                self.no_proxy is not None
                and isinstance(self.no_proxy, Iterable)
                and not isinstance(self.no_proxy, (str, bytes))
            )
            else self.no_proxy
        )
        self._http_config: AioHttpConfig = AioHttpConfig(
            connector_factory=SnowflakeSSLConnectorFactory(),
            use_pooling=not self.disable_request_pooling,
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
            proxy_user=self.proxy_user,
            proxy_password=self.proxy_password,
            snowflake_ocsp_mode=self._ocsp_mode(),
            trust_env=True,  # Required for proxy support via environment variables
            no_proxy=no_proxy_csv_str,
        )
        self._session_manager = SessionManagerFactory.get_manager(self._http_config)

        if self.enable_connection_diag:
            raise NotImplementedError(
                "Connection diagnostic is not supported in asyncio"
            )
        else:
            await self.__open_connection()
        self._telemetry = TelemetryClient(self._rest)
        await self._log_telemetry_imported_packages()

    def cursor(self, cursor_class: type[CursorCls] = SnowflakeCursor) -> CursorCls:
        logger.debug("cursor")
        if not self.rest:
            Error.errorhandler_wrapper(
                self,
                None,
                DatabaseError,
                {
                    "msg": "Connection is closed.\nPlease establish the connection first by "
                    "explicitly calling `await SnowflakeConnection.connect()` or "
                    "using an async context manager: `async with SnowflakeConnection() as conn`. "
                    "\nEnsure the connection is open before attempting any operations.",
                    "errno": ER_CONNECTION_IS_CLOSED,
                    "sqlstate": SQLSTATE_CONNECTION_NOT_EXISTS,
                },
            )
        return cursor_class(self)

    async def execute_stream(
        self,
        stream: StringIO,
        remove_comments: bool = False,
        cursor_class: type[SnowflakeCursor] = SnowflakeCursor,
        **kwargs,
    ) -> AsyncIterator[SnowflakeCursor, None, None]:
        """Executes a stream of SQL statements. This is a non-standard convenient method."""
        split_statements_list = split_statements(
            stream, remove_comments=remove_comments
        )
        # Note: split_statements_list is a list of tuples of sql statements and whether they are put/get
        non_empty_statements = [e for e in split_statements_list if e[0]]
        for sql, is_put_or_get in non_empty_statements:
            cur = self.cursor(cursor_class=cursor_class)
            await cur.execute(sql, _is_put_get=is_put_or_get, **kwargs)
            yield cur

    async def execute_string(
        self,
        sql_text: str,
        remove_comments: bool = False,
        return_cursors: bool = True,
        cursor_class: type[SnowflakeCursor] = SnowflakeCursor,
        **kwargs,
    ) -> Iterable[SnowflakeCursor]:
        """Executes a SQL text including multiple statements. This is a non-standard convenience method."""
        stream = StringIO(sql_text)
        ret = []
        async for cursor in self.execute_stream(
            stream, remove_comments=remove_comments, cursor_class=cursor_class, **kwargs
        ):
            ret.append(cursor)

        return ret if return_cursors else list()

    async def get_query_status(self, sf_qid: str) -> QueryStatus:
        """Retrieves the status of query with sf_qid.

        Query status is returned as a QueryStatus.

        Args:
            sf_qid: Snowflake query id of interest.

        Raises:
            ValueError: if sf_qid is not a valid UUID string.
        """
        status, _ = await self._get_query_status(sf_qid)
        self._cache_query_status(sf_qid, status)
        return status

    async def get_query_status_throw_if_error(self, sf_qid: str) -> QueryStatus:
        """Retrieves the status of query with sf_qid as a QueryStatus and raises an exception if the query terminated with an error.

        Query status is returned as a QueryStatus.

        Args:
            sf_qid: Snowflake query id of interest.

        Raises:
            ValueError: if sf_qid is not a valid UUID string.
        """
        status, status_resp = await self._get_query_status(sf_qid)
        self._cache_query_status(sf_qid, status)
        if self.is_an_error(status):
            self._process_error_query_status(sf_qid, status_resp)
        return status

    @staticmethod
    async def setup_ocsp_privatelink(app, hostname) -> None:
        hostname = hostname.lower()
        async with SnowflakeConnection.OCSP_ENV_LOCK:
            ocsp_cache_server = f"http://ocsp.{hostname}/ocsp_response_cache.json"
            os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"] = ocsp_cache_server
            logger.debug("OCSP Cache Server is updated: %s", ocsp_cache_server)

    async def rollback(self) -> None:
        """Rolls back the current transaction."""
        await self.cursor().execute("ROLLBACK")

    async def is_valid(self) -> bool:
        """This function tries to answer the question: Is this connection still good for sending queries?
        Attempts to validate the connections both on the TCP/IP and Session levels."""
        logger.debug("validating connection and session")
        if self.is_closed():
            logger.debug("connection is already closed and not valid")
            return False

        try:
            logger.debug("trying to heartbeat into the session to validate")
            hb_result = await self.rest._heartbeat()
            session_valid = hb_result.get("success")
            logger.debug("session still valid? %s", session_valid)
            return bool(session_valid)
        except Exception as e:
            logger.debug("session could not be validated due to exception: %s", e)
            return False
