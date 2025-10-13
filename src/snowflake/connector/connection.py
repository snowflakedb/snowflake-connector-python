#!/usr/bin/env python
from __future__ import annotations

import atexit
import logging
import os
import pathlib
import re
import sys
import traceback
import typing
import uuid
import warnings
import weakref
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from contextlib import suppress
from difflib import get_close_matches
from functools import cached_property, partial
from io import StringIO
from logging import getLogger
from threading import Lock
from types import TracebackType
from typing import (
    Any,
    Callable,
    Generator,
    Iterable,
    Iterator,
    NamedTuple,
    Sequence,
    TypeVar,
)
from uuid import UUID

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from . import errors
from ._query_context_cache import QueryContextCache
from ._utils import (
    _DEFAULT_VALUE_SERVER_DOP_CAP_FOR_FILE_TRANSFER,
    _VARIABLE_NAME_SERVER_DOP_CAP_FOR_FILE_TRANSFER,
)
from .auth import (
    FIRST_PARTY_AUTHENTICATORS,
    Auth,
    AuthByDefault,
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
    AuthNoAuth,
)
from .auth.idtoken import AuthByIdToken
from .backoff_policies import exponential_backoff
from .bind_upload_agent import BindUploadError
from .compat import IS_LINUX, IS_WINDOWS, quote, urlencode
from .config_manager import CONFIG_MANAGER, _get_default_connection_params
from .connection_diagnostic import ConnectionDiagnostic
from .constants import (
    _CONNECTIVITY_ERR_MSG,
    _DOMAIN_NAME_MAP,
    _OAUTH_DEFAULT_SCOPE,
    ENV_VAR_PARTNER,
    OCSP_ROOT_CERTS_DICT_LOCK_TIMEOUT_DEFAULT_NO_TIMEOUT,
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
    OCSPMode,
    QueryStatus,
)
from .converter import SnowflakeConverter
from .crl import CRLConfig
from .cursor import LOG_MAX_QUERY_LENGTH, SnowflakeCursor, SnowflakeCursorBase
from .description import (
    CLIENT_NAME,
    CLIENT_VERSION,
    PLATFORM,
    PYTHON_VERSION,
    SNOWFLAKE_CONNECTOR_VERSION,
)
from .direct_file_operation_utils import FileOperationParser, StreamDownloader
from .errorcode import (
    ER_CONNECTION_IS_CLOSED,
    ER_FAILED_PROCESSING_PYFORMAT,
    ER_FAILED_PROCESSING_QMARK,
    ER_FAILED_TO_CONNECT_TO_DB,
    ER_INVALID_BACKOFF_POLICY,
    ER_INVALID_VALUE,
    ER_INVALID_WIF_SETTINGS,
    ER_NO_ACCOUNT_NAME,
    ER_NO_NUMPY,
    ER_NO_PASSWORD,
    ER_NO_USER,
    ER_NOT_IMPLICITY_SNOWFLAKE_DATATYPE,
)
from .errors import DatabaseError, Error, OperationalError, ProgrammingError
from .log_configuration import EasyLoggingConfigPython
from .network import (
    DEFAULT_AUTHENTICATOR,
    EXTERNAL_BROWSER_AUTHENTICATOR,
    KEY_PAIR_AUTHENTICATOR,
    NO_AUTH_AUTHENTICATOR,
    OAUTH_AUTHENTICATOR,
    OAUTH_AUTHORIZATION_CODE,
    OAUTH_CLIENT_CREDENTIALS,
    PAT_WITH_EXTERNAL_SESSION,
    PROGRAMMATIC_ACCESS_TOKEN,
    REQUEST_ID,
    USR_PWD_MFA_AUTHENTICATOR,
    WORKLOAD_IDENTITY_AUTHENTICATOR,
    ReauthenticationRequest,
    SnowflakeRestful,
)
from .session_manager import HttpConfig, ProxySupportAdapterFactory, SessionManager
from .sqlstate import SQLSTATE_CONNECTION_NOT_EXISTS, SQLSTATE_FEATURE_NOT_SUPPORTED
from .telemetry import TelemetryClient, TelemetryData, TelemetryField
from .time_util import HeartBeatTimer, get_time_millis
from .url_util import extract_top_level_domain_from_hostname
from .util_text import construct_hostname, parse_account, split_statements
from .wif_util import AttestationProvider

if sys.version_info >= (3, 13) or typing.TYPE_CHECKING:
    CursorCls = TypeVar("CursorCls", bound=SnowflakeCursorBase, default=SnowflakeCursor)
else:
    CursorCls = TypeVar("CursorCls", bound=SnowflakeCursorBase)

DEFAULT_CLIENT_PREFETCH_THREADS = 4
MAX_CLIENT_PREFETCH_THREADS = 10
MAX_CLIENT_FETCH_THREADS = 1024
DEFAULT_BACKOFF_POLICY = exponential_backoff()


def DefaultConverterClass() -> type:
    if IS_WINDOWS:
        from .converter_issue23517 import SnowflakeConverterIssue23517

        return SnowflakeConverterIssue23517
    else:
        from .converter import SnowflakeConverter

        return SnowflakeConverter


def _get_private_bytes_from_file(
    private_key_file: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    private_key_file_pwd: bytes | str | None = None,
) -> bytes:
    if private_key_file_pwd is not None and isinstance(private_key_file_pwd, str):
        private_key_file_pwd = private_key_file_pwd.encode("utf-8")
    with open(private_key_file, "rb") as key:
        private_key = serialization.load_pem_private_key(
            key.read(),
            password=private_key_file_pwd,
            backend=default_backend(),
        )

    pkb = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return pkb


SUPPORTED_PARAMSTYLES = {
    "qmark",
    "numeric",
    "format",
    "pyformat",
}
# Default configs, tuple of default variable and accepted types
DEFAULT_CONFIGURATION: dict[str, tuple[Any, type | tuple[type, ...]]] = {
    "dsn": (None, (type(None), str)),  # standard
    "user": ("", str),  # standard
    "password": ("", str),  # standard
    "host": ("127.0.0.1", str),  # standard
    "port": (443, (int, str)),  # standard
    "database": (None, (type(None), str)),  # standard
    "proxy_host": (None, (type(None), str)),  # snowflake
    "proxy_port": (None, (type(None), str)),  # snowflake
    "proxy_user": (None, (type(None), str)),  # snowflake
    "proxy_password": (None, (type(None), str)),  # snowflake
    "protocol": ("https", str),  # snowflake
    "warehouse": (None, (type(None), str)),  # snowflake
    "region": (None, (type(None), str)),  # snowflake
    "account": (None, (type(None), str)),  # snowflake
    "schema": (None, (type(None), str)),  # snowflake
    "role": (None, (type(None), str)),  # snowflake
    "session_id": (None, (type(None), str)),  # snowflake
    "login_timeout": (None, (type(None), int)),  # login timeout
    "network_timeout": (
        None,
        (type(None), int),
    ),  # network timeout (infinite by default)
    "socket_timeout": (None, (type(None), int)),
    "external_browser_timeout": (120, int),
    "platform_detection_timeout_seconds": (
        None,
        (type(None), float),
    ),  # Platform detection timeout for CSP metadata endpoints
    "backoff_policy": (DEFAULT_BACKOFF_POLICY, Callable),
    "passcode_in_password": (False, bool),  # Snowflake MFA
    "passcode": (None, (type(None), str)),  # Snowflake MFA
    "private_key": (None, (type(None), bytes, str, RSAPrivateKey)),
    "private_key_file": (None, (type(None), str)),
    "private_key_file_pwd": (None, (type(None), str, bytes)),
    "token": (None, (type(None), str)),  # OAuth/JWT/PAT/OIDC Token
    "token_file_path": (
        None,
        (type(None), str, bytes),
    ),  # OAuth/JWT/PAT/OIDC Token file path
    "authenticator": (DEFAULT_AUTHENTICATOR, (type(None), str)),
    "workload_identity_provider": (None, (type(None), AttestationProvider)),
    "workload_identity_entra_resource": (None, (type(None), str)),
    "workload_identity_impersonation_path": (None, (type(None), list[str])),
    "mfa_callback": (None, (type(None), Callable)),
    "password_callback": (None, (type(None), Callable)),
    "auth_class": (None, (type(None), AuthByPlugin)),
    "application": (CLIENT_NAME, (type(None), str)),
    # internal_application_name/version is used to tell the server the type of client connecting to
    # Snowflake. There are some functionalities (e.g., MFA, Arrow result format) that
    # Snowflake server doesn't support for new client types, which requires developers to
    # add the new client type to the server to support these features.
    "internal_application_name": (CLIENT_NAME, (type(None), str)),
    "internal_application_version": (CLIENT_VERSION, (type(None), str)),
    "disable_ocsp_checks": (False, bool),
    "ocsp_fail_open": (True, bool),  # fail open on ocsp issues, default true
    "ocsp_root_certs_dict_lock_timeout": (
        OCSP_ROOT_CERTS_DICT_LOCK_TIMEOUT_DEFAULT_NO_TIMEOUT,  # no timeout
        int,
    ),
    "inject_client_pause": (0, int),  # snowflake internal
    "session_parameters": (None, (type(None), dict)),  # snowflake session parameters
    "autocommit": (None, (type(None), bool)),  # snowflake
    "client_session_keep_alive": (None, (type(None), bool)),  # snowflake
    "client_session_keep_alive_heartbeat_frequency": (
        None,
        (type(None), int),
    ),  # snowflake
    "client_prefetch_threads": (4, int),  # snowflake
    "client_fetch_threads": (None, (type(None), int)),
    "client_fetch_use_mp": (False, bool),
    "numpy": (False, bool),  # snowflake
    "ocsp_response_cache_filename": (None, (type(None), str)),  # snowflake internal
    "converter_class": (DefaultConverterClass(), SnowflakeConverter),
    "validate_default_parameters": (False, bool),  # snowflake
    "probe_connection": (False, bool),  # snowflake
    "paramstyle": (None, (type(None), str)),  # standard/snowflake
    "timezone": (None, (type(None), str)),  # snowflake
    "consent_cache_id_token": (True, bool),  # snowflake
    "service_name": (None, (type(None), str)),  # snowflake
    "support_negative_year": (True, bool),  # snowflake
    "log_max_query_length": (LOG_MAX_QUERY_LENGTH, int),  # snowflake
    "disable_request_pooling": (False, bool),  # snowflake
    # enable temporary credential file for Linux, default false. Mac/Win will overlook this
    "client_store_temporary_credential": (False, bool),
    "client_request_mfa_token": (False, bool),
    "use_openssl_only": (
        True,
        bool,
    ),  # ignored - python only crypto modules are no longer used
    # whether to convert Arrow number values to decimal instead of doubles
    "arrow_number_to_decimal": (False, bool),
    "enable_stage_s3_privatelink_for_us_east_1": (
        False,
        bool,
    ),  # only use regional url when the param is set
    # Allows cursors to be re-iterable
    "reuse_results": (False, bool),
    # parameter protecting behavior change of SNOW-501058
    "interpolate_empty_sequences": (False, bool),
    "enable_connection_diag": (False, bool),  # Generate SnowCD like report
    "connection_diag_log_path": (
        None,
        (type(None), str),
    ),  # Path to connection diag report
    "connection_diag_whitelist_path": (
        None,
        (type(None), str),
    ),  # Path to connection diag whitelist json - Deprecated remove in future
    "connection_diag_allowlist_path": (
        None,
        (type(None), str),
    ),  # Path to connection diag allowlist json
    "log_imported_packages_in_telemetry": (
        True,
        bool,
    ),  # Whether to log imported packages in telemetry
    "disable_query_context_cache": (
        False,
        bool,
    ),  # Disable query context cache
    "json_result_force_utf8_decoding": (
        False,
        bool,
    ),  # Whether to force the JSON content to be decoded in utf-8, it is only effective when result format is JSON
    "server_session_keep_alive": (
        False,
        bool,
    ),  # Whether to keep session alive after connector shuts down
    "enable_retry_reason_in_query_response": (
        True,
        bool,
    ),  # Enable sending retryReason in response header for query-requests
    "session_token": (
        None,
        (type(None), str),
    ),  # session token from another connection, to be provided together with master token
    "master_token": (
        None,
        (type(None), str),
    ),  # master token from another connection, to be provided together with session token
    "master_validity_in_seconds": (
        None,
        (type(None), int),
    ),  # master token validity in seconds
    "disable_console_login": (
        True,
        bool,
    ),  # Disable console login and fall back to getting SSO URL from GS
    "debug_arrow_chunk": (
        False,
        bool,
    ),  # log raw arrow chunk for debugging purpuse in case there is malformed arrow data
    "disable_saml_url_check": (
        False,
        bool,
    ),  # disable saml url check in okta authentication
    "iobound_tpe_limit": (
        None,
        (type(None), int),
    ),  # SNOW-1817982: limit iobound TPE sizes when executing PUT/GET
    "oauth_client_id": (
        None,
        (type(None), str),
        # SNOW-1825621: OAUTH implementation
    ),
    "oauth_client_secret": (
        None,
        (type(None), str),
        # SNOW-1825621: OAUTH implementation
    ),
    "oauth_credentials_in_body": (
        False,
        bool,
        # SNOW-2300649: Option to send client credentials in body
    ),
    "oauth_authorization_url": (
        "https://{host}:{port}/oauth/authorize",
        str,
        # SNOW-1825621: OAUTH implementation
    ),
    "oauth_token_request_url": (
        "https://{host}:{port}/oauth/token-request",
        str,
        # SNOW-1825621: OAUTH implementation
    ),
    "oauth_redirect_uri": ("http://127.0.0.1", str),
    "oauth_scope": (
        "",
        str,
        # SNOW-1825621: OAUTH implementation
    ),
    "oauth_disable_pkce": (
        False,
        bool,
        # SNOW-1825621: OAUTH PKCE
    ),
    "oauth_enable_refresh_tokens": (
        False,
        bool,
    ),
    "oauth_enable_single_use_refresh_tokens": (
        False,
        bool,
        # Client-side opt-in to single-use refresh tokens.
    ),
    "check_arrow_conversion_error_on_every_column": (
        True,
        bool,
    ),  # SNOW-XXXXX: remove the check_arrow_conversion_error_on_every_column flag
    "external_session_id": (
        None,
        str,
        # SNOW-2096721: External (Spark) session ID
    ),
    "unsafe_file_write": (
        False,
        bool,
    ),  # SNOW-1944208: add unsafe write flag
    "unsafe_skip_file_permissions_check": (
        False,
        bool,
    ),  # SNOW-2127911: add flag to opt-out file permissions check
    _VARIABLE_NAME_SERVER_DOP_CAP_FOR_FILE_TRANSFER: (
        _DEFAULT_VALUE_SERVER_DOP_CAP_FOR_FILE_TRANSFER,  # default value
        int,  # type
    ),  # snowflake internal
    "reraise_error_in_file_transfer_work_function": (
        False,
        bool,
    ),
    # CRL (Certificate Revocation List) configuration parameters
    # The default setup is specified in CRLConfig class
    "cert_revocation_check_mode": (
        None,
        (type(None), str),
    ),  # CRL revocation check mode: DISABLED, ENABLED, ADVISORY
    "allow_certificates_without_crl_url": (
        None,
        (type(None), bool),
    ),  # Allow certificates without CRL distribution points
    "crl_connection_timeout_ms": (
        None,
        (type(None), int),
    ),  # Connection timeout for CRL downloads in milliseconds
    "crl_read_timeout_ms": (
        None,
        (type(None), int),
    ),  # Read timeout for CRL downloads in milliseconds
    "crl_cache_validity_hours": (
        None,
        (type(None), float),
    ),  # CRL cache validity time in hours
    "enable_crl_cache": (None, (type(None), bool)),  # Enable CRL caching
    "enable_crl_file_cache": (None, (type(None), bool)),  # Enable file-based CRL cache
    "crl_cache_dir": (None, (type(None), str)),  # Directory for CRL file cache
    "crl_cache_removal_delay_days": (
        None,
        (type(None), int),
    ),  # Days to keep expired CRL files before removal
    "crl_cache_cleanup_interval_hours": (
        None,
        (type(None), int),
    ),  # CRL cache cleanup interval in hours
    "crl_cache_start_cleanup": (
        None,
        (type(None), bool),
    ),  # Run CRL cache cleanup in the background
}

APPLICATION_RE = re.compile(r"[\w\d_]+")

# adding the exception class to Connection class
for m in [method for method in dir(errors) if callable(getattr(errors, method))]:
    setattr(sys.modules[__name__], m, getattr(errors, m))

logger = getLogger(__name__)


class TypeAndBinding(NamedTuple):
    """Stores the type name and the Snowflake binding."""

    type: str
    binding: str | None


class SnowflakeConnection:
    """Implementation of the connection object for the Snowflake Database.

    Use connect(..) to get the object.

    Attributes:
        insecure_mode (deprecated): Whether or not the connection is in OCSP disabled mode. It means that the connection
            validates the TLS certificate but doesn't check revocation status with OCSP provider.
        disable_ocsp_checks: Whether or not the connection is in OCSP disabled mode. It means that the connection
            validates the TLS certificate but doesn't check revocation status with OCSP provider.
        ocsp_fail_open: Whether or not the connection is in fail open mode. Fail open mode decides if TLS certificates
            continue to be validated. Revoked certificates are blocked. Any other exceptions are disregarded.
        ocsp_root_certs_dict_lock_timeout: Timeout for the OCSP root certs dict lock in seconds. Default value is -1, which means no timeout.
        session_id: The session ID of the connection.
        user: The user name used in the connection.
        host: The host name the connection attempts to connect to.
        port: The port to communicate with on the host.
        region: Region name if not the default Snowflake Database deployment.
        proxy_host: The hostname used proxy server.
        proxy_port: Port on proxy server to communicate with.
        proxy_user: User name to login with on the proxy sever.
        proxy_password: Password to be used to authenticate with proxy server.
        account: Account name to be used to authenticate with Snowflake.
        database: Database to use on Snowflake.
        schema: Schema in use on Snowflake.
        warehouse: Warehouse to be used on Snowflake.
        role: Role in use on Snowflake.
        login_timeout: Login timeout in seconds. Login requests will not be retried after this timeout expires.
            Note that the login attempt may still take more than login_timeout seconds as an ongoing login request
            cannot be canceled even upon login timeout expiry. The login timeout only prevents further retries.
            If not specified, login_timeout is set to `snowflake.connector.auth.by_plugin.DEFAULT_AUTH_CLASS_TIMEOUT`.
            Note that the number of retries on login requests is still limited by
            `snowflake.connector.auth.by_plugin.DEFAULT_MAX_CON_RETRY_ATTEMPTS`.
        network_timeout: Network timeout in seconds. Network requests besides login requests will not be retried
            after this timeout expires. Overriden in cursor query execution if timeout is passed to cursor.execute.
            Note that an operation may still take more than network_timeout seconds for the same reason as above.
            If not specified, network_timeout is infinite.
        socket_timeout: Socket timeout in seconds. Sets both socket connect and read timeout.
        backoff_policy: Backoff policy to use for login and network requests. Must be a callable generator function.
            Standard linear and exponential backoff implementations are included in `snowflake.connector.backoff_policies`
            See the backoff_policies module for details and implementation examples.
        client_session_keep_alive_heartbeat_frequency: Heartbeat frequency to keep connection alive in seconds.
        client_prefetch_threads: Number of threads to download the result set.
        client_fetch_threads: Number of threads (or processes) to fetch staged query results.
            If not specified, reuses client_prefetch_threads value.
        client_fetch_use_mp: Enables multiprocessing for fetching query results in parallel.
        rest: Snowflake REST API object. Internal use only. Maybe removed in a later release.
        application: Application name to communicate with Snowflake as. By default, this is "PythonConnector".
        errorhandler: Handler used with errors. By default, an exception will be raised on error.
        converter_class: Handler used to convert data to Python native objects.
        validate_default_parameters: Validate database, schema, role and warehouse used on Snowflake.
        is_pyformat: Whether the current argument binding is pyformat or format.
        consent_cache_id_token: Consented cache ID token.
        enable_stage_s3_privatelink_for_us_east_1: when true, clients use regional s3 url to upload files.
        enable_connection_diag: when true, clients will generate a connectivity diagnostic report.
        connection_diag_log_path: path to location to create diag report with enable_connection_diag.
        connection_diag_whitelist_path: path to a whitelist.json file to test with enable_connection_diag - deprecated remove in future
        connection_diag_allowlist_path: path to a allowlist.json file to test with enable_connection_diag.
        json_result_force_utf8_decoding: When true, json result will be decoded in utf-8,
          when false, the encoding of the content is auto-detected. Default value is false.
          This parameter is only effective when the result format is JSON.
        server_session_keep_alive: When true, the connector does not destroy the session on the Snowflake server side
          before the connector shuts down. Default value is false.
        token_file_path: The file path of the token file. If both token and token_file_path are provided, the token in token_file_path will be used.
        unsafe_file_write: When true, files downloaded by GET will be saved with 644 permissions. Otherwise, files will be saved with safe - owner-only permissions: 600.
        check_arrow_conversion_error_on_every_column: When true, the error check after the conversion from arrow to python types will happen for every column in the row. This is a new behaviour which fixes the bug that caused the type errors to trigger silently when occurring at any place other than last column in a row. To revert the previous (faulty) behaviour, please set this flag to false.
    """

    OCSP_ENV_LOCK = Lock()

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
        self._unsafe_skip_file_permissions_check = kwargs.get(
            "unsafe_skip_file_permissions_check", False
        )
        # initiate easy logging during every connection
        easy_logging = EasyLoggingConfigPython(
            skip_config_file_permissions_check=self._unsafe_skip_file_permissions_check
        )
        easy_logging.create_log()
        self._lock_sequence_counter = Lock()
        self.sequence_counter = 0
        self._errorhandler = Error.default_errorhandler
        self._lock_converter = Lock()
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
        self._http_config: HttpConfig | None = None
        self._crl_config: CRLConfig | None = None
        self._session_manager: SessionManager | None = None
        self._rest: SnowflakeRestful | None = None

        for name, (value, _) in DEFAULT_CONFIGURATION.items():
            setattr(self, f"_{name}", value)

        self.heartbeat_thread = None
        is_kwargs_empty = not kwargs

        if "application" not in kwargs:
            app = self._detect_application()
            if app:
                kwargs["application"] = app

        if "insecure_mode" in kwargs:
            warn_message = "The 'insecure_mode' connection property is deprecated. Please use 'disable_ocsp_checks' instead"
            warnings.warn(
                warn_message,
                DeprecationWarning,
                stacklevel=2,
            )

            if (
                "disable_ocsp_checks" in kwargs
                and kwargs["disable_ocsp_checks"] != kwargs["insecure_mode"]
            ):
                logger.warning(
                    "The values for 'disable_ocsp_checks' and 'insecure_mode' differ. "
                    "Using the value of 'disable_ocsp_checks."
                )
            else:
                self._disable_ocsp_checks = kwargs["insecure_mode"]

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
            kwargs = {**connections[connection_name], **kwargs}
        elif is_kwargs_empty:
            # connection_name is None and kwargs was empty when called
            kwargs = _get_default_connection_params()
        self.__set_error_attributes()
        self.connect(**kwargs)
        self._telemetry = TelemetryClient(self._rest)
        self.expired = False

        # get the imported modules from sys.modules
        self._log_telemetry_imported_packages()
        # check SNOW-1218851 for long term improvement plan to refactor ocsp code
        atexit.register(self._close_at_exit)

        # Set up the file operation parser and stream downloader.
        self._file_operation_parser = FileOperationParser(self)
        self._stream_downloader = StreamDownloader(self)

    # Deprecated
    @property
    def insecure_mode(self) -> bool:
        return self._disable_ocsp_checks

    @property
    def disable_ocsp_checks(self) -> bool:
        return self._disable_ocsp_checks

    @property
    def ocsp_fail_open(self) -> bool:
        return self._ocsp_fail_open

    def _ocsp_mode(self) -> OCSPMode:
        """OCSP mode. DISABLE_OCSP_CHECKS, FAIL_OPEN or FAIL_CLOSED."""
        if self.disable_ocsp_checks:
            return OCSPMode.DISABLE_OCSP_CHECKS
        elif self.ocsp_fail_open:
            return OCSPMode.FAIL_OPEN
        else:
            return OCSPMode.FAIL_CLOSED

    # CRL (Certificate Revocation List) configuration properties
    @property
    def cert_revocation_check_mode(self) -> str | None:
        """Certificate revocation check mode: DISABLED, ENABLED, or ADVISORY."""
        if not self._crl_config:
            return self._cert_revocation_check_mode
        return self._crl_config.cert_revocation_check_mode.value

    @property
    def allow_certificates_without_crl_url(self) -> bool | None:
        """Whether to allow certificates without CRL distribution points."""
        if not self._crl_config:
            return self._allow_certificates_without_crl_url
        return self._crl_config.allow_certificates_without_crl_url

    @property
    def crl_connection_timeout_ms(self) -> int | None:
        """Connection timeout for CRL downloads in milliseconds."""
        if not self._crl_config:
            return self._crl_connection_timeout_ms
        return self._crl_config.connection_timeout_ms

    @property
    def crl_read_timeout_ms(self) -> int | None:
        """Read timeout for CRL downloads in milliseconds."""
        if not self._crl_config:
            return self._crl_read_timeout_ms
        return self._crl_config.read_timeout_ms

    @property
    def crl_cache_validity_hours(self) -> float | None:
        """CRL cache validity time in hours."""
        if not self._crl_config:
            return self._crl_cache_validity_hours
        return self._crl_config.cache_validity_time.total_seconds() / 3600

    @property
    def enable_crl_cache(self) -> bool | None:
        """Whether CRL caching is enabled."""
        if not self._crl_config:
            return self._enable_crl_cache
        return self._crl_config.enable_crl_cache

    @property
    def enable_crl_file_cache(self) -> bool | None:
        """Whether file-based CRL cache is enabled."""
        if not self._crl_config:
            return self._enable_crl_file_cache
        return self._crl_config.enable_crl_file_cache

    @property
    def crl_cache_dir(self) -> str | None:
        """Directory for CRL file cache."""
        if not self._crl_config:
            return self._crl_cache_dir
        if not self._crl_config.crl_cache_dir:
            return None
        return str(self._crl_config.crl_cache_dir)

    @property
    def crl_cache_removal_delay_days(self) -> int | None:
        """Days to keep expired CRL files before removal."""
        if not self._crl_config:
            return self._crl_cache_removal_delay_days
        return self._crl_config.crl_cache_removal_delay_days

    @property
    def crl_cache_cleanup_interval_hours(self) -> int | None:
        """CRL cache cleanup interval in hours."""
        if not self._crl_config:
            return self._crl_cache_cleanup_interval_hours
        return self._crl_config.crl_cache_cleanup_interval_hours

    @property
    def crl_cache_start_cleanup(self) -> bool | None:
        """Whether to start CRL cache cleanup immediately."""
        if not self._crl_config:
            return self._crl_cache_start_cleanup
        return self._crl_config.crl_cache_start_cleanup

    @property
    def session_id(self) -> int:
        return self._session_id

    @property
    def user(self) -> str:
        return self._user

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return int(self._port)

    @property
    def region(self) -> str | None:
        warnings.warn(
            "Region has been deprecated and will be removed in the near future",
            PendingDeprecationWarning,
            # Raise warning from where this property was called from
            stacklevel=2,
        )
        return self._region

    @property
    def proxy_host(self) -> str | None:
        return self._proxy_host

    @property
    def proxy_port(self) -> str | None:
        return self._proxy_port

    @property
    def proxy_user(self) -> str | None:
        return self._proxy_user

    @property
    def proxy_password(self) -> str | None:
        return self._proxy_password

    @property
    def account(self) -> str:
        return self._account

    @property
    def database(self) -> str | None:
        return self._database

    @property
    def schema(self) -> str | None:
        return self._schema

    @property
    def warehouse(self) -> str | None:
        return self._warehouse

    @property
    def role(self) -> str | None:
        return self._role

    @property
    def login_timeout(self) -> int | None:
        return int(self._login_timeout) if self._login_timeout is not None else None

    @property
    def network_timeout(self) -> int | None:
        return int(self._network_timeout) if self._network_timeout is not None else None

    @property
    def socket_timeout(self) -> int | None:
        return int(self._socket_timeout) if self._socket_timeout is not None else None

    @property
    def _backoff_generator(self) -> Iterator:
        return self._backoff_policy()

    @property
    def client_session_keep_alive(self) -> bool | None:
        return self._client_session_keep_alive

    @client_session_keep_alive.setter
    def client_session_keep_alive(self, value) -> None:
        self._client_session_keep_alive = value

    @property
    def client_session_keep_alive_heartbeat_frequency(self) -> int | None:
        return self._client_session_keep_alive_heartbeat_frequency

    @client_session_keep_alive_heartbeat_frequency.setter
    def client_session_keep_alive_heartbeat_frequency(self, value) -> None:
        self._client_session_keep_alive_heartbeat_frequency = value
        self._validate_client_session_keep_alive_heartbeat_frequency()

    @property
    def platform_detection_timeout_seconds(self) -> float | None:
        return self._platform_detection_timeout_seconds

    @platform_detection_timeout_seconds.setter
    def platform_detection_timeout_seconds(self, value) -> None:
        self._platform_detection_timeout_seconds = value

    @property
    def client_prefetch_threads(self) -> int:
        return (
            self._client_prefetch_threads
            if self._client_prefetch_threads
            else DEFAULT_CLIENT_PREFETCH_THREADS
        )

    @client_prefetch_threads.setter
    def client_prefetch_threads(self, value) -> None:
        self._client_prefetch_threads = value
        self._validate_client_prefetch_threads()

    @property
    def client_fetch_threads(self) -> int | None:
        return self._client_fetch_threads

    @client_fetch_threads.setter
    def client_fetch_threads(self, value: None | int) -> None:
        if value is not None:
            value = min(max(1, value), MAX_CLIENT_FETCH_THREADS)
        self._client_fetch_threads = value

    @property
    def client_fetch_use_mp(self) -> bool:
        return self._client_fetch_use_mp

    @property
    def rest(self) -> SnowflakeRestful | None:
        return self._rest

    @property
    def application(self) -> str:
        return self._application

    @property
    def errorhandler(self) -> Callable:  # TODO: callable args
        return self._errorhandler

    @errorhandler.setter
    # Note: Callable doesn't implement operator|
    def errorhandler(self, value: Callable | None) -> None:
        if value is None:
            raise ProgrammingError("None errorhandler is specified")
        self._errorhandler = value

    @property
    def converter_class(self) -> type[SnowflakeConverter]:
        return self._converter_class

    @property
    def validate_default_parameters(self) -> bool:
        return self._validate_default_parameters

    @property
    def is_pyformat(self) -> bool:
        return self._paramstyle in ("pyformat", "format")

    @property
    def consent_cache_id_token(self):
        return self._consent_cache_id_token

    @property
    def telemetry_enabled(self) -> bool:
        return bool(
            self._client_param_telemetry_enabled
            and self._server_param_telemetry_enabled
        )

    @telemetry_enabled.setter
    def telemetry_enabled(self, value) -> None:
        self._client_param_telemetry_enabled = True if value else False
        if (
            self._client_param_telemetry_enabled
            and not self._server_param_telemetry_enabled
        ):
            logger.info(
                "Telemetry has been disabled by the session parameter CLIENT_TELEMETRY_ENABLED."
                " Set session parameter CLIENT_TELEMETRY_ENABLED to true to enable telemetry."
            )

    @property
    def service_name(self) -> str | None:
        return self._service_name

    @service_name.setter
    def service_name(self, value) -> None:
        self._service_name = value

    @property
    def log_max_query_length(self) -> int:
        return self._log_max_query_length

    @property
    def disable_request_pooling(self) -> bool:
        return self._disable_request_pooling

    @disable_request_pooling.setter
    def disable_request_pooling(self, value) -> None:
        self._disable_request_pooling = True if value else False

    @property
    def use_openssl_only(self) -> bool:
        # Deprecated, kept for backwards compatibility
        return True

    @property
    def arrow_number_to_decimal(self):
        return self._arrow_number_to_decimal

    @property
    def enable_stage_s3_privatelink_for_us_east_1(self) -> bool:
        return self._enable_stage_s3_privatelink_for_us_east_1

    @enable_stage_s3_privatelink_for_us_east_1.setter
    def enable_stage_s3_privatelink_for_us_east_1(self, value) -> None:
        self._enable_stage_s3_privatelink_for_us_east_1 = True if value else False

    @property
    def enable_connection_diag(self) -> bool:
        return self._enable_connection_diag

    @property
    def connection_diag_log_path(self):
        return self._connection_diag_log_path

    @property
    def connection_diag_whitelist_path(self):
        """
        Old version of ``connection_diag_allowlist_path``.
        This used to be the original name, but snowflake backend
        deprecated whitelist for allowlist. This name will be
        deprecated in the future.
        """
        warnings.warn(
            "connection_diag_whitelist_path has been deprecated, use connection_diag_allowlist_path instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._connection_diag_whitelist_path

    @property
    def connection_diag_allowlist_path(self):
        return self._connection_diag_allowlist_path

    @arrow_number_to_decimal.setter
    def arrow_number_to_decimal_setter(self, value: bool) -> None:
        self._arrow_number_to_decimal = value

    @property
    def auth_class(self) -> AuthByPlugin | None:
        return self._auth_class

    @auth_class.setter
    def auth_class(self, value: AuthByPlugin) -> None:
        if isinstance(value, AuthByPlugin):
            self._auth_class = value
        else:
            raise TypeError("auth_class must subclass AuthByPlugin")

    @property
    def is_query_context_cache_disabled(self) -> bool:
        return self._disable_query_context_cache

    @property
    def iobound_tpe_limit(self) -> int | None:
        return self._iobound_tpe_limit

    @property
    def unsafe_file_write(self) -> bool:
        return self._unsafe_file_write

    @unsafe_file_write.setter
    def unsafe_file_write(self, value: bool) -> None:
        self._unsafe_file_write = value

    @property
    def check_arrow_conversion_error_on_every_column(self) -> bool:
        return self._check_arrow_conversion_error_on_every_column

    @cached_property
    def snowflake_version(self) -> str:
        # The result from SELECT CURRENT_VERSION() is `<version> <internal hash>`,
        # and we only need the first part
        return str(
            self.cursor().execute("SELECT CURRENT_VERSION()").fetchall()[0][0]
        ).split(" ")[0]

    @check_arrow_conversion_error_on_every_column.setter
    def check_arrow_conversion_error_on_every_column(self, value: bool) -> bool:
        self._check_arrow_conversion_error_on_every_column = value

    def connect(self, **kwargs) -> None:
        """Establishes connection to Snowflake."""
        logger.debug("connect")
        if len(kwargs) > 0:
            self.__config(**kwargs)

        self._crl_config: CRLConfig = CRLConfig.from_connection(self)

        self._http_config = HttpConfig(
            adapter_factory=ProxySupportAdapterFactory(),
            use_pooling=(not self.disable_request_pooling),
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
            proxy_user=self.proxy_user,
            proxy_password=self.proxy_password,
        )
        self._session_manager = SessionManager(self._http_config)

        if self.enable_connection_diag:
            exceptions_dict = {}
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
                session_manager=self._session_manager.clone(use_pooling=False),
            )
            try:
                connection_diag.run_test()
                self.__open_connection()
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
            self.__open_connection()

    def close(self, retry: bool = True) -> None:
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
            self._cancel_heartbeat()

            # close telemetry first, since it needs rest to send remaining data
            logger.debug("closed")
            self._telemetry.close(send_on_close=bool(retry and self.telemetry_enabled))
            if (
                self._all_async_queries_finished()
                and not self._server_session_keep_alive
            ):
                logger.debug("No async queries seem to be running, deleting session")
                self.rest.delete_session(retry=retry)
            else:
                logger.debug(
                    "There are {} async queries still running, not deleting session".format(
                        len(self._async_sfqids)
                    )
                )
            self.rest.close()
            self._rest = None
            if self.query_context_cache:
                self.query_context_cache.clear_cache()
            del self.messages[:]
            logger.debug("Session is closed")
        except Exception as e:
            logger.debug(
                "Exception encountered in closing connection. ignoring...: %s", e
            )

    def is_closed(self) -> bool:
        """Checks whether the connection has been closed."""
        return self.rest is None

    def autocommit(self, mode) -> None:
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
            self.cursor().execute(f"ALTER SESSION SET autocommit={mode}")
        except Error as e:
            if e.sqlstate == SQLSTATE_FEATURE_NOT_SUPPORTED:
                logger.debug(
                    "Autocommit feature is not enabled for this " "connection. Ignored"
                )

    def commit(self) -> None:
        """Commits the current transaction."""
        self.cursor().execute("COMMIT")

    def rollback(self) -> None:
        """Rolls back the current transaction."""
        self.cursor().execute("ROLLBACK")

    def cursor(self, cursor_class: type[CursorCls] = SnowflakeCursor) -> CursorCls:
        """Creates a cursor object. Each statement will be executed in a new cursor object."""
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

    def execute_string(
        self,
        sql_text: str,
        remove_comments: bool = False,
        return_cursors: bool = True,
        cursor_class: SnowflakeCursor = SnowflakeCursor,
        **kwargs,
    ) -> Iterable[SnowflakeCursor]:
        """Executes a SQL text including multiple statements. This is a non-standard convenience method."""
        stream = StringIO(sql_text)
        stream_generator = self.execute_stream(
            stream, remove_comments=remove_comments, cursor_class=cursor_class, **kwargs
        )
        ret = list(stream_generator)
        return ret if return_cursors else list()

    def execute_stream(
        self,
        stream: StringIO,
        remove_comments: bool = False,
        cursor_class: SnowflakeCursor = SnowflakeCursor,
        **kwargs,
    ) -> Generator[SnowflakeCursor]:
        """Executes a stream of SQL statements. This is a non-standard convenient method."""
        split_statements_list = split_statements(
            stream, remove_comments=remove_comments
        )
        # Note: split_statements_list is a list of tuples of sql statements and whether they are put/get
        non_empty_statements = [e for e in split_statements_list if e[0]]
        for sql, is_put_or_get in non_empty_statements:
            cur = self.cursor(cursor_class=cursor_class)
            cur.execute(sql, _is_put_get=is_put_or_get, **kwargs)
            yield cur

    def __set_error_attributes(self) -> None:
        for m in [
            method for method in dir(errors) if callable(getattr(errors, method))
        ]:
            # If name starts with _ then ignore that
            name = m if not m.startswith("_") else m[1:]
            setattr(self, name, getattr(errors, m))

    @staticmethod
    def setup_ocsp_privatelink(app, hostname) -> None:
        hostname = hostname.lower()
        SnowflakeConnection.OCSP_ENV_LOCK.acquire()
        ocsp_cache_server = f"http://ocsp.{hostname}/ocsp_response_cache.json"
        os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"] = ocsp_cache_server
        logger.debug("OCSP Cache Server is updated: %s", ocsp_cache_server)
        SnowflakeConnection.OCSP_ENV_LOCK.release()

    def __open_connection(self):
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

        if self.client_prefetch_threads:
            self._session_parameters[PARAMETER_CLIENT_PREFETCH_THREADS] = (
                self._validate_client_prefetch_threads()
            )

        # Setup authenticator
        auth = Auth(self.rest)

        if self._session_token and self._master_token:
            auth._rest.update_tokens(
                self._session_token,
                self._master_token,
                self._master_validity_in_seconds,
            )
            heartbeat_ret = auth._rest._heartbeat()
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
                    # TODO: add telemetry for custom auth
                self.auth_class = self.auth_class
            # match authentivator - validation happens in __config
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
                        host=self.host,  # TODO: delete this?
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

                if self._private_key_file:
                    private_key = _get_private_bytes_from_file(
                        self._private_key_file,
                        self._private_key_file_pwd,
                    )

                self.auth_class = AuthByKeyPair(
                    private_key=private_key,
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
                    credentials_in_body=self._oauth_credentials_in_body,
                    connection=self,
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
            elif self._authenticator == PROGRAMMATIC_ACCESS_TOKEN:
                self.auth_class = AuthByPAT(self._token)
            elif self._authenticator == PAT_WITH_EXTERNAL_SESSION:
                # We don't need to do a POST to /v1/login-request to get session and master tokens at the startup
                # time. PAT with external (Spark) session ID creates a new session when it encounters the unique
                # (PAT, external session ID) combination for the first time and then onwards use the (PAT, external
                # session id) as a key to identify and authenticate the session. So we bypass actual AuthN here.
                self.auth_class = AuthNoAuth()
                self._rest.set_pat_and_external_session(
                    self._token, self._external_session_id
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

            self.authenticate_with_retry(self.auth_class)

            self._password = None  # ensure password won't persist
            self.auth_class.reset_secrets()

        self.initialize_query_context_cache()

        if self.client_session_keep_alive:
            # This will be called after the heartbeat frequency has actually been set.
            # By this point it should have been decided if the heartbeat has to be enabled
            # and what would the heartbeat frequency be
            self._add_heartbeat()

    def __config(self, **kwargs):
        """Sets up parameters in the connection object."""
        logger.debug("__config")
        # Handle special cases first
        if "sequence_counter" in kwargs:
            self.sequence_counter = kwargs["sequence_counter"]
        if "application" in kwargs:
            value = kwargs["application"]
            if not APPLICATION_RE.match(value):
                msg = f"Invalid application name: {value}"
                raise ProgrammingError(msg=msg, errno=0)
            else:
                self._application = value
        if "validate_default_parameters" in kwargs:
            self._validate_default_parameters = kwargs["validate_default_parameters"]
        # Handle rest of arguments
        skip_list = ["validate_default_parameters", "sequence_counter", "application"]
        for name, value in filter(lambda e: e[0] not in skip_list, kwargs.items()):
            if self.validate_default_parameters:
                if name not in DEFAULT_CONFIGURATION.keys():
                    close_matches = get_close_matches(
                        name, DEFAULT_CONFIGURATION.keys(), n=1, cutoff=0.8
                    )
                    guess = close_matches[0] if len(close_matches) > 0 else None
                    warnings.warn(
                        "'{}' is an unknown connection parameter{}".format(
                            name, f", did you mean '{guess}'?" if guess else ""
                        ),
                        # Raise warning from where class was initiated
                        stacklevel=4,
                    )
                elif not isinstance(value, DEFAULT_CONFIGURATION[name][1]):
                    accepted_types = DEFAULT_CONFIGURATION[name][1]
                    warnings.warn(
                        "'{}' connection parameter should be of type '{}', but is a '{}'".format(
                            name,
                            (
                                str(tuple(e.__name__ for e in accepted_types)).replace(
                                    "'", ""
                                )
                                if isinstance(accepted_types, tuple)
                                else accepted_types.__name__
                            ),
                            type(value).__name__,
                        ),
                        # Raise warning from where class was initiated
                        stacklevel=4,
                    )
            setattr(self, "_" + name, value)

        if self._numpy:
            try:
                import numpy  # noqa: F401
            except ModuleNotFoundError:  # pragma: no cover
                Error.errorhandler_wrapper(
                    self,
                    None,
                    ProgrammingError,
                    {
                        "msg": "Numpy module is not installed. Cannot fetch data as numpy",
                        "errno": ER_NO_NUMPY,
                    },
                )

        if self._paramstyle is None:
            import snowflake.connector

            self._paramstyle = snowflake.connector.paramstyle
        elif self._paramstyle not in SUPPORTED_PARAMSTYLES:
            raise ProgrammingError(
                msg="Invalid paramstyle is specified", errno=ER_INVALID_VALUE
            )

        if self._auth_class and not isinstance(self._auth_class, AuthByPlugin):
            raise TypeError("auth_class must subclass AuthByPlugin")

        if "account" in kwargs:
            if "host" not in kwargs:
                self._host = construct_hostname(kwargs.get("region"), self._account)

        logger.info(
            f"Connecting to {_DOMAIN_NAME_MAP.get(extract_top_level_domain_from_hostname(self._host), 'GLOBAL')} Snowflake domain"
        )

        # If using a custom auth class, we should set the authenticator
        # type to be the same as the custom auth class
        if self._auth_class:
            self._authenticator = self._auth_class.type_.value
        elif self._authenticator:
            # Validate authenticator and convert it to uppercase if it is a non-okta link
            auth_tmp = self._authenticator.upper()
            if auth_tmp in [
                DEFAULT_AUTHENTICATOR,
                EXTERNAL_BROWSER_AUTHENTICATOR,
                KEY_PAIR_AUTHENTICATOR,
                OAUTH_AUTHENTICATOR,
                OAUTH_AUTHORIZATION_CODE,
                OAUTH_CLIENT_CREDENTIALS,
                USR_PWD_MFA_AUTHENTICATOR,
                WORKLOAD_IDENTITY_AUTHENTICATOR,
                PROGRAMMATIC_ACCESS_TOKEN,
                PAT_WITH_EXTERNAL_SESSION,
            ]:
                self._authenticator = auth_tmp
            elif auth_tmp.startswith("HTTPS://"):
                # okta authenticator link
                pass
            else:
                raise ProgrammingError(
                    msg=f"Unknown authenticator: {self._authenticator}",
                    errno=ER_INVALID_VALUE,
                )

        # read OAuth token from
        token_file_path = kwargs.get("token_file_path")
        if token_file_path:
            with open(token_file_path) as f:
                self._token = f.read()

        # Set of authenticators allowing empty user.
        empty_user_allowed_authenticators = {
            OAUTH_AUTHENTICATOR,
            NO_AUTH_AUTHENTICATOR,
            WORKLOAD_IDENTITY_AUTHENTICATOR,
            PROGRAMMATIC_ACCESS_TOKEN,
            PAT_WITH_EXTERNAL_SESSION,
        }

        if not (self._master_token and self._session_token):
            if (
                not self.user
                and self._authenticator not in empty_user_allowed_authenticators
            ):
                # Some authenticators do not require a username
                Error.errorhandler_wrapper(
                    self,
                    None,
                    ProgrammingError,
                    {
                        "msg": f"User is empty, but it must be provided unless authenticator is one of {', '.join(empty_user_allowed_authenticators)}.",
                        "errno": ER_NO_USER,
                    },
                )

            if self._private_key or self._private_key_file:
                self._authenticator = KEY_PAIR_AUTHENTICATOR

            workload_identity_dependent_options = [
                "workload_identity_provider",
                "workload_identity_entra_resource",
                "workload_identity_impersonation_path",
            ]
            for dependent_option in workload_identity_dependent_options:
                if (
                    self.__getattribute__(f"_{dependent_option}") is not None
                    and self._authenticator != WORKLOAD_IDENTITY_AUTHENTICATOR
                ):
                    Error.errorhandler_wrapper(
                        self,
                        None,
                        ProgrammingError,
                        {
                            "msg": f"{dependent_option} was set but authenticator was not set to {WORKLOAD_IDENTITY_AUTHENTICATOR}",
                            "errno": ER_INVALID_WIF_SETTINGS,
                        },
                    )

            if (
                self.auth_class is None
                and self._authenticator
                not in (
                    EXTERNAL_BROWSER_AUTHENTICATOR,
                    OAUTH_AUTHENTICATOR,
                    OAUTH_AUTHORIZATION_CODE,
                    OAUTH_CLIENT_CREDENTIALS,
                    KEY_PAIR_AUTHENTICATOR,
                    PROGRAMMATIC_ACCESS_TOKEN,
                    WORKLOAD_IDENTITY_AUTHENTICATOR,
                    PAT_WITH_EXTERNAL_SESSION,
                )
                and not self._password
            ):
                Error.errorhandler_wrapper(
                    self,
                    None,
                    ProgrammingError,
                    {"msg": "Password is empty", "errno": ER_NO_PASSWORD},
                )

        # Only AuthNoAuth allows account to be omitted.
        if not self._account and not isinstance(self.auth_class, AuthNoAuth):
            Error.errorhandler_wrapper(
                self,
                None,
                ProgrammingError,
                {"msg": "Account must be specified", "errno": ER_NO_ACCOUNT_NAME},
            )
        if self._account and "." in self._account:
            self._account = parse_account(self._account)

        if not isinstance(self._backoff_policy, Callable) or not isinstance(
            self._backoff_policy(), Iterator
        ):
            Error.errorhandler_wrapper(
                self,
                None,
                ProgrammingError,
                {
                    "msg": "Backoff policy must be a generator function",
                    "errno": ER_INVALID_BACKOFF_POLICY,
                },
            )

        if self.ocsp_fail_open:
            logger.debug(
                "This connection is in OCSP Fail Open Mode. "
                "TLS Certificates would be checked for validity "
                "and revocation status. Any other Certificate "
                "Revocation related exceptions or OCSP Responder "
                "failures would be disregarded in favor of "
                "connectivity."
            )

        if self.disable_ocsp_checks:
            logger.debug(
                "This connection runs with disabled OCSP checks. "
                "Revocation status of the certificate will not be checked against OCSP Responder."
            )

    def cmd_query(
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

        ret = self.rest.request(
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

    def _reauthenticate(self):
        return self._auth_class.reauthenticate(conn=self)

    def authenticate_with_retry(self, auth_instance) -> None:
        # make some changes if needed before real __authenticate
        try:
            self._authenticate(auth_instance)
        except ReauthenticationRequest as ex:
            # cached id_token expiration error, we have cleaned id_token and try to authenticate again
            logger.debug("ID token expired. Reauthenticating...: %s", ex)
            if type(auth_instance) in (
                AuthByIdToken,
                AuthByOauthCode,
                AuthByOauthCredentials,
            ):
                # IDToken and OAuth auth need to authenticate through
                # SSO if its credential has expired
                self._reauthenticate()
            else:
                self._authenticate(auth_instance)

    def _authenticate(self, auth_instance: AuthByPlugin):
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

        auth = Auth(self.rest)
        # record start time for computing timeout
        auth_instance._retry_ctx.set_start_time()
        try:
            auth.authenticate(
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
                    auth_instance.handle_timeout(
                        authenticator=self._authenticator,
                        service_name=self.service_name,
                        account=self.account,
                        user=self.user,
                        password=self._password,
                    )
                    auth.authenticate(
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

    def _write_params_to_byte_rows(
        self, params: list[tuple[Any | tuple]]
    ) -> list[bytes]:
        """Write csv-format rows of binding values as list of bytes string.

        Args:
            params: Binding parameters to bulk array insertion query with qmark/numeric format.
            cursor: SnowflakeCursor.

        Returns:
            List of bytes string corresponding to rows

        """
        res = []
        try:
            for row in params:
                temp = map(self.converter.to_csv_bindings, row)
                res.append((",".join(temp) + "\n").encode("utf-8"))
        except (ProgrammingError, AttributeError) as exc:
            raise BindUploadError from exc
        return res

    def _get_snowflake_type_and_binding(
        self,
        cursor: SnowflakeCursor | None,
        v: tuple[str, Any] | Any,
    ) -> TypeAndBinding:
        if isinstance(v, tuple):
            if len(v) != 2:
                Error.errorhandler_wrapper(
                    self,
                    cursor,
                    ProgrammingError,
                    {
                        "msg": "Binding parameters must be a list "
                        "where one element is a single value or "
                        "a pair of Snowflake datatype and a value",
                        "errno": ER_FAILED_PROCESSING_QMARK,
                    },
                )
            snowflake_type, v = v
        else:
            snowflake_type = self.converter.snowflake_type(v)
            if snowflake_type is None:
                Error.errorhandler_wrapper(
                    self,
                    cursor,
                    ProgrammingError,
                    {
                        "msg": "Python data type [{}] cannot be "
                        "automatically mapped to Snowflake data "
                        "type. Specify the snowflake data type "
                        "explicitly.".format(v.__class__.__name__.lower()),
                        "errno": ER_NOT_IMPLICITY_SNOWFLAKE_DATATYPE,
                    },
                )
        return TypeAndBinding(
            snowflake_type,
            self.converter.to_snowflake_bindings(snowflake_type, v),
        )

    # TODO we could probably rework this to not make dicts like this: {'1': 'value', '2': '13'}
    def _process_params_qmarks(
        self,
        params: Sequence | None,
        cursor: SnowflakeCursor | None = None,
    ) -> dict[str, dict[str, str]] | None:
        if not params:
            return None
        processed_params = {}

        get_type_and_binding = partial(self._get_snowflake_type_and_binding, cursor)

        for idx, v in enumerate(params):
            if isinstance(v, list):
                snowflake_type = self.converter.snowflake_type(v)
                all_param_data = list(map(get_type_and_binding, v))
                first_type = all_param_data[0].type
                # if all elements have the same snowflake type, update snowflake_type
                if all(param_data.type == first_type for param_data in all_param_data):
                    snowflake_type = first_type
                processed_params[str(idx + 1)] = {
                    "type": snowflake_type,
                    "value": [param_data.binding for param_data in all_param_data],
                }
            else:
                snowflake_type, snowflake_binding = get_type_and_binding(v)
                processed_params[str(idx + 1)] = {
                    "type": snowflake_type,
                    "value": snowflake_binding,
                }
        if logger.getEffectiveLevel() <= logging.DEBUG:
            for k, v in processed_params.items():
                logger.debug("idx: %s, type: %s", k, v.get("type"))
        return processed_params

    def _process_params_pyformat(
        self,
        params: Any | Sequence[Any] | dict[Any, Any] | None,
        cursor: SnowflakeCursor | None = None,
    ) -> tuple[Any] | dict[str, Any] | None:
        """Process parameters for client-side parameter binding.

        Args:
            params: Either a sequence, or a dictionary of parameters, if anything else
                is given then it will be put into a list and processed that way.
            cursor: The SnowflakeCursor used to report errors if necessary.
        """
        if params is None:
            if self._interpolate_empty_sequences:
                return None
            return {}
        if isinstance(params, dict):
            return self._process_params_dict(params)

        # TODO: remove this, callers should send in what's in the signature
        if not isinstance(params, (tuple, list)):
            params = [
                params,
            ]

        try:
            res = map(self._process_single_param, params)
            ret = tuple(res)
            logger.debug(f"parameters: {ret}")
            return ret
        except Exception as e:
            Error.errorhandler_wrapper(
                self,
                cursor,
                ProgrammingError,
                {
                    "msg": f"Failed processing pyformat-parameters; {e}",
                    "errno": ER_FAILED_PROCESSING_PYFORMAT,
                },
            )

    def _process_params_dict(
        self, params: dict[Any, Any], cursor: SnowflakeCursor | None = None
    ) -> dict:
        try:
            res = {k: self._process_single_param(v) for k, v in params.items()}
            logger.debug(f"parameters: {res}")
            return res
        except Exception as e:
            Error.errorhandler_wrapper(
                self,
                cursor,
                ProgrammingError,
                {
                    "msg": f"Failed processing pyformat-parameters: {e}",
                    "errno": ER_FAILED_PROCESSING_PYFORMAT,
                },
            )

    def _process_single_param(self, param: Any) -> Any:
        """Process a single parameter to Snowflake understandable form.

        This is a convenience function to replace repeated multiple calls with a single
        function call.

        It calls the following underlying functions in this order:
            1. self.converter.to_snowflake
            2. self.converter.escape
            3. self.converter.quote
        """
        to_snowflake = self.converter.to_snowflake
        escape = self.converter.escape
        _quote = self.converter.quote
        return _quote(escape(to_snowflake(param)))

    def _cancel_query(self, sql: str, request_id: UUID) -> dict[str, bool | None]:
        """Cancels the query with the exact SQL query and requestId."""
        logger.debug("_cancel_query sql=[%s], request_id=[%s]", sql, request_id)
        url_parameters = {REQUEST_ID: str(uuid.uuid4())}

        return self.rest.request(
            "/queries/v1/abort-request?" + urlencode(url_parameters),
            {
                "sqlText": sql,
                REQUEST_ID: str(request_id),
            },
        )

    def _next_sequence_counter(self) -> int:
        """Gets next sequence counter. Used internally."""
        with self._lock_sequence_counter:
            self.sequence_counter += 1
            logger.debug("sequence counter: %s", self.sequence_counter)
            return self.sequence_counter

    def _log_telemetry(self, telemetry_data) -> None:
        """Logs data to telemetry."""
        if self.telemetry_enabled:
            self._telemetry.try_add_log_to_batch(telemetry_data)

    def _add_heartbeat(self) -> None:
        """Add a periodic heartbeat query in order to keep connection alive."""
        if not self.heartbeat_thread:
            self._validate_client_session_keep_alive_heartbeat_frequency()
            heartbeat_wref = weakref.WeakMethod(self._heartbeat_tick)

            def beat_if_possible() -> None:
                heartbeat_fn = heartbeat_wref()
                if heartbeat_fn:
                    heartbeat_fn()

            self.heartbeat_thread = HeartBeatTimer(
                self.client_session_keep_alive_heartbeat_frequency,
                beat_if_possible,
            )
            self.heartbeat_thread.start()
            logger.debug("started heartbeat")

    def _cancel_heartbeat(self) -> None:
        """Cancel a heartbeat thread."""
        if self.heartbeat_thread:
            self.heartbeat_thread.cancel()
            self.heartbeat_thread.join()
            self.heartbeat_thread = None
            logger.debug("stopped heartbeat")

    def _heartbeat_tick(self) -> None:
        """Execute a heartbeat if connection isn't closed yet."""
        if not self.is_closed():
            logger.debug("heartbeating!")
            self.rest._heartbeat()

    def _validate_client_session_keep_alive_heartbeat_frequency(self) -> int:
        """Validate and return heartbeat frequency in seconds."""
        real_max = int(self.rest.master_validity_in_seconds / 4)
        real_min = int(real_max / 4)

        # ensure the type is integer
        self._client_session_keep_alive_heartbeat_frequency = int(
            self.client_session_keep_alive_heartbeat_frequency
        )

        if self.client_session_keep_alive_heartbeat_frequency is None:
            # This is an unlikely scenario but covering it just in case.
            self._client_session_keep_alive_heartbeat_frequency = real_min
        elif self.client_session_keep_alive_heartbeat_frequency > real_max:
            self._client_session_keep_alive_heartbeat_frequency = real_max
        elif self.client_session_keep_alive_heartbeat_frequency < real_min:
            self._client_session_keep_alive_heartbeat_frequency = real_min

        return self.client_session_keep_alive_heartbeat_frequency

    def _validate_client_prefetch_threads(self) -> int:
        if self.client_prefetch_threads <= 0:
            self._client_prefetch_threads = 1
        elif self.client_prefetch_threads > MAX_CLIENT_PREFETCH_THREADS:
            self._client_prefetch_threads = MAX_CLIENT_PREFETCH_THREADS
        self._client_prefetch_threads = int(self.client_prefetch_threads)
        return self.client_prefetch_threads

    def _update_parameters(
        self,
        parameters: dict[str, str | int | bool],
    ) -> None:
        """Update session parameters."""
        with self._lock_converter:
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

    def _format_query_for_log(self, query: str) -> str:
        ret = " ".join(line.strip() for line in query.split("\n"))
        return (
            ret
            if len(ret) < self.log_max_query_length
            else ret[0 : self.log_max_query_length] + "..."
        )

    def __enter__(self) -> SnowflakeConnection:
        """Context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Context manager with commit or rollback teardown."""
        if not self._session_parameters.get("AUTOCOMMIT", False):
            # Either AUTOCOMMIT is turned off, or is not set so we default to old behavior
            if exc_tb is None:
                self.commit()
            else:
                self.rollback()
        self.close()

    def _get_query_status(self, sf_qid: str) -> tuple[QueryStatus, dict[str, Any]]:
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
        status_resp = self.rest.request(
            "/monitoring/queries/" + quote(sf_qid), method="get", client="rest"
        )
        if "queries" not in status_resp["data"]:
            return QueryStatus.FAILED_WITH_ERROR, status_resp
        queries = status_resp["data"]["queries"]
        if len(queries) > 0:
            status = queries[0]["status"]
        status_ret = QueryStatus[status]
        return status_ret, status_resp

    def _cache_query_status(self, sf_qid: str, status_ret: QueryStatus) -> None:
        # If query was started by us and it has finished let's cache this info
        if sf_qid in self._async_sfqids and not self.is_still_running(status_ret):
            self._async_sfqids.pop(
                sf_qid, None
            )  # Prevent KeyError when multiple threads try to remove the same query id
            self._done_async_sfqids[sf_qid] = None

    def _close_at_exit(self):
        with suppress(Exception):
            self.close(retry=False)

    def _process_error_query_status(
        self,
        sf_qid: str,
        status_resp: dict,
        error_message: str = "",
        error_cls: type[Exception] = ProgrammingError,
    ) -> None:
        status_resp = status_resp or {}
        data = status_resp.get("data", {})
        queries = data.get("queries")

        if sf_qid in self._async_sfqids:
            self._async_sfqids.pop(sf_qid, None)
        message = status_resp.get("message")
        if message is None:
            message = ""
        code = queries[0].get("errorCode", -1) if queries else -1
        sql_state = None
        if "data" in status_resp:
            message += queries[0].get("errorMessage", "") if queries else ""
            sql_state = data.get("sqlState")
        Error.errorhandler_wrapper(
            self,
            None,
            error_cls,
            {
                "msg": message or error_message,
                "errno": int(code),
                "sqlstate": sql_state,
                "sfqid": sf_qid,
            },
        )

    def get_query_status(self, sf_qid: str) -> QueryStatus:
        """Retrieves the status of query with sf_qid.

        Query status is returned as a QueryStatus.

        Args:
            sf_qid: Snowflake query id of interest.

        Raises:
            ValueError: if sf_qid is not a valid UUID string.
        """
        status, _ = self._get_query_status(sf_qid)
        self._cache_query_status(sf_qid, status)
        return status

    def get_query_status_throw_if_error(self, sf_qid: str) -> QueryStatus:
        """Retrieves the status of query with sf_qid as a QueryStatus and raises an exception if the query terminated with an error.

        Query status is returned as a QueryStatus.

        Args:
            sf_qid: Snowflake query id of interest.

        Raises:
            ValueError: if sf_qid is not a valid UUID string.
        """
        status, status_resp = self._get_query_status(sf_qid)
        self._cache_query_status(sf_qid, status)
        if self.is_an_error(status):
            self._process_error_query_status(sf_qid, status_resp)
        return status

    def initialize_query_context_cache(self) -> None:
        if not self.is_query_context_cache_disabled:
            self.query_context_cache = QueryContextCache(self.query_context_cache_size)

    def get_query_context(self) -> dict | None:
        if self.is_query_context_cache_disabled:
            return None
        return self.query_context_cache.serialize_to_dict()

    def set_query_context(self, data: dict) -> None:
        if not self.is_query_context_cache_disabled:
            self.query_context_cache.deserialize_json_dict(data)

    @staticmethod
    def is_still_running(status: QueryStatus) -> bool:
        """Checks whether given status is currently running."""
        return status in (
            QueryStatus.RUNNING,
            QueryStatus.QUEUED,
            QueryStatus.RESUMING_WAREHOUSE,
            QueryStatus.QUEUED_REPARING_WAREHOUSE,
            QueryStatus.BLOCKED,
            QueryStatus.NO_DATA,
        )

    @staticmethod
    def is_an_error(status: QueryStatus) -> bool:
        """Checks whether given status means that there has been an error."""
        return status in (
            QueryStatus.ABORTING,
            QueryStatus.FAILED_WITH_ERROR,
            QueryStatus.ABORTED,
            QueryStatus.FAILED_WITH_INCIDENT,
            QueryStatus.DISCONNECTED,
        )

    def _all_async_queries_finished(self) -> bool:
        """Checks whether all async queries started by this Connection have finished executing."""

        if not self._async_sfqids:
            return True

        queries = list(reversed(self._async_sfqids.keys()))

        num_workers = min(self.client_prefetch_threads, len(queries))
        found_unfinished_query = False

        def async_query_check_helper(
            sfq_id: str,
        ) -> bool:
            nonlocal found_unfinished_query
            return found_unfinished_query or self.is_still_running(
                self.get_query_status(sfq_id)
            )

        with ThreadPoolExecutor(
            max_workers=num_workers, thread_name_prefix="async_query_check_"
        ) as tpe:  # We should upgrade to using cancel_futures=True once supporting 3.9+
            futures = (tpe.submit(async_query_check_helper, sfqid) for sfqid in queries)
            for f in as_completed(futures):
                if f.result():
                    found_unfinished_query = True
                    break
            for f in futures:
                f.cancel()

        return not found_unfinished_query

    def _log_telemetry_imported_packages(self) -> None:
        if self._log_imported_packages_in_telemetry:
            # filter out duplicates caused by submodules
            # and internal modules with names starting with an underscore
            imported_modules = {
                k.split(".", maxsplit=1)[0]
                for k in list(sys.modules)
                if not k.startswith("_")
            }
            ts = get_time_millis()
            self._log_telemetry(
                TelemetryData.from_telemetry_data_dict(
                    from_dict={
                        TelemetryField.KEY_TYPE.value: TelemetryField.IMPORTED_PACKAGES.value,
                        TelemetryField.KEY_VALUE.value: str(imported_modules),
                    },
                    timestamp=ts,
                    connection=self,
                )
            )

    def is_valid(self) -> bool:
        """This function tries to answer the question: Is this connection still good for sending queries?
        Attempts to validate the connections both on the TCP/IP and Session levels."""
        logger.debug("validating connection and session")
        if self.is_closed():
            logger.debug("connection is already closed and not valid")
            return False

        try:
            logger.debug("trying to heartbeat into the session to validate")
            hb_result = self.rest._heartbeat()
            session_valid = hb_result.get("success")
            logger.debug("session still valid? %s", session_valid)
            return bool(session_valid)
        except Exception as e:
            logger.debug("session could not be validated due to exception: %s", e)
            return False

    @staticmethod
    def _detect_application() -> None | str:
        if ENV_VAR_PARTNER in os.environ.keys():
            return os.environ[ENV_VAR_PARTNER]
        if "streamlit" in sys.modules:
            return "streamlit"
        if all(
            (jpmod in sys.modules)
            for jpmod in ("ipykernel", "jupyter_core", "jupyter_client")
        ):
            return "jupyter_notebook"
        if "snowbooks" in sys.modules:
            return "snowflake_notebook"
