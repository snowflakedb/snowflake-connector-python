#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import logging
import uuid
from functools import partial
from io import StringIO
from logging import getLogger
from threading import Lock
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Iterable,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
)

from .compat import IS_WINDOWS
from .constants import (
    DEFAULT_S3_CONNECTION_POOL_SIZE,
    PARAMETER_SERVICE_NAME,
    QueryStatus,
)
from .converter import SnowflakeConverter
from .cursor import LOG_MAX_QUERY_LENGTH, SnowflakeCursor
from .description import (
    CLIENT_NAME,
    CLIENT_VERSION,
    PLATFORM,
    PYTHON_VERSION,
    SNOWFLAKE_CONNECTOR_VERSION,
)
from .errorcode import (
    ER_CONNECTION_IS_CLOSED,
    ER_FAILED_PROCESSING_PYFORMAT,
    ER_INVALID_VALUE,
)
from .errors import DatabaseError, Error, ProgrammingError
from .network import DEFAULT_AUTHENTICATOR
from .sqlstate import SQLSTATE_CONNECTION_NOT_EXISTS, SQLSTATE_FEATURE_NOT_SUPPORTED
from .util_text import split_statements

SUPPORTED_PARAMSTYLES = {
    "qmark",
    "numeric",
    "format",
    "pyformat",
}


def DefaultConverterClass():
    if IS_WINDOWS:
        from .converter_issue23517 import SnowflakeConverterIssue23517

        return SnowflakeConverterIssue23517
    else:
        from .converter import SnowflakeConverter

        return SnowflakeConverter


# Default configs, tuple of default variable and accepted types
DEFAULT_CONFIGURATION: Dict[str, Tuple[Any, Union[Type, Tuple[Type, ...]]]] = {
    "dsn": (None, (type(None), str)),  # standard
    "user": ("", str),  # standard
    "password": ("", str),  # standard
    "host": ("127.0.0.1", str),  # standard
    "port": (8080, (int, str)),  # standard
    "database": (None, (type(None), str)),  # standard
    "proxy_host": (None, (type(None), str)),  # snowflake
    "proxy_port": (None, (type(None), str)),  # snowflake
    "proxy_user": (None, (type(None), str)),  # snowflake
    "proxy_password": (None, (type(None), str)),  # snowflake
    "protocol": ("http", str),  # snowflake
    "warehouse": (None, (type(None), str)),  # snowflake
    "region": (None, (type(None), str)),  # snowflake
    "account": (None, (type(None), str)),  # snowflake
    "schema": (None, (type(None), str)),  # snowflake
    "role": (None, (type(None), str)),  # snowflake
    "session_id": (None, (type(None), str)),  # snowflake
    "login_timeout": (120, int),  # login timeout
    "network_timeout": (
        None,
        (type(None), int),
    ),  # network timeout (infinite by default)
    "passcode_in_password": (False, bool),  # Snowflake MFA
    "passcode": (None, (type(None), str)),  # Snowflake MFA
    "private_key": (None, (type(None), str)),
    "token": (None, (type(None), str)),  # OAuth or JWT Token
    "authenticator": (DEFAULT_AUTHENTICATOR, (type(None), str)),
    "mfa_callback": (None, (type(None), Callable)),
    "password_callback": (None, (type(None), Callable)),
    "application": (CLIENT_NAME, (type(None), str)),
    "internal_application_name": (CLIENT_NAME, (type(None), str)),
    "internal_application_version": (CLIENT_VERSION, (type(None), str)),
    "insecure_mode": (False, bool),  # Error security fix requirement
    "ocsp_fail_open": (True, bool),  # fail open on ocsp issues, default true
    "inject_client_pause": (0, int),  # snowflake internal
    "session_parameters": (None, (type(None), dict)),  # snowflake session parameters
    "autocommit": (None, (type(None), bool)),  # snowflake
    "client_session_keep_alive": (None, (type(None), bool)),  # snowflake
    "client_session_keep_alive_heartbeat_frequency": (
        None,
        (type(None), int),
    ),  # snowflake
    "client_prefetch_threads": (4, int),  # snowflake
    "s3_connection_pool_s": (DEFAULT_S3_CONNECTION_POOL_SIZE, int),  # boto3 pool size
    "numpy": (False, bool),  # snowflake
    "ocsp_response_cache_filename": (None, (type(None), str)),  # snowflake internal
    "converter_class": (DefaultConverterClass(), SnowflakeConverter),
    "validate_default_parameters": (False, bool),  # snowflake
    "probe_connection": (False, bool),  # snowflake
    "paramstyle": (None, (type(None), str)),  # standard/snowflake
    "timezone": (None, (type(None), str)),  # snowflake
    "consent_cache_id_token": (True, bool),  # snowflake
    "service_name": (None, (type(None), str)),  # snowflake,
    "support_negative_year": (True, bool),  # snowflake
    "log_max_query_length": (LOG_MAX_QUERY_LENGTH, int),  # snowflake
    "disable_request_pooling": (False, bool),  # snowflake
    # enable temporary credential file for Linux, default false. Mac/Win will overlook this
    "client_store_temporary_credential": (False, bool),
    "client_request_mfa_token": (False, bool),
    "use_openssl_only": (
        False,
        bool,
    ),  # only use openssl instead of python only crypto modules
    # whether to convert Arrow number values to decimal instead of doubles
    "arrow_number_to_decimal": (False, bool),
    "enable_stage_s3_privatelink_for_us_east_1": (
        False,
        bool,
    ),  # only use regional url when the param is set
    # Allows cursors to be re-iterable
    "reuse_results": (False, bool),
    "use_new_put_get": (True, bool),
}

logger = getLogger(__name__)


class SnowflakeConnectionBase:
    """Implementation of the connection object for the Snowflake Database.

    Attributes:
    session_id: The session ID of the connection.
    user: The user name used in the connection.
    host: The host name the connection attempts to connect to.
    port: The port to communicate with on the host.
    region: Region name if not the default Snowflake Database deployment.
    account: Account name to be used to authenticate with Snowflake.
    database: Database to use on Snowflake.
    schema: Schema in use on Snowflake.
    warehouse: Warehouse to be used on Snowflake.
    role: Role in use on Snowflake.
    network_timeout: Network timeout. Used for general purpose.
    application: Application name to communicate with Snowflake as.
    errorhandler: Handler used with errors. By default, an exception will be raised on error.
    converter_class: Handler used to convert data to Python native objects.
    validate_default_parameters: Validate database, schema, role and warehouse used on Snowflake.
    is_pyformat: Whether the current argument binding is pyformat or format.
    use_openssl_only: Use OpenSSL instead of pure Python libraries for signature verification and encryption.
    """

    def __init__(self, **kwargs):
        self._errorhandler = Error.default_errorhandler
        self._session_parameters: Dict[str, Union[str, int, bool]] = {}
        self.telemetry_enabled = False
        self.converter = None
        self.sequence_counter = 0
        self._lock_sequence_counter = Lock()

        for name, (value, _) in DEFAULT_CONFIGURATION.items():
            setattr(self, "_" + name, value)

        logger.info(
            "Snowflake Connector for Python Version: %s, "
            "Python Version: %s, Platform: %s",
            SNOWFLAKE_CONNECTOR_VERSION,
            PYTHON_VERSION,
            PLATFORM,
        )

        self.converter = self._converter_class(
            use_numpy=self._numpy, support_negative_year=self._support_negative_year
        )

    def __del__(self):  # pragma: no cover
        pass

    def _config(self):
        if self._paramstyle is None:
            import snowflake.connector

            self._paramstyle = snowflake.connector.paramstyle
        elif self._paramstyle not in SUPPORTED_PARAMSTYLES:
            raise ProgrammingError(
                msg="Invalid paramstyle is specified", errno=ER_INVALID_VALUE
            )

    @property
    def is_pyformat(self):
        return self._paramstyle in ("pyformat", "format")

    @property
    def service_name(self):
        return self._service_name

    @property
    def application(self):
        return self._application

    @service_name.setter
    def service_name(self, value):
        self._service_name = value

    @property
    def network_timeout(self):
        return int(self._network_timeout) if self._network_timeout is not None else None

    @property
    def log_max_query_length(self):
        return self._log_max_query_length

    def connect(self, **kwargs):
        """Establishes connection to Snowflake."""
        pass

    def close(self, retry=True):
        pass

    def is_closed(self) -> bool:
        """Checks whether the connection has been closed."""
        return False

    # Commit, rollback related

    def commit(self):
        """Commits the current transaction."""
        self.cursor().execute("COMMIT")

    def rollback(self):
        """Rolls back the current transaction."""
        self.cursor().execute("ROLLBACK")

    def autocommit(self, mode: bool) -> None:
        """Sets autocommit mode to True, or False. Defaults to True."""
        if self.is_closed():
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
                    "msg": "Invalid parameter: {}".format(mode),
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

    # Query submission related

    def cursor(
        self, cursor_class: Type[SnowflakeCursor] = SnowflakeCursor
    ) -> SnowflakeCursor:
        """Creates a cursor object. Each statement will be executed in a new cursor object."""
        logger.debug("cursor")
        if self.is_closed():
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
    ) -> Generator["SnowflakeCursor", None, None]:
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

    def cmd_query(
        self,
        sql: str,
        sequence_counter: int,
        request_id: uuid.UUID,
        binding_params: Union[None, Tuple, Dict[str, Dict[str, str]]] = None,
        binding_stage: Optional[str] = None,
        is_file_transfer: bool = False,
        statement_params: Optional[Dict[str, str]] = None,
        is_internal: bool = False,
        describe_only: bool = False,
        _no_results: bool = False,
        _update_current_object: bool = True,
    ) -> Dict:
        pass

    # Context manager related

    def __enter__(self):
        """Context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager with commit or rollback teardown."""
        if not self._session_parameters.get("AUTOCOMMIT", False):
            # Either AUTOCOMMIT is turned off, or is not set so we default to old behavior
            if exc_tb is None:
                self.commit()
            else:
                self.rollback()
        self.close()

    # Sequence id related
    def _next_sequence_counter(self):
        """Gets next sequence counter. Used internally."""
        with self._lock_sequence_counter:
            self.sequence_counter += 1
            logger.debug("sequence counter: %s", self.sequence_counter)
            return self.sequence_counter

    # Async queries related

    def get_query_status(self, sf_qid: str) -> QueryStatus:
        raise NotImplementedError

    def get_query_status_throw_if_error(self, sf_qid: str) -> QueryStatus:
        raise NotImplementedError

    @staticmethod
    def is_an_error(status: QueryStatus) -> bool:
        """Checks whether given status means that there has been an error."""
        return status in (
            QueryStatus.ABORTING,
            QueryStatus.FAILED_WITH_ERROR,
            QueryStatus.ABORTED,
            QueryStatus.FAILED_WITH_INCIDENT,
            QueryStatus.DISCONNECTED,
            QueryStatus.BLOCKED,
        )

    @staticmethod
    def is_still_running(status: QueryStatus) -> bool:
        """Checks whether given status is currently running."""
        return status in (
            QueryStatus.RUNNING,
            QueryStatus.RESUMING_WAREHOUSE,
            QueryStatus.QUEUED,
            QueryStatus.QUEUED_REPARING_WAREHOUSE,
            QueryStatus.NO_DATA,
        )

    # OCSP related

    @staticmethod
    def setup_ocsp_privatelink(app, hostname):
        raise NotImplementedError

    # Client side binding related

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

    def _process_params_dict(
        self, params: Dict[Any, Any], cursor: Optional["SnowflakeCursor"] = None
    ) -> Dict:
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

    def _process_params_pyformat(
        self,
        params: Optional[Union[Any, Sequence[Any], Dict[Any, Any]]],
        cursor: Optional["SnowflakeCursor"] = None,
    ) -> Union[Tuple[Any], Dict[str, Any]]:
        """Process parameters for client-side parameter binding.

        Args:
            params: Either a sequence, or a dictionary of parameters, if anything else
                is given then it will be put into a list and processed that way.
            cursor: The SnowflakeCursor used to report errors if necessary.
        """
        if params is None:
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

    # TODO we could probably rework this to not make dicts like this: {'1': 'value', '2': '13'}
    def _process_params_qmarks(
        self,
        params: Optional[Sequence],
        cursor: Optional["SnowflakeCursor"] = None,
    ) -> Optional[Dict[str, Dict[str, str]]]:
        if not params:
            return None
        processed_params = {}

        if not isinstance(params, (list, tuple)):
            errorvalue = {
                "msg": "Binding parameters must be a list: {}".format(params),
                "errno": ER_FAILED_PROCESSING_PYFORMAT,
            }
            Error.errorhandler_wrapper(self, cursor, ProgrammingError, errorvalue)

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

    def update_parameters(self, parameters: Dict[str, Union[str, int, bool]]) -> None:
        with self._lock_converter:
            self.converter.set_parameters(parameters)
        self._session_parameters.update(parameters)

        if PARAMETER_SERVICE_NAME in parameters:
            self.service_name = parameters[PARAMETER_SERVICE_NAME]

        self._update_parameters(parameters)

    def _update_parameters(self, parameters: Dict[str, Union[str, int, bool]]) -> None:
        pass

    def _format_query_for_log(self, query):
        ret = " ".join(line.strip() for line in query.split("\n"))
        return (
            ret
            if len(ret) < self.log_max_query_length
            else ret[0 : self.log_max_query_length] + "..."
        )
