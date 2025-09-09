from __future__ import annotations

import copy
import json
import logging
import uuid
from datetime import datetime, timezone
from threading import Thread
from typing import TYPE_CHECKING, Any, Callable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_der_private_key,
    load_pem_private_key,
)

from .._utils import get_application_path
from ..compat import urlencode
from ..constants import (
    DAY_IN_SECONDS,
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_SERVICE_NAME,
    HTTP_HEADER_USER_AGENT,
    PARAMETER_CLIENT_REQUEST_MFA_TOKEN,
    PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL,
)
from ..description import (
    COMPILER,
    IMPLEMENTATION,
    OPERATING_SYSTEM,
    PLATFORM,
    PYTHON_VERSION,
)
from ..errorcode import ER_FAILED_TO_CONNECT_TO_DB
from ..errors import (
    BadGatewayError,
    DatabaseError,
    Error,
    ForbiddenError,
    ProgrammingError,
    ServiceUnavailableError,
)
from ..network import (
    ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
    CONTENT_TYPE_APPLICATION_JSON,
    ID_TOKEN_INVALID_LOGIN_REQUEST_GS_CODE,
    OAUTH_ACCESS_TOKEN_EXPIRED_GS_CODE,
    PYTHON_CONNECTOR_USER_AGENT,
    ReauthenticationRequest,
)
from ..platform_detection import detect_platforms
from ..session_manager import SessionManager
from ..sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
from ..token_cache import TokenCache, TokenKey, TokenType
from ..version import VERSION
from .no_auth import AuthNoAuth

if TYPE_CHECKING:
    from . import AuthByPlugin

logger = logging.getLogger(__name__)

# keyring
KEYRING_SERVICE_NAME = "net.snowflake.temporary_token"
KEYRING_USER = "temp_token"
KEYRING_DRIVER_NAME = "SNOWFLAKE-PYTHON-DRIVER"

ID_TOKEN = "ID_TOKEN"
MFA_TOKEN = "MFATOKEN"

AUTHENTICATION_REQUEST_KEY_WHITELIST = {
    "ACCOUNT_NAME",
    "AUTHENTICATOR",
    "CLIENT_APP_ID",
    "CLIENT_APP_VERSION",
    "CLIENT_ENVIRONMENT",
    "EXT_AUTHN_DUO_METHOD",
    "LOGIN_NAME",
    "SESSION_PARAMETERS",
    "SVN_REVISION",
}


class Auth:
    """Snowflake Authenticator."""

    def __init__(self, rest) -> None:
        self._rest = rest
        self._token_cache: TokenCache | None = None

    @staticmethod
    def base_auth_data(
        user,
        account,
        application,
        internal_application_name,
        internal_application_version,
        ocsp_mode,
        login_timeout: int | None = None,
        network_timeout: int | None = None,
        socket_timeout: int | None = None,
        platform_detection_timeout_seconds: float | None = None,
        session_manager: SessionManager | None = None,
    ):
        return {
            "data": {
                "CLIENT_APP_ID": internal_application_name,
                "CLIENT_APP_VERSION": internal_application_version,
                "SVN_REVISION": VERSION[3],
                "ACCOUNT_NAME": account,
                "LOGIN_NAME": user,
                "CLIENT_ENVIRONMENT": {
                    "APPLICATION": application,
                    "APPLICATION_PATH": get_application_path(),
                    "OS": OPERATING_SYSTEM,
                    "OS_VERSION": PLATFORM,
                    "PYTHON_VERSION": PYTHON_VERSION,
                    "PYTHON_RUNTIME": IMPLEMENTATION,
                    "PYTHON_COMPILER": COMPILER,
                    "OCSP_MODE": ocsp_mode.name,
                    "TRACING": logger.getEffectiveLevel(),
                    "LOGIN_TIMEOUT": login_timeout,
                    "NETWORK_TIMEOUT": network_timeout,
                    "SOCKET_TIMEOUT": socket_timeout,
                    "PLATFORM": detect_platforms(
                        platform_detection_timeout_seconds=platform_detection_timeout_seconds,
                        session_manager=session_manager.clone(max_retries=0),
                    ),
                },
            },
        }

    def authenticate(
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

        # For no-auth connection, authentication is no-op, and we can return early here.
        if isinstance(auth_instance, AuthNoAuth):
            return {}

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
            self._rest._connection.login_timeout,
            self._rest._connection._network_timeout,
            self._rest._connection._socket_timeout,
            self._rest._connection.platform_detection_timeout_seconds,
            session_manager=self._rest.session_manager.clone(use_pooling=False),
        )

        body = copy.deepcopy(body_template)
        # updating request body
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
            {
                k: v if k in AUTHENTICATION_REQUEST_KEY_WHITELIST else "******"
                for (k, v) in body["data"].items()
            },
        )

        try:
            ret = self._rest._post_request(
                url,
                headers,
                json.dumps(body),
                socket_timeout=auth_instance._socket_timeout,
            )
        except ForbiddenError as err:
            # HTTP 403
            raise err.__class__(
                msg=(
                    "Failed to connect to DB. "
                    "Verify the account name is correct: {host}:{port}. "
                    "{message}"
                ).format(
                    host=self._rest._host, port=self._rest._port, message=str(err)
                ),
                errno=ER_FAILED_TO_CONNECT_TO_DB,
                sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
            )
        except (ServiceUnavailableError, BadGatewayError) as err:
            # HTTP 502/504
            raise err.__class__(
                msg=(
                    "Failed to connect to DB. "
                    "Service is unavailable: {host}:{port}. "
                    "{message}"
                ).format(
                    host=self._rest._host, port=self._rest._port, message=str(err)
                ),
                errno=ER_FAILED_TO_CONNECT_TO_DB,
                sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
            )

        # waiting for MFA authentication
        if ret["data"] and ret["data"].get("nextAction") in (
            "EXT_AUTHN_DUO_ALL",
            "EXT_AUTHN_DUO_PUSH_N_PASSCODE",
        ):
            body["inFlightCtx"] = ret["data"].get("inFlightCtx")
            body["data"]["EXT_AUTHN_DUO_METHOD"] = "push"
            self.ret = {"message": "Timeout", "data": {}}

            def post_request_wrapper(self, url, headers, body) -> None:
                # get the MFA response
                self.ret = self._rest._post_request(
                    url,
                    headers,
                    body,
                    socket_timeout=auth_instance._socket_timeout,
                )

            # send new request to wait until MFA is approved
            t = Thread(
                target=post_request_wrapper, args=[self, url, headers, json.dumps(body)]
            )
            t.daemon = True
            t.start()
            if callable(mfa_callback):
                c = mfa_callback()
                while not self.ret or self.ret.get("message") == "Timeout":
                    next(c)
            else:
                # _post_request should already terminate on timeout, so this is just a safeguard
                t.join(timeout=timeout)

            ret = self.ret
            if (
                ret
                and ret["data"]
                and ret["data"].get("nextAction") == "EXT_AUTHN_SUCCESS"
            ):
                body = copy.deepcopy(body_template)
                body["inFlightCtx"] = ret["data"].get("inFlightCtx")
                # final request to get tokens
                ret = self._rest._post_request(
                    url,
                    headers,
                    json.dumps(body),
                    socket_timeout=auth_instance._socket_timeout,
                )
            elif not ret or not ret["data"] or not ret["data"].get("token"):
                # not token is returned.
                Error.errorhandler_wrapper(
                    self._rest._connection,
                    None,
                    DatabaseError,
                    {
                        "msg": (
                            "Failed to connect to DB. MFA "
                            "authentication failed: {"
                            "host}:{port}. {message}"
                        ).format(
                            host=self._rest._host,
                            port=self._rest._port,
                            message=ret["message"],
                        ),
                        "errno": ER_FAILED_TO_CONNECT_TO_DB,
                        "sqlstate": SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                    },
                )
                return session_parameters  # required for unit test

        elif ret["data"] and ret["data"].get("nextAction") == "PWD_CHANGE":
            if callable(password_callback):
                body = copy.deepcopy(body_template)
                body["inFlightCtx"] = ret["data"].get("inFlightCtx")
                body["data"]["LOGIN_NAME"] = user
                body["data"]["PASSWORD"] = (
                    auth_instance.password
                    if hasattr(auth_instance, "password")
                    else None
                )
                body["data"]["CHOSEN_NEW_PASSWORD"] = password_callback()
                # New Password input
                ret = self._rest._post_request(
                    url,
                    headers,
                    json.dumps(body),
                    socket_timeout=auth_instance._socket_timeout,
                )

        logger.debug("completed authentication")
        if not ret["success"]:
            errno = ret.get("code", ER_FAILED_TO_CONNECT_TO_DB)
            if errno == ID_TOKEN_INVALID_LOGIN_REQUEST_GS_CODE:
                # clear stored id_token if failed to connect because of id_token
                # raise an exception for reauth without id_token
                self._rest.id_token = None
                self._delete_temporary_credential(
                    self._rest._host, user, TokenType.ID_TOKEN
                )
                raise ReauthenticationRequest(
                    ProgrammingError(
                        msg=ret["message"],
                        errno=int(errno),
                        sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                    )
                )
            elif errno == OAUTH_ACCESS_TOKEN_EXPIRED_GS_CODE:
                raise ReauthenticationRequest(
                    ProgrammingError(
                        msg=ret["message"],
                        errno=int(errno),
                        sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                    )
                )

            from . import AuthByKeyPair

            if isinstance(auth_instance, AuthByKeyPair):
                logger.debug(
                    "JWT Token authentication failed. "
                    "Token expires at: %s. "
                    "Current Time: %s",
                    str(auth_instance._jwt_token_exp),
                    str(datetime.now(timezone.utc).replace(tzinfo=None)),
                )
            from . import AuthByUsrPwdMfa

            if isinstance(auth_instance, AuthByUsrPwdMfa):
                self._delete_temporary_credential(
                    self._rest._host, user, TokenType.MFA_TOKEN
                )
            Error.errorhandler_wrapper(
                self._rest._connection,
                None,
                DatabaseError,
                {
                    "msg": (
                        "Failed to connect to DB: {host}:{port}. " "{message}"
                    ).format(
                        host=self._rest._host,
                        port=self._rest._port,
                        message=ret["message"],
                    ),
                    "errno": ER_FAILED_TO_CONNECT_TO_DB,
                    "sqlstate": SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                },
            )
        else:
            logger.debug(
                "token = %s",
                (
                    "******"
                    if ret["data"] and ret["data"].get("token") is not None
                    else "NULL"
                ),
            )
            logger.debug(
                "master_token = %s",
                (
                    "******"
                    if ret["data"] and ret["data"].get("masterToken") is not None
                    else "NULL"
                ),
            )
            logger.debug(
                "id_token = %s",
                (
                    "******"
                    if ret["data"] and ret["data"].get("idToken") is not None
                    else "NULL"
                ),
            )
            logger.debug(
                "mfa_token = %s",
                (
                    "******"
                    if ret["data"] and ret["data"].get("mfaToken") is not None
                    else "NULL"
                ),
            )
            if not ret["data"]:
                Error.errorhandler_wrapper(
                    None,
                    None,
                    Error,
                    {
                        "msg": "There is no data in the returning response, please retry the operation."
                    },
                )
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

    def _read_temporary_credential(
        self,
        host: str,
        user: str,
        cred_type: TokenType,
    ) -> str | None:
        return self.get_token_cache().retrieve(TokenKey(host, user, cred_type))

    def read_temporary_credentials(
        self,
        host: str,
        user: str,
        session_parameters: dict[str, Any],
    ) -> None:
        if session_parameters.get(PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL, False):
            self._rest.id_token = self._read_temporary_credential(
                host,
                user,
                TokenType.ID_TOKEN,
            )

        if session_parameters.get(PARAMETER_CLIENT_REQUEST_MFA_TOKEN, False):
            self._rest.mfa_token = self._read_temporary_credential(
                host,
                user,
                TokenType.MFA_TOKEN,
            )

    def _write_temporary_credential(
        self,
        host: str,
        user: str,
        cred_type: TokenType,
        cred: str | None,
    ) -> None:
        if not cred:
            logger.debug(
                "no credential is given when try to store temporary credential"
            )
            return
        self.get_token_cache().store(TokenKey(host, user, cred_type), cred)

    def write_temporary_credentials(
        self,
        host: str,
        user: str,
        session_parameters: dict[str, Any],
        response: dict[str, Any],
    ) -> None:
        if (
            self._rest._connection.auth_class.consent_cache_id_token
            and session_parameters.get(
                PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL, False
            )
        ):
            self._write_temporary_credential(
                host, user, TokenType.ID_TOKEN, response["data"].get("idToken")
            )

        if session_parameters.get(PARAMETER_CLIENT_REQUEST_MFA_TOKEN, False):
            self._write_temporary_credential(
                host, user, TokenType.MFA_TOKEN, response["data"].get("mfaToken")
            )

    def _delete_temporary_credential(
        self, host: str, user: str, cred_type: TokenType
    ) -> None:
        self.get_token_cache().remove(TokenKey(host, user, cred_type))

    def get_token_cache(self) -> TokenCache:
        if self._token_cache is None:
            self._token_cache = TokenCache.make(
                skip_file_permissions_check=self._rest._connection._unsafe_skip_file_permissions_check
            )
        return self._token_cache


def get_token_from_private_key(
    user: str, account: str, privatekey_path: str, key_password: str | None
) -> str:
    encoded_password = key_password.encode() if key_password is not None else None
    with open(privatekey_path, "rb") as key:
        p_key = load_pem_private_key(
            key.read(), password=encoded_password, backend=default_backend()
        )

    private_key = p_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    from . import AuthByKeyPair

    auth_instance = AuthByKeyPair(
        private_key,
        DAY_IN_SECONDS,
    )  # token valid for 24 hours
    return auth_instance.prepare(account=account, user=user)


def get_public_key_fingerprint(private_key_file: str, password: str) -> str:
    """Helper function to generate the public key fingerprint from the private key file"""
    with open(private_key_file, "rb") as key:
        p_key = load_pem_private_key(
            key.read(), password=password.encode(), backend=default_backend()
        )
    private_key = p_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    private_key = load_der_private_key(
        data=private_key, password=None, backend=default_backend()
    )
    from . import AuthByKeyPair

    return AuthByKeyPair.calculate_public_key_fingerprint(private_key)
