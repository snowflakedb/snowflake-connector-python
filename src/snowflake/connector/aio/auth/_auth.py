from __future__ import annotations

import asyncio
import copy
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable

from ...auth import Auth as AuthSync
from ...auth._auth import AUTHENTICATION_REQUEST_KEY_WHITELIST
from ...compat import urlencode
from ...constants import (
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_SERVICE_NAME,
    HTTP_HEADER_USER_AGENT,
)
from ...errorcode import ER_FAILED_TO_CONNECT_TO_DB
from ...errors import (
    BadGatewayError,
    DatabaseError,
    Error,
    ForbiddenError,
    ProgrammingError,
    ServiceUnavailableError,
)
from ...network import (
    ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
    CONTENT_TYPE_APPLICATION_JSON,
    ID_TOKEN_INVALID_LOGIN_REQUEST_GS_CODE,
    OAUTH_ACCESS_TOKEN_EXPIRED_GS_CODE,
    PYTHON_CONNECTOR_USER_AGENT,
    ReauthenticationRequest,
)
from ...sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
from ...token_cache import TokenType
from ._no_auth import AuthNoAuth

if TYPE_CHECKING:
    from ._by_plugin import AuthByPlugin

logger = logging.getLogger(__name__)


class Auth(AuthSync):
    async def authenticate(
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
        if mfa_callback or password_callback:
            # TODO: SNOW-1707210 for mfa_callback and password_callback support
            raise NotImplementedError(
                "mfa_callback or password_callback is not supported in asyncio connector, please open a feature"
                " request issue in github: https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose"
            )
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
            self._rest._connection.cert_revocation_check_mode,
            self._rest._connection._login_timeout,
            self._rest._connection._network_timeout,
            self._rest._connection._socket_timeout,
            self._rest._connection.platform_detection_timeout_seconds,
            http_config=self._rest.session_manager.config,  # AioHttpConfig extends BaseHttpConfig
        )

        body = copy.deepcopy(body_template)
        # Add SPCS token if present, independent of authenticator type.
        self._add_spcs_token_to_body(body)
        # updating request body
        await auth_instance.update_body(body)

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
            ret = await self._rest._post_request(
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

            async def post_request_wrapper(self, url, headers, body) -> None:
                # get the MFA response
                self.ret = await self._rest._post_request(
                    url,
                    headers,
                    body,
                    socket_timeout=auth_instance._socket_timeout,
                )

            # send new request to wait until MFA is approved
            try:
                await asyncio.wait_for(
                    post_request_wrapper(self, url, headers, json.dumps(body)),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.debug("get the MFA response timed out")

            ret = self.ret
            if (
                ret
                and ret["data"]
                and ret["data"].get("nextAction") == "EXT_AUTHN_SUCCESS"
            ):
                body = copy.deepcopy(body_template)
                body["inFlightCtx"] = ret["data"].get("inFlightCtx")
                # Add SPCS token to the follow-up login request as well.
                self._add_spcs_token_to_body(body)
                # final request to get tokens
                ret = await self._rest._post_request(
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
                # Add SPCS token to the password change login request as well.
                self._add_spcs_token_to_body(body)
                # New Password input
                ret = await self._rest._post_request(
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
            await self._rest.update_tokens(
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
            await self._rest._connection._update_parameters(session_parameters)
            return session_parameters
