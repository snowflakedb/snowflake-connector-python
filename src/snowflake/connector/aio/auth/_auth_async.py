#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import copy
import json
import logging
from typing import TYPE_CHECKING, Any, Callable

from ...auth import Auth
from ...auth._auth import ID_TOKEN, delete_temporary_credential
from ...errorcode import ER_FAILED_TO_CONNECT_TO_DB
from ...errors import (
    BadGatewayError,
    DatabaseError,
    Error,
    ForbiddenError,
    ProgrammingError,
    ServiceUnavailableError,
)
from ...network import ID_TOKEN_INVALID_LOGIN_REQUEST_GS_CODE, ReauthenticationRequest
from ...sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED

if TYPE_CHECKING:
    from .by_plugin_async import AuthByPluginAsync

logger = logging.getLogger(__name__)


class AuthAsync(Auth):
    async def authenticate(
        self,
        auth_instance: AuthByPluginAsync,
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
            # TODO: what's the usage of callback here and whether callback should be async?
            raise NotImplementedError(
                "mfa_callback or password_callback not supported for asyncio"
            )
        logger.debug("authenticate")

        if timeout is None:
            timeout = auth_instance.timeout

        url, headers, body, body_template = self._prepare_authenticate_request(
            auth_instance,
            account,
            user,
            database,
            schema,
            warehouse,
            role,
            passcode,
            passcode_in_password,
            session_parameters,
        )

        # updating request body
        logger.debug("assertion content: %s", auth_instance.assertion_content)
        await auth_instance.update_body(body)

        logger.debug(
            "body['data']: %s",
            {k: v for (k, v) in body["data"].items() if k != "PASSWORD"},
        )

        try:
            ret = await self._rest._post_request(
                url,
                headers,
                json.dumps(body),
                socket_timeout=auth_instance._socket_timeout,
            )
        # TODO: encapsulate error handling logic to be shared between sync and async
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
            raise NotImplementedError("asyncio MFA not supported")
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
                delete_temporary_credential(self._rest._host, user, ID_TOKEN)
                raise ReauthenticationRequest(
                    ProgrammingError(
                        msg=ret["message"],
                        errno=int(errno),
                        sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                    )
                )
            # TODO: error handling for AuthByKeyPairAsync and AuthByUsrPwdMfaAsync
            # from . import AuthByKeyPair
            #
            # if isinstance(auth_instance, AuthByKeyPair):
            #     logger.debug(
            #         "JWT Token authentication failed. "
            #         "Token expires at: %s. "
            #         "Current Time: %s",
            #         str(auth_instance._jwt_token_exp),
            #         str(datetime.now(timezone.utc).replace(tzinfo=None)),
            #     )
            # from . import AuthByUsrPwdMfa
            #
            # if isinstance(auth_instance, AuthByUsrPwdMfa):
            #     delete_temporary_credential(self._rest._host, user, MFA_TOKEN)
            # TODO: can errorhandler of a connection be async? should we support both sync and async
            #  users could perform async ops in the error handling
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
