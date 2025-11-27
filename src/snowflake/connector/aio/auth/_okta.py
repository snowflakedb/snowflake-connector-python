#!/usr/bin/env python


from __future__ import annotations

import json
import logging
import time
from functools import partial
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from snowflake.connector.aio.auth import Auth

from ... import DatabaseError, Error
from ...auth.okta import AuthByOkta as AuthByOktaSync
from ...compat import urlencode
from ...constants import (
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_SERVICE_NAME,
    HTTP_HEADER_USER_AGENT,
)
from ...errorcode import ER_IDP_CONNECTION_ERROR
from ...errors import RefreshTokenError
from ...network import CONTENT_TYPE_APPLICATION_JSON, PYTHON_CONNECTOR_USER_AGENT
from ...sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
from ._by_plugin import AuthByPlugin as AuthByPluginAsync

if TYPE_CHECKING:
    from .. import SnowflakeConnection

logger = logging.getLogger(__name__)


class AuthByOkta(AuthByPluginAsync, AuthByOktaSync):
    def __init__(self, application: str, **kwargs) -> None:
        AuthByOktaSync.__init__(self, application, **kwargs)

    async def reset_secrets(self) -> None:
        AuthByOktaSync.reset_secrets(self)

    async def prepare(
        self,
        *,
        conn: SnowflakeConnection,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        password: str,
        **kwargs: Any,
    ) -> None:
        """SAML Authentication.

        Steps are:
        1.  query GS to obtain IDP token and SSO url
        2.  IMPORTANT Client side validation:
            validate both token url and sso url contains same prefix
            (protocol + host + port) as the given authenticator url.
            Explanation:
            This provides a way for the user to 'authenticate' the IDP it is
            sending his/her credentials to.  Without such a check, the user could
            be coerced to provide credentials to an IDP impersonator.
        3.  query IDP token url to authenticate and retrieve access token
        4.  given access token, query IDP URL snowflake app to get SAML response
        5.  IMPORTANT Client side validation:
            validate the post back url come back with the SAML response
            contains the same prefix as the Snowflake's server url, which is the
            intended destination url to Snowflake.
        Explanation:
            This emulates the behavior of IDP initiated login flow in the user
            browser where the IDP instructs the browser to POST the SAML
            assertion to the specific SP endpoint.  This is critical in
            preventing a SAML assertion issued to one SP from being sent to
            another SP.
        """
        logger.debug("authenticating by SAML")
        headers, sso_url, token_url = await self._step1(
            conn,
            authenticator,
            service_name,
            account,
            user,
        )
        await self._step2(conn, authenticator, sso_url, token_url)
        response_html = await self._step4(
            conn,
            partial(self._step3, conn, headers, token_url, user, password),
            sso_url,
        )
        await self._step5(conn, response_html)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthByOktaSync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthByOktaSync.update_body(self, body)

    async def _step1(
        self,
        conn: SnowflakeConnection,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
    ) -> tuple[dict[str, str], str, str]:
        logger.debug("step 1: query GS to obtain IDP token and SSO url")

        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = service_name
        url = "/session/authenticator-request"
        body = Auth.base_auth_data(
            user,
            account,
            conn.application,
            conn._internal_application_name,
            conn._internal_application_version,
            conn._ocsp_mode(),
            conn.cert_revocation_check_mode,
            conn.login_timeout,
            conn.network_timeout,
            conn.socket_timeout,
            conn.platform_detection_timeout_seconds,
            http_config=conn._session_manager.config,  # AioHttpConfig extends BaseHttpConfig
        )

        body["data"]["AUTHENTICATOR"] = authenticator
        logger.debug(
            "account=%s, authenticator=%s",
            account,
            authenticator,
        )
        ret = await conn.rest._post_request(
            url,
            headers,
            json.dumps(body),
            timeout=conn.login_timeout,
            socket_timeout=conn.login_timeout,
        )

        if not ret["success"]:
            await self._handle_failure(conn=conn, ret=ret)

        data = ret["data"]
        token_url = data["tokenUrl"]
        sso_url = data["ssoUrl"]
        return headers, sso_url, token_url

    async def _step2(
        self,
        conn: SnowflakeConnection,
        authenticator: str,
        sso_url: str,
        token_url: str,
    ) -> None:
        return super()._step2(conn, authenticator, sso_url, token_url)

    @staticmethod
    async def _step3(
        conn: SnowflakeConnection,
        headers: dict[str, str],
        token_url: str,
        user: str,
        password: str,
    ) -> str:
        logger.debug(
            "step 3: query IDP token url to authenticate and " "retrieve access token"
        )
        data = {
            "username": user,
            "password": password,
        }
        ret = await conn.rest.fetch(
            "post",
            token_url,
            headers,
            data=json.dumps(data),
            timeout=conn.login_timeout,
            socket_timeout=conn.login_timeout,
            catch_okta_unauthorized_error=True,
        )
        one_time_token = ret.get("sessionToken", ret.get("cookieToken"))
        if not one_time_token:
            Error.errorhandler_wrapper(
                conn,
                None,
                DatabaseError,
                {
                    "msg": (
                        "The authentication failed for {user} "
                        "by {token_url}.".format(
                            token_url=token_url,
                            user=user,
                        )
                    ),
                    "errno": ER_IDP_CONNECTION_ERROR,
                    "sqlstate": SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                },
            )
        return one_time_token

    @staticmethod
    async def _step4(
        conn: SnowflakeConnection,
        generate_one_time_token: Callable[[], Awaitable[str]],
        sso_url: str,
    ) -> dict[Any, Any]:
        logger.debug("step 4: query IDP URL snowflake app to get SAML " "response")
        timeout_time = time.time() + conn.login_timeout if conn.login_timeout else None
        response_html = {}
        origin_sso_url = sso_url
        while timeout_time is None or time.time() < timeout_time:
            try:
                url_parameters = {
                    "RelayState": "/some/deep/link",
                    "onetimetoken": await generate_one_time_token(),
                }
                sso_url = origin_sso_url + "?" + urlencode(url_parameters)
                headers = {
                    HTTP_HEADER_ACCEPT: "*/*",
                }
                remaining_timeout = timeout_time - time.time() if timeout_time else None
                response_html = await conn.rest.fetch(
                    "get",
                    sso_url,
                    headers,
                    timeout=remaining_timeout,
                    socket_timeout=remaining_timeout,
                    is_raw_text=True,
                    is_okta_authentication=True,
                )
                break
            except RefreshTokenError:
                logger.debug("step4: refresh token for re-authentication")
        return response_html

    async def _step5(
        self,
        conn: SnowflakeConnection,
        response_html: str,
    ) -> None:
        return super()._step5(conn, response_html)
