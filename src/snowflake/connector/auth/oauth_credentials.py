#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import base64
import json
import logging
from typing import TYPE_CHECKING, Any

from ..constants import OAUTH_TYPE_CLIENT_CREDENTIALS
from ..errorcode import ER_IDP_CONNECTION_ERROR
from ..network import OAUTH_AUTHENTICATOR
from ..vendored import urllib3
from .by_plugin import AuthByPlugin, AuthType

if TYPE_CHECKING:
    from .. import SnowflakeConnection

logger = logging.getLogger(__name__)


class AuthByOauthCredentials(AuthByPlugin):
    def __init__(
        self,
        application: str,
        client_id: str,
        client_secret: str,
        authentication_url: str,
        token_request_url: str,
        scope: str,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._oauth_token: str | None = None
        self._application = application
        self._origin: str | None = None
        self._client_id = client_id
        self._client_secret = client_secret
        self._authentication_url = authentication_url
        self._token_request_url = token_request_url
        self._scope = scope

    def type_(self) -> AuthType:
        return AuthType.OAUTH

    def reset_secrets(self) -> None:
        return

    def update_body(self, body: dict[Any, Any]) -> None:
        body["data"]["AUTHENTICATOR"] = OAUTH_AUTHENTICATOR
        body["data"]["TOKEN"] = self._oauth_token
        body["data"]["OAUTH_TYPE"] = OAUTH_TYPE_CLIENT_CREDENTIALS

    def prepare(
        self,
        conn: SnowflakeConnection,
        **kwargs: Any,
    ) -> None:
        logger.debug("authenticating with OAuth client credentials")
        fields = {
            "grant_type": "client_credentials",
            "scope": self._scope,
        }
        auth_header = base64.b64encode(
            f"{self._client_id}:{self._client_secret}".encode()
        ).decode()
        resp = urllib3.PoolManager().request_encode_body(
            # TODO: use network pool to gain use of proxy settings and so on
            method="POST",
            url=self._token_request_url,
            headers={
                "Authorization": f"Basic {auth_header}",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            },
            encode_multipart=False,
            fields=fields,
        )
        try:
            response = json.loads(resp.data.decode())
            self._oauth_token = response["access_token"]
        except (
            json.JSONDecodeError,
            KeyError,
        ):
            logger.error("oauth response invalid, does not contain 'access_token'")
            logger.debug(
                "received the following response body when requesting oauth token: %s",
                resp.data,
            )
            self._handle_failure(
                conn=conn,
                ret={
                    "code": ER_IDP_CONNECTION_ERROR,
                    "message": "Invalid HTTP request from web browser. Idp "
                    "authentication could have failed.",
                },
            )
        return

    def reauthenticate(
        self, *, conn: SnowflakeConnection, **kwargs: Any
    ) -> dict[str, bool]:
        conn.authenticate_with_retry(self)
        return {"success": True}

    @property
    def assertion_content(self) -> str | None:
        return self._oauth_token or ""
