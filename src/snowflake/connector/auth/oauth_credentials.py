#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ..constants import OAUTH_TYPE_CLIENT_CREDENTIALS
from ._oauth_base import AuthByOAuthBase

if TYPE_CHECKING:
    from .. import SnowflakeConnection

logger = logging.getLogger(__name__)


class AuthByOauthCredentials(AuthByOAuthBase):
    """Authenticates user by OAuth credentials - a client_id/client_secret pair."""

    def __init__(
        self,
        application: str,
        client_id: str,
        client_secret: str,
        token_request_url: str,
        scope: str,
        connection: SnowflakeConnection | None = None,
        **kwargs,
    ) -> None:
        self._validate_client_credentials_present(client_id, client_secret, connection)
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            token_request_url=token_request_url,
            scope=scope,
            token_cache=None,
            refresh_token_enabled=False,
            **kwargs,
        )
        self._application = application
        self._origin: str | None = None

    def _get_oauth_type_id(self) -> str:
        return OAUTH_TYPE_CLIENT_CREDENTIALS

    def _request_tokens(
        self,
        *,
        conn: SnowflakeConnection,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        **kwargs: Any,
    ) -> (str | None, str | None):
        logger.debug("authenticating with OAuth client credentials flow")
        fields = {
            "grant_type": "client_credentials",
            "scope": self._scope,
        }
        return self._get_request_token_response(conn, fields)
