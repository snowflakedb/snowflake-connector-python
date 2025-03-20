#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ..constants import OAUTH_TYPE_CLIENT_CREDENTIALS
from ..token_cache import TokenCache
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
        token_cache: TokenCache | None = None,
        refresh_token_enabled: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            token_request_url=token_request_url,
            scope=scope,
            token_cache=token_cache,
            refresh_token_enabled=refresh_token_enabled,
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
