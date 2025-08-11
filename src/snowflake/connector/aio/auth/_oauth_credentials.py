#!/usr/bin/env python

from __future__ import annotations

import logging
from typing import Any

from ...auth.oauth_credentials import (
    AuthByOauthCredentials as AuthByOauthCredentialsSync,
)
from ...token_cache import TokenCache
from ._by_plugin import AuthByPlugin as AuthByPluginAsync

logger = logging.getLogger(__name__)


class AuthByOauthCredentials(AuthByPluginAsync, AuthByOauthCredentialsSync):
    """Async version of OAuth client credentials authenticator."""

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
        """Initializes an instance with OAuth client credentials parameters."""
        logger.debug(
            "OAuth authentication is not supported in async version - falling back to sync implementation"
        )
        AuthByOauthCredentialsSync.__init__(
            self,
            application=application,
            client_id=client_id,
            client_secret=client_secret,
            token_request_url=token_request_url,
            scope=scope,
            token_cache=token_cache,
            refresh_token_enabled=refresh_token_enabled,
            **kwargs,
        )

    async def reset_secrets(self) -> None:
        AuthByOauthCredentialsSync.reset_secrets(self)

    async def prepare(self, **kwargs: Any) -> None:
        AuthByOauthCredentialsSync.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthByOauthCredentialsSync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthByOauthCredentialsSync.update_body(self, body)
