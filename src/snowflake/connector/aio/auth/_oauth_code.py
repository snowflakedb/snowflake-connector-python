#!/usr/bin/env python

from __future__ import annotations

import logging
from typing import Any

from ...auth.oauth_code import AuthByOauthCode as AuthByOauthCodeSync
from ...token_cache import TokenCache
from ._by_plugin import AuthByPlugin as AuthByPluginAsync

logger = logging.getLogger(__name__)


class AuthByOauthCode(AuthByPluginAsync, AuthByOauthCodeSync):
    """Async version of OAuth authorization code authenticator."""

    def __init__(
        self,
        application: str,
        client_id: str,
        client_secret: str,
        authentication_url: str,
        token_request_url: str,
        redirect_uri: str,
        scope: str,
        pkce_enabled: bool = True,
        token_cache: TokenCache | None = None,
        refresh_token_enabled: bool = False,
        external_browser_timeout: int | None = None,
        **kwargs,
    ) -> None:
        """Initializes an instance with OAuth authorization code parameters."""
        logger.debug(
            "OAuth authentication is not supported in async version - falling back to sync implementation"
        )
        AuthByOauthCodeSync.__init__(
            self,
            application=application,
            client_id=client_id,
            client_secret=client_secret,
            authentication_url=authentication_url,
            token_request_url=token_request_url,
            redirect_uri=redirect_uri,
            scope=scope,
            pkce_enabled=pkce_enabled,
            token_cache=token_cache,
            refresh_token_enabled=refresh_token_enabled,
            external_browser_timeout=external_browser_timeout,
            **kwargs,
        )

    async def reset_secrets(self) -> None:
        AuthByOauthCodeSync.reset_secrets(self)

    async def prepare(self, **kwargs: Any) -> None:
        AuthByOauthCodeSync.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthByOauthCodeSync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthByOauthCodeSync.update_body(self, body)
