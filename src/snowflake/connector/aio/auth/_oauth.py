#!/usr/bin/env python


from __future__ import annotations

from typing import Any

from ...auth.oauth import AuthByOAuth as AuthByOAuthSync
from ._by_plugin import AuthByPlugin as AuthByPluginAsync


class AuthByOAuth(AuthByPluginAsync, AuthByOAuthSync):
    def __init__(self, oauth_token: str, **kwargs) -> None:
        """Initializes an instance with an OAuth Token."""
        AuthByOAuthSync.__init__(self, oauth_token, **kwargs)

    async def reset_secrets(self) -> None:
        AuthByOAuthSync.reset_secrets(self)

    async def prepare(self, **kwargs: Any) -> None:
        AuthByOAuthSync.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthByOAuthSync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthByOAuthSync.update_body(self, body)
