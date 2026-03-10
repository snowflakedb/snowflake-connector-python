#!/usr/bin/env python


from __future__ import annotations

from typing import Any

from ...auth.no_auth import AuthNoAuth as AuthNoAuthSync
from ._by_plugin import AuthByPlugin as AuthByPluginAsync


class AuthNoAuth(AuthByPluginAsync, AuthNoAuthSync):
    """No-auth Authentication.

    It is a dummy auth that requires no extra connection establishment.
    """

    def __init__(self, **kwargs) -> None:
        AuthNoAuthSync.__init__(self, **kwargs)

    async def reset_secrets(self) -> None:
        AuthNoAuthSync.reset_secrets(self)

    async def prepare(self, **kwargs: Any) -> None:
        AuthNoAuthSync.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthNoAuthSync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthNoAuthSync.update_body(self, body)
