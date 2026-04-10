#!/usr/bin/env python


from __future__ import annotations

from typing import Any

from ...auth.pat import AuthByPAT as AuthByPATSync
from ._by_plugin import AuthByPlugin as AuthByPluginAsync


class AuthByPAT(AuthByPluginAsync, AuthByPATSync):
    def __init__(self, pat_token: str, **kwargs) -> None:
        """Initializes an instance with a PAT Token."""
        AuthByPATSync.__init__(self, pat_token, **kwargs)

    async def reset_secrets(self) -> None:
        AuthByPATSync.reset_secrets(self)

    async def prepare(self, **kwargs: Any) -> None:
        AuthByPATSync.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthByPATSync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthByPATSync.update_body(self, body)
