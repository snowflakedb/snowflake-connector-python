#!/usr/bin/env python


from __future__ import annotations

from ...auth.usrpwdmfa import AuthByUsrPwdMfa as AuthByUsrPwdMfaSync
from ._by_plugin import AuthByPlugin as AuthByPluginAsync


class AuthByUsrPwdMfa(AuthByPluginAsync, AuthByUsrPwdMfaSync):
    def __init__(
        self,
        password: str,
        mfa_token: str | None = None,
        **kwargs,
    ) -> None:
        """Initializes and instance with a password and a mfa token."""
        AuthByUsrPwdMfaSync.__init__(self, password, mfa_token, **kwargs)

    async def reset_secrets(self) -> None:
        AuthByUsrPwdMfaSync.reset_secrets(self)

    async def prepare(self, **kwargs) -> None:
        AuthByUsrPwdMfaSync.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs) -> dict[str, bool]:
        return AuthByUsrPwdMfaSync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[str, str]) -> None:
        AuthByUsrPwdMfaSync.update_body(self, body)
