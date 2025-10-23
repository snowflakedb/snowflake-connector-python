from __future__ import annotations

import typing
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .. import SnowflakeConnection

from ...auth.workload_identity import (
    AuthByWorkloadIdentity as AuthByWorkloadIdentitySync,
)
from .._wif_util import AttestationProvider, create_attestation
from ._by_plugin import AuthByPlugin as AuthByPluginAsync


class AuthByWorkloadIdentity(AuthByPluginAsync, AuthByWorkloadIdentitySync):
    """Plugin to authenticate via workload identity."""

    def __init__(
        self,
        *,
        provider: AttestationProvider,
        token: str | None = None,
        entra_resource: str | None = None,
        impersonation_path: list[str] | None = None,
        **kwargs,
    ) -> None:
        """Initializes an instance with workload identity authentication."""
        AuthByWorkloadIdentitySync.__init__(
            self,
            provider=provider,
            token=token,
            entra_resource=entra_resource,
            impersonation_path=impersonation_path,
            **kwargs,
        )

    async def reset_secrets(self) -> None:
        AuthByWorkloadIdentitySync.reset_secrets(self)

    async def prepare(
        self, *, conn: SnowflakeConnection | None, **kwargs: typing.Any
    ) -> None:
        """Fetch the token using async wif_util."""
        self.attestation = await create_attestation(
            self.provider,
            self.entra_resource,
            self.token,
            self.impersonation_path,
            session_manager=(
                conn._session_manager.clone(max_retries=0) if conn else None
            ),
        )

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        """This is only relevant for AuthByIdToken, which uses a web-browser based flow. All other auth plugins just call authenticate() again."""
        return {"success": False}

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthByWorkloadIdentitySync.update_body(self, body)
