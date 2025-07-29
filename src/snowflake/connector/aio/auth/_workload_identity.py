#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from typing import Any

from ...auth.workload_identity import (
    AuthByWorkloadIdentity as AuthByWorkloadIdentitySync,
)
from .._wif_util import AttestationProvider, create_attestation
from ._by_plugin import AuthByPlugin as AuthByPluginAsync


class AuthByWorkloadIdentity(AuthByWorkloadIdentitySync, AuthByPluginAsync):
    """Plugin to authenticate via workload identity."""

    def __init__(
        self,
        *,
        provider: AttestationProvider | None = None,
        token: str | None = None,
        entra_resource: str | None = None,
        **kwargs,
    ) -> None:
        """Initializes an instance with workload identity authentication."""
        AuthByWorkloadIdentitySync.__init__(
            self,
            provider=provider,
            token=token,
            entra_resource=entra_resource,
            **kwargs,
        )

    async def reset_secrets(self) -> None:
        AuthByWorkloadIdentitySync.reset_secrets(self)

    async def prepare(self, **kwargs: Any) -> None:
        """Fetch the token using async wif_util."""
        self.attestation = await create_attestation(
            self.provider, self.entra_resource, self.token
        )

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        """This is only relevant for AuthByIdToken, which uses a web-browser based flow. All other auth plugins just call authenticate() again."""
        return {"success": False}

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthByWorkloadIdentitySync.update_body(self, body)
