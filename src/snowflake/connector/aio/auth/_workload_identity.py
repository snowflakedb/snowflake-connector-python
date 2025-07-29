#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from typing import Any

from ...auth.workload_identity import (
    AuthByWorkloadIdentity as AuthByWorkloadIdentitySync,
)
from ._by_plugin import AuthByPlugin as AuthByPluginAsync


class AuthByWorkloadIdentity(AuthByPluginAsync, AuthByWorkloadIdentitySync):
    def __init__(
        self,
        *,
        provider=None,
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
        AuthByWorkloadIdentitySync.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthByWorkloadIdentitySync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        AuthByWorkloadIdentitySync.update_body(self, body)
