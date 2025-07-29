#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from enum import Enum, unique
from typing import Any

from ...auth.by_plugin import AuthType
from ...network import WORKLOAD_IDENTITY_AUTHENTICATOR
from .._wif_util import AttestationProvider, create_attestation
from ._by_plugin import AuthByPlugin as AuthByPluginAsync


@unique
class ApiFederatedAuthenticationType(Enum):
    """An API-specific enum of the WIF authentication type."""

    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    OIDC = "OIDC"

    @staticmethod
    def from_attestation(attestation) -> ApiFederatedAuthenticationType:
        """Maps the internal / driver-specific attestation providers to API authenticator types."""
        if attestation.provider == AttestationProvider.AWS:
            return ApiFederatedAuthenticationType.AWS
        if attestation.provider == AttestationProvider.AZURE:
            return ApiFederatedAuthenticationType.AZURE
        if attestation.provider == AttestationProvider.GCP:
            return ApiFederatedAuthenticationType.GCP
        if attestation.provider == AttestationProvider.OIDC:
            return ApiFederatedAuthenticationType.OIDC
        raise ValueError(f"Unknown attestation provider '{attestation.provider}'")


class AuthByWorkloadIdentity(AuthByPluginAsync):
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
        super().__init__(**kwargs)
        self.provider = provider
        self.token = token
        self.entra_resource = entra_resource
        self.attestation = None

    def type_(self) -> AuthType:
        return AuthType.WORKLOAD_IDENTITY

    async def reset_secrets(self) -> None:
        self.attestation = None

    async def prepare(self, **kwargs: Any) -> None:
        """Fetch the token using async wif_util."""
        self.attestation = await create_attestation(
            self.provider, self.entra_resource, self.token
        )

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        """This is only relevant for AuthByIdToken, which uses a web-browser based flow. All other auth plugins just call authenticate() again."""
        return {"success": False}

    async def update_body(self, body: dict[Any, Any]) -> None:
        body["data"]["AUTHENTICATOR"] = WORKLOAD_IDENTITY_AUTHENTICATOR
        body["data"]["PROVIDER"] = ApiFederatedAuthenticationType.from_attestation(
            self.attestation
        ).value
        body["data"]["TOKEN"] = self.attestation.credential

    @property
    def assertion_content(self) -> str:
        """Returns the CSP provider name and an identifier. Used for logging purposes."""
        if not self.attestation:
            return ""
        properties = self.attestation.user_identifier_components
        properties["_provider"] = self.attestation.provider.value
        import json

        return json.dumps(properties, sort_keys=True, separators=(",", ":"))
