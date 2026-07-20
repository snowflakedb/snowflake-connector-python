from __future__ import annotations

import json
import typing
from enum import Enum, unique

from ..network import WORKLOAD_IDENTITY_AUTHENTICATOR
from ..wif_util import (
    AttestationProvider,
    WorkloadIdentityAttestation,
    create_attestation,
)
from .by_plugin import AuthByPlugin, AuthType


@unique
class ApiFederatedAuthenticationType(Enum):
    """An API-specific enum of the WIF authentication type."""

    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    OIDC = "OIDC"

    @staticmethod
    def from_attestation(
        attestation: WorkloadIdentityAttestation,
    ) -> ApiFederatedAuthenticationType:
        """Maps the internal / driver-specific attestation providers to API authenticator types.

        The AttestationProvider is related to how the driver fetches the credential, while the API authenticator
        type is related to how the credential is verified. In most current cases these may be the same, though
        in the future we could have, for example, multiple AttestationProviders that all fetch an OIDC ID token.
        """
        if attestation.provider == AttestationProvider.AWS:
            return ApiFederatedAuthenticationType.AWS
        if attestation.provider == AttestationProvider.AZURE:
            return ApiFederatedAuthenticationType.AZURE
        if attestation.provider == AttestationProvider.GCP:
            return ApiFederatedAuthenticationType.GCP
        if attestation.provider == AttestationProvider.OIDC:
            return ApiFederatedAuthenticationType.OIDC
        raise ValueError(f"Unknown attestation provider '{attestation.provider}'")


class AuthByWorkloadIdentity(AuthByPlugin):
    """Plugin to authenticate via workload identity."""

    def __init__(
        self,
        *,
        provider: AttestationProvider | None = None,
        token: str | None = None,
        entra_resource: str | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.provider = provider
        self.token = token
        self.entra_resource = entra_resource

        self.attestation: WorkloadIdentityAttestation | None = None

    def type_(self) -> AuthType:
        return AuthType.WORKLOAD_IDENTITY

    def reset_secrets(self) -> None:
        self.attestation = None

    def update_body(self, body: dict[typing.Any, typing.Any]) -> None:
        body["data"]["AUTHENTICATOR"] = WORKLOAD_IDENTITY_AUTHENTICATOR
        body["data"]["PROVIDER"] = ApiFederatedAuthenticationType.from_attestation(
            self.attestation
        ).value
        body["data"]["TOKEN"] = self.attestation.credential

    def prepare(self, **kwargs: typing.Any) -> None:
        """Fetch the token."""
        self.attestation = create_attestation(
            self.provider, self.entra_resource, self.token
        )

    def reauthenticate(self, **kwargs: typing.Any) -> dict[str, bool]:
        """This is only relevant for AuthByIdToken, which uses a web-browser based flow. All other auth plugins just call authenticate() again."""
        return {"success": False}

    @property
    def assertion_content(self) -> str:
        """Returns the CSP provider name and an identifier. Used for logging purposes."""
        if not self.attestation:
            return ""
        properties = self.attestation.user_identifier_components
        properties["_provider"] = self.attestation.provider.value
        return json.dumps(properties, sort_keys=True, separators=(",", ":"))
