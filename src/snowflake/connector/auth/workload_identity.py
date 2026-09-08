from __future__ import annotations

import json
import logging
import os
import typing
from enum import Enum, unique

if typing.TYPE_CHECKING:
    from snowflake.connector.connection import SnowflakeConnection

from .._host_util import has_recognized_snowflake_suffix, normalize_host
from ..errorcode import ER_WIF_UNTRUSTED_HOST
from ..errors import ProgrammingError
from ..network import WORKLOAD_IDENTITY_AUTHENTICATOR
from ..wif_util import (
    AttestationProvider,
    WorkloadIdentityAttestation,
    create_attestation,
)
from .by_plugin import AuthByPlugin, AuthType

logger = logging.getLogger(__name__)

# Additive escape hatch for on-prem / air-gapped Snowflake deployments whose host
# does not end in a recognized Snowflake suffix.
#
# Read only from the process environment - never from the DSN, connection
# parameters or configuration files - so connection configuration cannot
# influence the allowlist. Entries are additive: they extend the
# recognized-host list and cannot disable it.
#
# Scoped to WORKLOAD_IDENTITY on purpose. Widening the hosts an ambient cloud
# credential may be sent to is a different decision from widening the hosts an
# OCSP cache may be fetched from, so the OCSP gate passes no extra suffixes.
_SNOWFLAKE_WIF_ALLOWED_HOST_SUFFIXES_ENV_VAR = "SNOWFLAKE_WIF_ALLOWED_HOST_SUFFIXES"


def _extra_wif_allowed_suffixes() -> list[str]:
    """Reads the additive SNOWFLAKE_WIF_ALLOWED_HOST_SUFFIXES env-var allow-list.

    Comma-separated, additive-only (never disables the built-in allow-list),
    normalized the same way as the candidate host. Logs at INFO naming the
    extra suffixes whenever the env var is used, since this widens the set of
    hosts the ambient cloud credential may be sent to.
    """
    raw = os.environ.get(_SNOWFLAKE_WIF_ALLOWED_HOST_SUFFIXES_ENV_VAR, "")
    if not raw:
        return []
    suffixes = [normalize_host(entry) for entry in raw.split(",") if entry.strip()]
    suffixes = [s for s in suffixes if s]
    if suffixes:
        logger.info(
            "SNOWFLAKE_WIF_ALLOWED_HOST_SUFFIXES is set; extending the WORKLOAD_IDENTITY "
            "recognized-host allow-list with additional suffixes: %s.",
            suffixes,
        )
    return suffixes


def _is_host_allowed_for_workload_identity(host: str) -> bool:
    """Returns True if `host` (already-normalized or not) is a trusted WIF destination."""
    return has_recognized_snowflake_suffix(
        normalize_host(host), _extra_wif_allowed_suffixes()
    )


def _verify_host_allowed_for_workload_identity(
    conn: SnowflakeConnection | None,
) -> None:
    """Suffix-anchored allowlist that restricts Workload Identity attestation to
    recognized Snowflake hosts before any cloud credential is fetched.

    When ``conn`` is None there is no destination to send the credential to (e.g.
    unit tests that only exercise attestation creation), so the check is skipped.
    """
    if conn is None:
        return
    host = conn.host or ""
    if not _is_host_allowed_for_workload_identity(host):
        raise ProgrammingError(
            msg=(
                f"WORKLOAD_IDENTITY requires a recognized Snowflake host "
                f"(*.snowflakecomputing.com, .cn or .mil). Got: '{host}'."
            ),
            errno=ER_WIF_UNTRUSTED_HOST,
        )


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
        provider: AttestationProvider,
        token: str | None = None,
        entra_resource: str | None = None,
        impersonation_path: list[str] | None = None,
        aws_use_outbound_token: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.provider = provider
        self.token = token
        self.entra_resource = entra_resource
        self.impersonation_path = impersonation_path
        self.aws_use_outbound_token = aws_use_outbound_token

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
        body["data"].setdefault("CLIENT_ENVIRONMENT", {})[
            "WORKLOAD_IDENTITY_IMPERSONATION_PATH_LENGTH"
        ] = len(self.impersonation_path or [])

    def prepare(
        self, *, conn: SnowflakeConnection | None, **kwargs: typing.Any
    ) -> None:
        """Fetch the token."""
        # Verify the host is a recognized Snowflake endpoint before fetching
        # cloud credentials.
        _verify_host_allowed_for_workload_identity(conn)
        self.attestation = create_attestation(
            self.provider,
            self.entra_resource,
            self.token,
            self.impersonation_path,
            session_manager=(
                conn._session_manager.clone(max_retries=0) if conn else None
            ),
            aws_use_outbound_token=self.aws_use_outbound_token,
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
