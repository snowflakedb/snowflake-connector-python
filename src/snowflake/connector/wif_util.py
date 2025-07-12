from __future__ import annotations

"""Workload‑identity attestation helpers.

This module builds the attestation token that the Snowflake Python connector
sends when Authenticating with *Workload Identity Federation* (WIF).
It supports AWS, Azure, GCP and generic OIDC environments **without** pulling
in heavy SDKs such as *botocore* – we only need a small presigned STS request
for AWS and a couple of metadata‑server calls for Azure / GCP.
"""

import json
import logging
import os
from base64 import b64encode
from dataclasses import dataclass
from enum import Enum, unique
from typing import Any

import jwt

from ._aws_credentials import get_region, load_default_credentials
from ._aws_sign_v4 import sign_get_caller_identity
from .errorcode import ER_WIF_CREDENTIALS_NOT_FOUND
from .errors import ProgrammingError
from .vendored import requests
from .vendored.requests import Response

logger = logging.getLogger(__name__)
SNOWFLAKE_AUDIENCE = "snowflakecomputing.com"
DEFAULT_ENTRA_SNOWFLAKE_RESOURCE = "api://fd3f753b-eed3-462c-b6a7-a4b5bb650aad"

"""
References:
- https://learn.microsoft.com/en-us/entra/identity-platform/authentication-national-cloud#microsoft-entra-authentication-endpoints
- https://learn.microsoft.com/en-us/answers/questions/1190472/what-are-the-token-issuers-for-the-sovereign-cloud
"""
AZURE_ISSUER_PREFIXES = [
    "https://sts.windows.net/",  # Public and USGov (v1 issuer)
    "https://sts.chinacloudapi.cn/",  # Mooncake (v1 issuer)
    "https://login.microsoftonline.com/",  # Public (v2 issuer)
    "https://login.microsoftonline.us/",  # USGov (v2 issuer)
    "https://login.partner.microsoftonline.cn/",  # Mooncake (v2 issuer)
]


@unique
class AttestationProvider(Enum):
    """A WIF provider implementation that can produce an attestation."""

    AWS = "AWS"
    """Provider that builds an encoded pre-signed GetCallerIdentity request using the current workload's IAM role."""
    AZURE = "AZURE"
    """Provider that requests an OAuth access token for the workload's managed identity."""
    GCP = "GCP"
    """Provider that requests an ID token for the workload's attached service account."""
    OIDC = "OIDC"
    """Provider that looks for an OIDC ID token."""

    @staticmethod
    def from_string(provider: str) -> AttestationProvider:
        """Converts a string to a strongly-typed enum value of :class:`AttestationProvider`."""
        return AttestationProvider[provider.upper()]


@dataclass
class WorkloadIdentityAttestation:
    provider: AttestationProvider
    credential: str  # **base64** JSON blob – provider‑specific
    user_identifier_components: dict[str, Any]


def try_metadata_service_call(
    method: str, url: str, headers: dict[str, str], *, timeout: int = 3
) -> Response | None:
    """Tries to make a HTTP request to the metadata service with the given URL, method, headers and timeout in seconds.

    If we receive an error response or any exceptions are raised, returns None. Otherwise returns the response.
    """
    try:
        res: Response = requests.request(
            method=method, url=url, headers=headers, timeout=timeout
        )
        return res if res.ok else None
    except requests.RequestException:
        return None


def extract_iss_and_sub_without_signature_verification(
    jwt_str: str,
) -> tuple[str | None, str | None]:
    """Extracts the 'iss' and 'sub' claims from the given JWT, without verifying the signature.

    Note: the real token verification (including signature verification) happens on the Snowflake side. The driver doesn't have
    the keys to verify these JWTs, and in any case that's not where the security boundary is drawn.

    We only decode the JWT here to get some basic claims, which will be used for a) a quick smoke test to ensure we got the right
    issuer, and b) to find the unique user being asserted and populate assertion_content. The latter may be used for logging
    and possibly caching.

    If there are any errors in parsing the token or extracting iss and sub, this will return (None, None).
    """
    claims = _decode_jwt_without_validation(jwt_str)
    if claims is None:
        return None, None

    if "iss" not in claims or "sub" not in claims:
        logger.warning("Token is missing 'iss' or 'sub' claims.")
        return None, None

    return claims["iss"], claims["sub"]


def _decode_jwt_without_validation(token: str) -> Any:
    """Helper that decodes *token* with ``verify_signature=False``.:contentReference[oaicite:1]{index=1}"""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.exceptions.InvalidTokenError:
        logger.warning("Token is not a valid JWT.", exc_info=True)
        return None


class AWSPartition(str, Enum):
    BASE = "aws"
    CHINA = "aws-cn"
    GOV = "aws-us-gov"


def _partition_from_region(region: str) -> AWSPartition:
    if region.startswith("cn-"):
        return AWSPartition.CHINA
    if region.startswith("us-gov-"):
        return AWSPartition.GOV
    return AWSPartition.BASE


def _sts_host_from_region(region: str) -> str:
    """
    Construct the STS endpoint hostname for *region* according to the
    regionalised-STS rules published by AWS.:contentReference[oaicite:2]{index=2}

    References:
    - https://docs.aws.amazon.com/sdkref/latest/guide/feature-sts-regionalized-endpoints.html
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html
    - https://docs.aws.amazon.com/general/latest/gr/sts.html
    """
    part = _partition_from_region(region)
    suffix = ".amazonaws.com.cn" if part is AWSPartition.CHINA else ".amazonaws.com"
    return f"sts.{region}{suffix}"


def _try_get_arn_from_env_vars() -> str | None:
    """Try to get ARN already exposed by the runtime (no extra network I/O).

    •  `AWS_ROLE_ARN` – web-identity / many FaaS runtimes
    •  `AWS_EC2_METADATA_ARN` – some IMDSv2 environments
    •  `AWS_SESSION_ARN` – recent AWS SDKs export this when assuming a role
    """
    for possible_arn_env_var in (
        "AWS_ROLE_ARN",
        "AWS_EC2_METADATA_ARN",
        "AWS_SESSION_ARN",
    ):
        value = os.getenv(possible_arn_env_var)
        if value and value.startswith("arn:"):
            return value
    return None


def try_compose_aws_user_identifier(region: str | None = None) -> dict[str, str]:
    """Return an identifier for the running AWS workload.

    Always includes the AWS *region*; adds an *arn* key only if one is already
    discoverable via common environment variables.  Returns **{}** only if
    the region cannot be determined."""
    region = region or get_region()
    if not region:
        return {}

    identifier: dict[str, str] = {"region": region}

    if arn := _try_get_arn_from_env_vars():
        identifier["arn"] = arn

    return identifier


def create_aws_attestation() -> WorkloadIdentityAttestation | None:
    """Return AWS attestation or *None* if we're not on AWS / creds missing."""

    creds = load_default_credentials()
    if not creds:
        logger.debug("No AWS credentials available.")
        return None

    region = get_region()
    if not region:
        logger.debug("AWS region could not be determined.")
        return None

    sts_url = (
        f"https://{_sts_host_from_region(region)}"
        "/?Action=GetCallerIdentity&Version=2011-06-15"
    )
    signed_headers = sign_get_caller_identity(
        url=sts_url,
        region=region,
        access_key=creds.access_key,
        secret_key=creds.secret_key,
        session_token=creds.token,
    )

    attestation = b64encode(
        json.dumps(
            {"url": sts_url, "method": "POST", "headers": signed_headers}
        ).encode()
    ).decode()

    user_identifier = try_compose_aws_user_identifier(region)
    return WorkloadIdentityAttestation(
        AttestationProvider.AWS, attestation, user_identifier
    )


def create_gcp_attestation() -> WorkloadIdentityAttestation | None:
    """Tries to create a workload identity attestation for GCP.

    If the application isn't running on GCP or no credentials were found, returns None.
    """
    res = try_metadata_service_call(
        method="GET",
        url=f"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience={SNOWFLAKE_AUDIENCE}",
        headers={
            "Metadata-Flavor": "Google",
        },
    )
    if res is None:
        # Most likely we're just not running on GCP, which may be expected.
        logger.debug("GCP metadata server request was not successful.")
        return None

    jwt_str = res.content.decode("utf-8")
    issuer, subject = extract_iss_and_sub_without_signature_verification(jwt_str)
    if not issuer or not subject:
        return None
    if issuer != "https://accounts.google.com":
        # This might happen if we're running on a different platform that responds to the same metadata request signature as GCP.
        logger.debug("Unexpected GCP token issuer '%s'", issuer)
        return None

    return WorkloadIdentityAttestation(
        AttestationProvider.GCP, jwt_str, {"sub": subject}
    )


def create_azure_attestation(
    snowflake_entra_resource: str,
) -> WorkloadIdentityAttestation | None:
    """Tries to create a workload identity attestation for Azure.

    If the application isn't running on Azure or no credentials were found, returns None.
    """
    headers = {"Metadata": "True"}
    url_without_query_string = "http://169.254.169.254/metadata/identity/oauth2/token"
    query_params = f"api-version=2018-02-01&resource={snowflake_entra_resource}"

    # Check if running in Azure Functions environment
    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT")
    identity_header = os.environ.get("IDENTITY_HEADER")
    is_azure_functions = identity_endpoint is not None

    if is_azure_functions:
        if not identity_header:
            logger.warning("Managed identity is not enabled on this Azure function.")
            return None

        # Azure Functions uses a different endpoint, headers and API version.
        url_without_query_string = identity_endpoint
        headers = {"X-IDENTITY-HEADER": identity_header}
        query_params = f"api-version=2019-08-01&resource={snowflake_entra_resource}"

        # Some Azure Functions environments may require client_id in the URL
        managed_identity_client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")
        if managed_identity_client_id:
            query_params += f"&client_id={managed_identity_client_id}"

    res = try_metadata_service_call(
        method="GET",
        url=f"{url_without_query_string}?{query_params}",
        headers=headers,
    )
    if res is None:
        # Most likely we're just not running on Azure, which may be expected.
        logger.debug("Azure metadata server request was not successful.")
        return None

    try:
        jwt_str = res.json().get("access_token")
        if not jwt_str:
            # Could be that Managed Identity is disabled.
            logger.debug("No access token found in Azure response.")
            return None
    except (ValueError, KeyError) as e:
        logger.debug(f"Error parsing Azure response: {e}")
        return None

    issuer, subject = extract_iss_and_sub_without_signature_verification(jwt_str)
    if not issuer or not subject:
        return None
    if not any(
        issuer.startswith(issuer_prefix) for issuer_prefix in AZURE_ISSUER_PREFIXES
    ):
        # This might happen if we're running on a different platform that responds to the same metadata request signature as Azure.
        logger.debug("Unexpected Azure token issuer '%s'", issuer)
        return None

    return WorkloadIdentityAttestation(
        AttestationProvider.AZURE, jwt_str, {"iss": issuer, "sub": subject}
    )


def create_oidc_attestation(token: str | None) -> WorkloadIdentityAttestation | None:
    """Tries to create an attestation using the given token.

    If this is not populated, returns None.
    """
    if not token:
        logger.debug("No OIDC token was specified.")
        return None

    issuer, subject = extract_iss_and_sub_without_signature_verification(token)
    if not issuer or not subject:
        return None

    return WorkloadIdentityAttestation(
        AttestationProvider.OIDC, token, {"iss": issuer, "sub": subject}
    )


def create_autodetect_attestation(
    entra_resource: str, token: str | None = None
) -> WorkloadIdentityAttestation | None:
    """Tries to create an attestation using the auto-detected runtime environment.

    If no attestation can be found, returns None.
    """
    attestation = create_oidc_attestation(token)
    if attestation:
        return attestation

    attestation = create_aws_attestation()
    if attestation:
        return attestation

    attestation = create_azure_attestation(entra_resource)
    if attestation:
        return attestation

    attestation = create_gcp_attestation()
    if attestation:
        return attestation

    return None


def create_attestation(
    provider: AttestationProvider | None,
    entra_resource: str | None = None,
    token: str | None = None,
) -> WorkloadIdentityAttestation:
    """Entry point to create an attestation using the given provider.

    If the provider is None, this will try to auto-detect a credential from the runtime environment. If the provider fails to detect a credential,
    a ProgrammingError will be raised.

    If an explicit entra_resource was provided to the connector, this will be used. Otherwise, the default Snowflake Entra resource will be used.
    """
    entra_resource = entra_resource or DEFAULT_ENTRA_SNOWFLAKE_RESOURCE

    attestation: WorkloadIdentityAttestation = None
    if provider == AttestationProvider.AWS:
        attestation = create_aws_attestation()
    elif provider == AttestationProvider.AZURE:
        attestation = create_azure_attestation(entra_resource)
    elif provider == AttestationProvider.GCP:
        attestation = create_gcp_attestation()
    elif provider == AttestationProvider.OIDC:
        attestation = create_oidc_attestation(token)
    elif provider is None:
        attestation = create_autodetect_attestation(entra_resource, token)

    if not attestation:
        provider_str = "auto-detect" if provider is None else provider.value
        raise ProgrammingError(
            msg=f"No workload identity credential was found for '{provider_str}'.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    return attestation
