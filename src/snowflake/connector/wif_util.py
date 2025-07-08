from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, unique
from urllib.parse import parse_qsl, quote, urlparse

import jwt

from .errorcode import ER_WIF_CREDENTIALS_NOT_FOUND
from .errors import ProgrammingError
from .http_client import request as http_request
from .session_manager import SessionManager
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
        """Converts a string to a strongly-typed enum value of AttestationProvider."""
        return AttestationProvider[provider.upper()]


@dataclass
class WorkloadIdentityAttestation:
    provider: AttestationProvider
    credential: str
    user_identifier_components: dict


@dataclass
class AwsCredentials:
    """AWS credentials container."""

    access_key: str
    secret_key: str
    token: str | None = None


def try_metadata_service_call(
    method: str,
    url: str,
    headers: dict,
    timeout_sec: int = 3,
    session_manager: SessionManager | None = None,
) -> Response | None:
    """Tries to make a HTTP request to the metadata service with the given URL, method, headers and timeout.

    If we receive an error response or any exceptions are raised, returns None. Otherwise returns the response.
    """
    try:
        # If no session_manager provided, create a basic one for this call
        if session_manager is None:
            session_manager = SessionManager(use_pooling=False)

        res: Response = http_request(
            method=method,
            url=url,
            headers=headers,
            timeout_sec=timeout_sec,
            session_manager=session_manager,
            use_pooling=False,  # IMDS calls are rare → don't pollute pool
        )
        if not res.ok:
            return None
    except requests.RequestException:
        return None
    return res


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
    try:
        claims = jwt.decode(jwt_str, options={"verify_signature": False})
    except jwt.exceptions.InvalidTokenError:
        logger.warning("Token is not a valid JWT.", exc_info=True)
        return None, None

    if not ("iss" in claims and "sub" in claims):
        logger.warning("Token is missing 'iss' or 'sub' claims.")
        return None, None

    return claims["iss"], claims["sub"]


def _imds_v2_token(session_manager: SessionManager | None = None) -> str | None:
    res = try_metadata_service_call(
        method="PUT",
        url="http://169.254.169.254/latest/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"},
        session_manager=session_manager,
    )
    return res.text.strip() if res else None


def get_aws_credentials(
    session_manager: SessionManager | None = None,
) -> AwsCredentials | None:
    """Get AWS credentials from environment variables or instance metadata.

    Implements the AWS credential chain without using boto3.
    """
    # Try environment variables first
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    session_token = os.environ.get("AWS_SESSION_TOKEN")

    if access_key and secret_key:
        return AwsCredentials(access_key, secret_key, session_token)

    # Try instance metadata service (IMDSv2)
    try:
        token = _imds_v2_token(session_manager)
        if token is None:
            logger.debug("Failed to get IMDSv2 token from metadata service.")
            return None

        token_hdr = {"X-aws-ec2-metadata-token": token} if token else {}

        # Get the security credentials from the metadata service
        res = try_metadata_service_call(
            method="GET",
            url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            headers=token_hdr,
            session_manager=session_manager,
        )
        if res is None:
            logger.debug("Failed to get IAM role list from metadata service.")
            return None

        role_name = res.text.strip()
        if not role_name:
            logger.debug("No IAM role found in metadata service.")
            return None

        # Get credentials for the role
        res = try_metadata_service_call(
            method="GET",
            url=f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
            headers=token_hdr,
            session_manager=session_manager,
        )
        if res is None:
            logger.debug("Failed to get IAM role credentials from metadata service.")
            return None

        creds_data = res.json()
        access_key = creds_data.get("AccessKeyId")
        secret_key = creds_data.get("SecretAccessKey")
        token = creds_data.get("Token")

        if access_key and secret_key:
            return AwsCredentials(access_key, secret_key, token)
    except Exception as e:
        logger.debug(f"Error getting AWS credentials from metadata service: {e}")

    return None


def get_aws_region(session_manager: SessionManager | None = None) -> str | None:
    """Get the current AWS workload's region, if any."""
    region = os.environ.get("AWS_REGION")
    if region:
        return region

    try:
        token = _imds_v2_token(session_manager)
        if token is None:
            logger.debug("Failed to get IMDSv2 token from metadata service.")
            return None

        token_hdr = {"X-aws-ec2-metadata-token": token} if token else {}

        # Get region from metadata service
        res = try_metadata_service_call(
            method="GET",
            url="http://169.254.169.254/latest/meta-data/placement/region",
            headers=token_hdr,
            session_manager=session_manager,
        )
        if res is not None:
            return res.text.strip()

        res = try_metadata_service_call(
            method="GET",
            url="http://169.254.169.254/latest/meta-data/placement/availability-zone",
            headers=token_hdr,
            session_manager=session_manager,
        )
        if res is not None:
            return res.text.strip()[:-1]
    except Exception as e:
        logger.debug(f"Error getting AWS region from metadata service: {e}")

    return None


def get_aws_arn(session_manager: SessionManager | None = None) -> str | None:
    """Get the current AWS workload's ARN by calling GetCallerIdentity.

    Note: This function makes a network call to AWS STS and is only used for
    assertion content generation (logging and backward compatibility purposes).
    The ARN is not required for authentication - it's just used as a unique
    identifier for the workload in logs and assertion content.

    Returns the ARN of the current AWS identity, or None if it cannot be determined.
    """
    credentials = get_aws_credentials(session_manager)
    if not credentials:
        logger.debug("No AWS credentials available for ARN lookup.")
        return None

    region = get_aws_region(session_manager)
    if not region:
        logger.debug("No AWS region available for ARN lookup.")
        return None

    try:
        # Create the GetCallerIdentity request
        sts_hostname = get_aws_sts_hostname(region)
        url = f"https://{sts_hostname}/?Action=GetCallerIdentity&Version=2011-06-15"

        base_headers = {
            "Content-Type": "application/x-amz-json-1.1",
        }

        signed_headers = aws_signature_v4_sign(
            credentials=credentials,
            method="POST",
            url=url,
            region=region,
            service="sts",
            headers=base_headers,
        )

        # Make the actual request to get caller identity
        response = http_request(
            method="POST",
            url=url,
            headers=signed_headers,
            timeout_sec=10,
            session_manager=session_manager,
        )

        if response and response.ok:
            # Parse the XML response to extract the ARN
            import xml.etree.ElementTree as ET

            # Ensure content is bytes and decode it
            content = response.content
            if isinstance(content, bytes):
                content_str = content.decode("utf-8")
            else:
                content_str = str(content) if content else ""

            if content_str:
                root = ET.fromstring(content_str)

                # Find the Arn element in the response
                for elem in root.iter():
                    if elem.tag.endswith("Arn") and elem.text:
                        return elem.text.strip()

        logger.debug("Failed to get ARN from GetCallerIdentity response.")
        return None
    except Exception as e:
        logger.debug(f"Error getting AWS ARN: {e}")
        return None


def get_aws_sts_hostname(region: str) -> str | None:
    """Constructs the AWS STS hostname for a given region.

    * China regions (`cn-*`) → sts.<region>.amazonaws.com.cn
    * All other regions      → sts.<region>.amazonaws.com
    * Any invalid input      → None

    Args:
        region (str): The AWS region (e.g., 'us-east-1', 'cn-north-1').

    Returns:
        str: The AWS STS hostname (e.g., 'sts.us-east-1.amazonaws.com')

    References:
    - https://docs.aws.amazon.com/sdkref/latest/guide/feature-sts-regionalized-endpoints.html
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html
    - https://docs.aws.amazon.com/general/latest/gr/sts.html
    """

    if not region or not isinstance(region, str):
        return None

    if region.startswith("cn-"):
        # China regions have a different domain suffix
        return f"sts.{region}.amazonaws.com.cn"
    else:
        # Standard AWS regions
        return f"sts.{region}.amazonaws.com"


def _aws_percent_encode(s: str) -> str:
    return quote(s, safe="~")


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    pairs = sorted(parse_qsl(query, keep_blank_values=True))
    return "&".join(
        f"{_aws_percent_encode(k)}={_aws_percent_encode(v)}" for k, v in pairs
    )


def aws_signature_v4_sign(
    credentials: AwsCredentials,
    method: str,
    url: str,
    region: str,
    service: str,
    headers: dict,
    payload: str = "",
) -> dict:
    """Sign an AWS request using Signature Version 4.

    Based on the C# implementation in AwsSignature4Signer.cs.
    """
    parsed_url = urlparse(url)

    utc_now = datetime.now(timezone.utc)
    amz_date = utc_now.strftime("%Y%m%dT%H%M%SZ")
    date_string = utc_now.strftime("%Y%m%d")

    headers_lower = {k.lower(): str(v).strip() for k, v in headers.items()}
    headers_lower["host"] = parsed_url.netloc
    headers_lower["x-amz-date"] = amz_date
    if credentials.token:
        headers_lower["x-amz-security-token"] = credentials.token

    sorted_header_keys = sorted(headers_lower.keys())
    canonical_headers = "".join(f"{k}:{headers_lower[k]}\n" for k in sorted_header_keys)
    signed_headers = ";".join(sorted_header_keys)

    canonical_querystring = _canonical_query(parsed_url.query)
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    canonical_request = (
        f"{method}\n"
        f"{parsed_url.path or '/'}\n"
        f"{canonical_querystring}\n"
        f"{canonical_headers}"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_string}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"{algorithm}\n"
        f"{amz_date}\n"
        f"{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    def hmac_sha256(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = hmac_sha256(f"AWS4{credentials.secret_key}".encode(), date_string)
    k_region = hmac_sha256(k_date, region)
    k_service = hmac_sha256(k_region, service)
    k_signing = hmac_sha256(k_service, "aws4_request")

    signature = hmac.new(
        k_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    authorization = (
        f"{algorithm} "
        f"Credential={credentials.access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    final_headers = headers.copy()
    final_headers["Host"] = parsed_url.netloc
    final_headers["X-Amz-Date"] = amz_date
    if credentials.token:
        final_headers["X-Amz-Security-Token"] = credentials.token
    final_headers["Authorization"] = authorization

    return final_headers


def create_aws_attestation(
    session_manager: SessionManager | None = None,
) -> WorkloadIdentityAttestation | None:
    """Tries to create a workload identity attestation for AWS.

    If the application isn't running on AWS or no credentials were found, returns None.
    """
    credentials = get_aws_credentials(session_manager)
    if not credentials:
        logger.debug("No AWS credentials were found.")
        return None

    region = get_aws_region(session_manager)
    if not region:
        logger.debug("No AWS region was found.")
        return None

    # Create the GetCallerIdentity request
    sts_hostname = get_aws_sts_hostname(region)
    url = f"https://{sts_hostname}/?Action=GetCallerIdentity&Version=2011-06-15"

    base_headers = {
        "X-Snowflake-Audience": SNOWFLAKE_AUDIENCE,
    }

    signed_headers = aws_signature_v4_sign(
        credentials=credentials,
        method="POST",
        url=url,
        region=region,
        service="sts",
        headers=base_headers,
    )

    # Create attestation request
    attestation_request = {
        "method": "POST",
        "url": url,
        "headers": signed_headers,
    }

    credential = b64encode(json.dumps(attestation_request).encode("utf-8")).decode(
        "utf-8"
    )

    # Get the ARN for user identifier components (used only for assertion content - logging and backward compatibility)
    # The ARN is not required for authentication, but provides a unique identifier for the workload
    arn = get_aws_arn(session_manager)
    user_identifier_components = {"arn": arn} if arn else {}

    return WorkloadIdentityAttestation(
        AttestationProvider.AWS,
        credential,
        user_identifier_components,
    )


def create_gcp_attestation(
    session_manager: SessionManager | None = None,
) -> WorkloadIdentityAttestation | None:
    """Tries to create a workload identity attestation for GCP.

    If the application isn't running on GCP or no credentials were found, returns None.
    """
    res = try_metadata_service_call(
        method="GET",
        url=f"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience={SNOWFLAKE_AUDIENCE}",
        headers={
            "Metadata-Flavor": "Google",
        },
        session_manager=session_manager,
    )
    if res is None:
        # Most likely we're just not running on GCP, which may be expected.
        logger.debug("GCP metadata server request was not successful.")
        return None

    # Ensure content is bytes and decode it
    content = res.content
    if isinstance(content, bytes):
        jwt_str = content.decode("utf-8")
    else:
        jwt_str = str(content)

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
    session_manager: SessionManager | None = None,
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
        session_manager=session_manager,
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
    entra_resource: str,
    token: str | None = None,
    session_manager: SessionManager | None = None,
) -> WorkloadIdentityAttestation | None:
    """Tries to create an attestation using the auto-detected runtime environment.

    If no attestation can be found, returns None.
    """
    attestation = create_oidc_attestation(token)
    if attestation:
        return attestation

    attestation = create_azure_attestation(entra_resource, session_manager)
    if attestation:
        return attestation

    attestation = create_aws_attestation(session_manager)
    if attestation:
        return attestation

    attestation = create_gcp_attestation(session_manager)
    if attestation:
        return attestation

    return None


def create_attestation(
    provider: AttestationProvider | None,
    entra_resource: str | None = None,
    token: str | None = None,
    session_manager: SessionManager | None = None,
) -> WorkloadIdentityAttestation:
    """Entry point to create an attestation using the given provider.

    If the provider is None, this will try to auto-detect a credential from the runtime environment. If the provider fails to detect a credential,
    a ProgrammingError will be raised.

    If an explicit entra_resource was provided to the connector, this will be used. Otherwise, the default Snowflake Entra resource will be used.
    """
    entra_resource = entra_resource or DEFAULT_ENTRA_SNOWFLAKE_RESOURCE
    session_manager = (
        session_manager.clone() if session_manager else SessionManager(use_pooling=True)
    )

    attestation: WorkloadIdentityAttestation | None = None
    if provider == AttestationProvider.AWS:
        attestation = create_aws_attestation(session_manager)
    elif provider == AttestationProvider.AZURE:
        attestation = create_azure_attestation(entra_resource, session_manager)
    elif provider == AttestationProvider.GCP:
        attestation = create_gcp_attestation(session_manager)
    elif provider == AttestationProvider.OIDC:
        attestation = create_oidc_attestation(token)
    elif provider is None:
        attestation = create_autodetect_attestation(
            entra_resource, token, session_manager
        )

    if not attestation:
        provider_str = "auto-detect" if provider is None else provider.value
        raise ProgrammingError(
            msg=f"No workload identity credential was found for '{provider_str}'.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    return attestation
