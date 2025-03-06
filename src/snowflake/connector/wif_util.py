#
# Copyright (c) 2012-2025 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from base64 import b64encode
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.utils import InstanceMetadataRegionFetcher
from dataclasses import dataclass
from enum import Enum, unique
import os
import json
import jwt
import logging
from typing import Union

from .errorcode import ER_WIF_CREDENTIALS_NOT_FOUND
from .errors import ProgrammingError
from .vendored import requests
from .vendored.requests import Response

logger = logging.getLogger(__name__)
SNOWFLAKE_AUDIENCE = "snowflakecomputing.com"
# TODO: use real app ID or domain name.
DEFAULT_ENTRA_SNOWFLAKE_RESOURCE = "api://snowflakecomputing.com"


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


@dataclass
class WorkloadIdentityAttestation:
    provider: AttestationProvider
    credential: str
    user_identifier_components: dict


def try_metadata_service_call(method: str, url: str, headers: dict, timeout_sec: int = 3) -> Union[Response, None]:
    """Tries to make a HTTP request to the metadata service with the given URL, method, headers and timeout.

    If we receive an error response or any exceptions are raised, returns None. Otherwise returns the response.
    """
    try:
        res: Response = requests.request(method=method,url=url,headers=headers,timeout=timeout_sec)
        if not res.ok:
            return None
    except:
        return None
    return res


def extract_iss_and_sub_without_signature_verification(jwt_str: str) -> tuple[str, str]:
    """Extracts the 'iss' and 'sub' claims from the given JWT, without verifying the signature.

    Note: the real token verification (including signature verification) happens on the Snowflake side. The driver doesn't have
    the keys to verify these JWTs, and in any case that's not where the security boundary is drawn.

    We only decode the JWT here to get some basic claims, which will be used for a) a quick smoke test to ensure we got the right
    issuer, and b) to find the unique user being asserted and populate assertion_content. The latter may be used for logging
    and possibly caching.
    """
    claims = jwt.decode(jwt_str, options={"verify_signature": False})
    return claims["iss"], claims["sub"]


def get_aws_region() -> str | None:
    """Get the current AWS workload's region, if any."""
    if "AWS_REGION" in os.environ:  # Lambda
        return os.environ["AWS_REGION"]
    else:  # EC2
        return InstanceMetadataRegionFetcher().retrieve_region()


def get_aws_arn() -> str | None:
    """Get the current AWS workload's ARN, if any."""
    caller_identity = boto3.client('sts').get_caller_identity()
    if not caller_identity or "Arn" not in caller_identity:
        return None
    return caller_identity["Arn"]


def create_aws_attestation() -> Union[WorkloadIdentityAttestation, None]:
    """Tries to create a workload identity attestation for AWS.
    
    If the application isn't running on AWS or no credentials were found, returns None.
    """
    aws_creds = boto3.session.Session().get_credentials()
    if not aws_creds:
        logger.debug("No AWS credentials were found.")
        return None
    region = get_aws_region()
    if not region:
        logger.debug("No AWS region was found.")
        return None
    arn = get_aws_arn()
    if not arn:
        logger.debug("No AWS caller identity was found.")
        return None

    sts_hostname = f"sts.{region}.amazonaws.com"
    request = AWSRequest(
        method="POST",
        url=f"https://{sts_hostname}/?Action=GetCallerIdentity&Version=2011-06-15",
        headers={
            "Host": sts_hostname,
            "X-Snowflake-Audience": SNOWFLAKE_AUDIENCE,
        },
    )

    SigV4Auth(aws_creds, "sts", region).add_auth(request)

    assertion_dict = {
        "url": request.url,
        "method": request.method,
        "headers": dict(request.headers.items()),
    }
    credential = b64encode(json.dumps(assertion_dict).encode("utf-8")).decode("utf-8")
    return WorkloadIdentityAttestation(AttestationProvider.AWS, credential, {"arn": arn})


def create_gcp_attestation() -> Union[WorkloadIdentityAttestation, None]:
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
        logger.debug('GCP metadata server request was not successful.')
        return None

    jwt_str = res.content.decode("utf-8")
    issuer, subject = extract_iss_and_sub_without_signature_verification(jwt_str)
    if issuer != "https://accounts.google.com":
        # This might happen if we're running on a different platform that responds to the same metadata request signature as GCP.
        logger.debug("Unexpected GCP token issuer '%s'", issuer)
        return None

    return WorkloadIdentityAttestation(AttestationProvider.GCP, jwt_str, {"sub": subject})


def create_azure_attestation(snowflake_entra_resource: str) -> Union[WorkloadIdentityAttestation, None]:
    """Tries to create a workload identity attestation for Azure.
    
    If the application isn't running on Azure or no credentials were found, returns None.
    """
    headers = {"Metadata": "True"}
    # Special case for Azure functions.
    identity_header = os.environ.get("IDENTITY_HEADER")
    if identity_header:
        headers["X-IDENTITY-HEADER"] = identity_header

    
    res = try_metadata_service_call(
        method="GET",
        url=f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={snowflake_entra_resource}",
        headers=headers,
    )
    if res is None:
        # Most likely we're just not running on Azure, which may be expected.
        logger.debug('Azure metadata server request was not successful.')
        return None

    jwt_str = str(res.json()["access_token"])
    issuer, subject = extract_iss_and_sub_without_signature_verification(jwt_str)
    if not issuer.startswith("https://sts.windows.net/"):
        # This might happen if we're running on a different platform that responds to the same metadata request signature as Azure.
        logger.debug("Unexpected Azure token issuer '%s'", issuer)
        return None

    return WorkloadIdentityAttestation(AttestationProvider.AZURE, jwt_str, {"iss": issuer, "sub": subject})


def create_oidc_attestation(token: str | None) -> Union[WorkloadIdentityAttestation, None]:
    """Tries to create an attestation using the given token.
    
    If this is not populated, returns None.
    """
    if not token:
        logger.debug("No OIDC token was specified.")
        return None

    try:
        claims = jwt.decode(token, options={"verify_signature": False})
        return WorkloadIdentityAttestation(AttestationProvider.OIDC, token, {"iss": claims["iss"], "sub": claims["sub"]})
    except jwt.exceptions.InvalidTokenError:
        raise ProgrammingError(
            msg=f"Specified token is not a valid JWT.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )


def create_autodetect_attestation(entra_resource: str, token: str | None = None) -> Union[WorkloadIdentityAttestation, None]:
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


def create_attestation(provider: AttestationProvider | None, entra_resource: str | None = None, token: str | None = None) -> WorkloadIdentityAttestation:
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
    elif provider == None:
        attestation = create_autodetect_attestation(entra_resource, token)

    if not attestation:
        provider_str = "auto-detect" if provider is None else provider.value
        raise ProgrammingError(
            msg=f"No workload identity credential was found for '{provider_str}'.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    return attestation
