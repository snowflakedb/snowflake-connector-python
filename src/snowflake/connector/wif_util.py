#
# Copyright (c) 2012-2025 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from base64 import b64encode
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from dataclasses import dataclass
from enum import Enum, unique
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
ENTRA_SNOWFLAKE_RESOURCE = "api://snowflakecomputing.com"


def get_default_entra_resource(account: str) -> str:
    # TODO: handle sovereign regions based on account name.
    return ENTRA_SNOWFLAKE_RESOURCE


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
    user_identifier: str


def create_aws_attestation() -> Union[WorkloadIdentityAttestation, None]:
    """Tries to create a workload identity attestation for AWS.
    
    If the application isn't running on AWS or no credentials were found, returns None.
    """
    session = boto3.session.Session()
    aws_creds = session.get_credentials()
    if not aws_creds:
        return None

    request = AWSRequest(
        method="POST",
        url="https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        headers={
            # TODO: use a regional STS URL.
            "Host": "sts.amazonaws.com",
            "X-Snowflake-Audience": SNOWFLAKE_AUDIENCE,
        },
    )

    # TODO: figure out a way to get the current workload's region and use a regional URL.
    SigV4Auth(aws_creds, "sts", "us-east-1").add_auth(request)

    assertion_dict = {
        "url": request.url,
        "method": request.method,
        "headers": dict(request.headers.items()),
    }
    credential = b64encode(json.dumps(assertion_dict).encode("utf-8")).decode("utf-8")
    # TODO: load the ARN.
    return WorkloadIdentityAttestation(AttestationProvider.AWS, credential, "<ARN-goes-here>")


def create_gcp_attestation() -> Union[WorkloadIdentityAttestation, None]:
    """Tries to create a workload identity attestation for GCP.
    
    If the application isn't running on GCP or no credentials were found, returns None.
    """
    res: Response = requests.request(
        method="GET",
        url=f"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience={SNOWFLAKE_AUDIENCE}",
        headers={
            "Metadata-Flavor": "Google",
        },
        timeout=3  # Don't want longer than 3 seconds, in case we're not running in GCP.
    )
    if not res.ok:
        return None

    jwt_str = res.content.decode("utf-8")
    claims = jwt.decode(jwt_str, options={"verify_signature": False})
    issuer = claims["iss"]
    if issuer != "https://accounts.google.com":
        logger.debug("Unexpected GCP token issuer '%s'", issuer)
        return None

    return WorkloadIdentityAttestation(AttestationProvider.GCP, jwt_str, claims["sub"])


def create_azure_attestation(snowflake_entra_resource: str) -> Union[WorkloadIdentityAttestation, None]:
    """Tries to create a workload identity attestation for Azure.
    
    If the application isn't running on Azure or no credentials were found, returns None.
    """
    # TODO: ensure this works in Azure functions.
    res: Response = requests.request(
        method="GET",
        url=f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={snowflake_entra_resource}",
        headers={
            "Metadata": "True"
        },
        timeout=3  # Don't want longer than 3 seconds, in case we're not running in Azure.
    )
    if not res.ok:
        return None

    jwt_str = str(res.json()["access_token"])
    claims = jwt.decode(jwt_str, options={"verify_signature": False})
    issuer = claims["iss"]
    if not issuer.startswith("https://sts.windows.net/"):
        logger.debug("Unexpected Azure token issuer '%s'", issuer)
        return None

    return WorkloadIdentityAttestation(AttestationProvider.AZURE, jwt_str, claims["sub"])


def create_oidc_attestation(token: str | None) -> Union[WorkloadIdentityAttestation, None]:
    """Tries to create an attestation using the given token.
    
    If this is not populated, returns None.
    """
    if not token:
        return None

    try:
        claims = jwt.decode(token, options={"verify_signature": False})
        return WorkloadIdentityAttestation(AttestationProvider.OIDC, token, claims["sub"])
    except jwt.exceptions.InvalidTokenError:
        raise ProgrammingError(
            msg=f"Specified token is not a valid JWT.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )


def create_autodetect_attestation(account: str, token: str | None = None) -> Union[WorkloadIdentityAttestation, None]:
    """Tries to create an attestation using the auto-detected runtime environment.
    
    If no attestation can be found, returns None.
    """
    if token:
        return create_oidc_attestation(token)

    attestation = create_aws_attestation()
    if attestation:
        return attestation

    attestation = create_azure_attestation(get_default_entra_resource(account))
    if attestation:
        return attestation

    attestation = create_gcp_attestation()
    if attestation:
        return attestation

    return None


def create_attestation(provider: AttestationProvider, account: str, token: str | None = None) -> WorkloadIdentityAttestation:
    """Entry point to create an attestation using the given provider.
    
    If the provider is None, this will try to auto-detect a credential from the runtime environment. If the provider fails to detect a credential,
    a ProgrammingError will be raised.
    """
    attestation: WorkloadIdentityAttestation = None
    if provider == AttestationProvider.AWS:
        attestation = create_aws_attestation()
    elif provider == AttestationProvider.AZURE:
        attestation = create_azure_attestation(get_default_entra_resource(account))
    elif provider == AttestationProvider.GCP:
        attestation = create_gcp_attestation()
    elif provider == AttestationProvider.OIDC:
        attestation = create_oidc_attestation(token)
    elif provider == None:
        attestation = create_autodetect_attestation(account, token)

    if not attestation:
        provider_str = provider or "auto-detect"
        raise ProgrammingError(
            msg=f"No workload identity credential was found for '{provider_str}'.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    return attestation
