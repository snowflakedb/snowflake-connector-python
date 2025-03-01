#
# Copyright (c) 2012-2025 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from base64 import b64encode
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from dataclasses import dataclass
import json
import jwt
import logging
from typing import Union

from .vendored import requests
from .vendored.requests import Response

logger = logging.getLogger(__name__)
SNOWFLAKE_AUDIENCE = "snowflakecomputing.com"
# TODO: use real app ID or domain name.
ENTRA_SNOWFLAKE_RESOURCE = "api://snowflakecomputing.com"


def get_default_entra_resource(account: str) -> str:
    # TODO: handle sovereign regions based on account name.
    return ENTRA_SNOWFLAKE_RESOURCE


@dataclass
class WorkloadIdentityAttestation:
    provider: str
    credential: str
    user_identifier: str


def create_aws_attestation() -> Union[WorkloadIdentityAttestation, None]:
    """Tries to create a workload identity attestation for AWS.
    
    If the application isn't running on AWS or no credentials were found, returns None.
    """
    # TODO: figure out a way to get the current workload's region and use a regional URL.
    session = boto3.session.Session()
    aws_creds = session.get_credentials()
    if not aws_creds:
        return None

    request = AWSRequest(
        method="POST",
        url="https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        headers={
            "Host": "sts.amazonaws.com",
            "X-Snowflake-Audience": SNOWFLAKE_AUDIENCE,
        },
    )

    SigV4Auth(aws_creds, "sts", "us-east-1").add_auth(request)

    assertion_dict = {
        "url": request.url,
        "method": request.method,
        "headers": dict(request.headers.items()),
    }
    credential = b64encode(json.dumps(assertion_dict).encode("utf-8")).decode("utf-8")
    # TODO: load the ARN.
    return WorkloadIdentityAttestation("AWS", credential, "ARN")



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

    return WorkloadIdentityAttestation("GCP", jwt_str, claims["sub"])


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

    return WorkloadIdentityAttestation("GCP", jwt_str, claims["sub"])
