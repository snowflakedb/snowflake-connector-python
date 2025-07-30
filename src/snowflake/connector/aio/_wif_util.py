#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import json
import logging
import os
from base64 import b64encode

import aiohttp

try:
    import aioboto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.utils import InstanceMetadataRegionFetcher
except ImportError:
    aioboto3 = None
    SigV4Auth = None
    AWSRequest = None
    InstanceMetadataRegionFetcher = None

from ..errorcode import ER_WIF_CREDENTIALS_NOT_FOUND
from ..errors import ProgrammingError
from ..wif_util import (
    DEFAULT_ENTRA_SNOWFLAKE_RESOURCE,
    SNOWFLAKE_AUDIENCE,
    AttestationProvider,
    WorkloadIdentityAttestation,
    create_oidc_attestation,
    extract_iss_and_sub_without_signature_verification,
)

logger = logging.getLogger(__name__)


async def try_metadata_service_call(
    method: str, url: str, headers: dict, timeout_sec: int = 3
) -> aiohttp.ClientResponse | None:
    """Tries to make a HTTP request to the metadata service with the given URL, method, headers and timeout.

    If we receive an error response or any exceptions are raised, returns None. Otherwise returns the response.
    """
    try:
        timeout = aiohttp.ClientTimeout(total=timeout_sec)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(
                method=method, url=url, headers=headers
            ) as response:
                if not response.ok:
                    return None
                # Create a copy of the response data since the response will be closed
                content = await response.read()
                response._content = content
                return response
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None


async def get_aws_region() -> str | None:
    """Get the current AWS workload's region, if any."""
    # Use sync implementation which has proper mocking support
    from ..wif_util import get_aws_region as sync_get_aws_region

    return sync_get_aws_region()


async def get_aws_arn() -> str | None:
    """Get the current AWS workload's ARN, if any."""
    if aioboto3 is None:
        logger.debug("aioboto3 not available, falling back to sync implementation")
        from ..wif_util import get_aws_arn as sync_get_aws_arn

        return sync_get_aws_arn()

    try:
        session = aioboto3.Session()
        async with session.client("sts") as client:
            caller_identity = await client.get_caller_identity()
            if not caller_identity or "Arn" not in caller_identity:
                return None
            return caller_identity["Arn"]
    except Exception:
        logger.debug("Failed to get AWS ARN", exc_info=True)
        return None


async def create_aws_attestation() -> WorkloadIdentityAttestation | None:
    """Tries to create a workload identity attestation for AWS.

    If the application isn't running on AWS or no credentials were found, returns None.
    """
    if aioboto3 is None:
        logger.debug("aioboto3 not available, falling back to sync implementation")
        from ..wif_util import create_aws_attestation as sync_create_aws_attestation

        return sync_create_aws_attestation()

    try:
        # Get credentials using aioboto3
        session = aioboto3.Session()
        aws_creds = await session.get_credentials()  # This IS async in aioboto3
        if not aws_creds:
            logger.debug("No AWS credentials were found.")
            return None

        region = await get_aws_region()
        if not region:
            logger.debug("No AWS region was found.")
            return None

        arn = await get_aws_arn()
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
        credential = b64encode(json.dumps(assertion_dict).encode("utf-8")).decode(
            "utf-8"
        )
        return WorkloadIdentityAttestation(
            AttestationProvider.AWS, credential, {"arn": arn}
        )
    except Exception:
        logger.debug("Failed to create AWS attestation", exc_info=True)
        return None


async def create_gcp_attestation() -> WorkloadIdentityAttestation | None:
    """Tries to create a workload identity attestation for GCP.

    If the application isn't running on GCP or no credentials were found, returns None.
    """
    res = await try_metadata_service_call(
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

    jwt_str = res._content.decode("utf-8")
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


async def create_azure_attestation(
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

    res = await try_metadata_service_call(
        method="GET",
        url=f"{url_without_query_string}?{query_params}",
        headers=headers,
    )
    if res is None:
        # Most likely we're just not running on Azure, which may be expected.
        logger.debug("Azure metadata server request was not successful.")
        return None

    try:
        response_text = res._content.decode("utf-8")
        response_data = json.loads(response_text)
        jwt_str = response_data.get("access_token")
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
    if not issuer.startswith("https://sts.windows.net/"):
        # This might happen if we're running on a different platform that responds to the same metadata request signature as Azure.
        logger.debug("Unexpected Azure token issuer '%s'", issuer)
        return None

    return WorkloadIdentityAttestation(
        AttestationProvider.AZURE, jwt_str, {"iss": issuer, "sub": subject}
    )


async def create_autodetect_attestation(
    entra_resource: str, token: str | None = None
) -> WorkloadIdentityAttestation | None:
    """Tries to create an attestation using the auto-detected runtime environment.

    If no attestation can be found, returns None.
    """
    attestation = create_oidc_attestation(token)
    if attestation:
        return attestation

    attestation = await create_aws_attestation()
    if attestation:
        return attestation

    attestation = await create_azure_attestation(entra_resource)
    if attestation:
        return attestation

    attestation = await create_gcp_attestation()
    if attestation:
        return attestation

    return None


async def create_attestation(
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
        attestation = await create_aws_attestation()
    elif provider == AttestationProvider.AZURE:
        attestation = await create_azure_attestation(entra_resource)
    elif provider == AttestationProvider.GCP:
        attestation = await create_gcp_attestation()
    elif provider == AttestationProvider.OIDC:
        attestation = create_oidc_attestation(token)
    elif provider is None:
        attestation = await create_autodetect_attestation(entra_resource, token)

    if not attestation:
        provider_str = "auto-detect" if provider is None else provider.value
        raise ProgrammingError(
            msg=f"No workload identity credential was found for '{provider_str}'.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    return attestation
