from __future__ import annotations

import json
import logging
import os
from base64 import b64encode

import aioboto3
import aiohttp
from aiobotocore.utils import AioInstanceMetadataRegionFetcher
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from ..errorcode import ER_WIF_CREDENTIALS_NOT_FOUND
from ..errors import ProgrammingError
from ..wif_util import (
    DEFAULT_ENTRA_SNOWFLAKE_RESOURCE,
    SNOWFLAKE_AUDIENCE,
    AttestationProvider,
    WorkloadIdentityAttestation,
    create_oidc_attestation,
    extract_iss_and_sub_without_signature_verification,
    get_aws_sts_hostname,
)

logger = logging.getLogger(__name__)


async def get_aws_region() -> str:
    """Get the current AWS workload's region."""
    if "AWS_REGION" in os.environ:  # Lambda
        region = os.environ["AWS_REGION"]
    else:  # EC2
        region = await AioInstanceMetadataRegionFetcher().retrieve_region()

    if not region:
        raise ProgrammingError(
            msg="No AWS region was found. Ensure the application is running on AWS.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )
    return region


async def create_aws_attestation() -> WorkloadIdentityAttestation:
    """Tries to create a workload identity attestation for AWS.

    If the application isn't running on AWS or no credentials were found, raises an error.
    """
    session = aioboto3.Session()
    aws_creds = await session.get_credentials()
    if not aws_creds:
        raise ProgrammingError(
            msg="No AWS credentials were found. Ensure the application is running on AWS with an IAM role attached.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    region = await get_aws_region()
    partition = session.get_partition_for_region(region)
    sts_hostname = get_aws_sts_hostname(region, partition)
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
    # Unlike other providers, for AWS, we only include general identifiers (region and partition)
    # rather than specific user identifiers, since we don't actually execute a GetCallerIdentity call.
    return WorkloadIdentityAttestation(
        AttestationProvider.AWS, credential, {"region": region, "partition": partition}
    )


async def try_metadata_service_call(
    method: str, url: str, headers: dict, timeout_sec: int = 3
) -> aiohttp.ClientResponse | None:
    """Tries to make a HTTP request to the metadata service with the given URL, method, headers and timeout.

    Raises an error if an error response or any exceptions are raised.
    """
    timeout = aiohttp.ClientTimeout(total=timeout_sec)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.request(method=method, url=url, headers=headers) as response:
            response.raise_for_status()
            # Create a copy of the response data since the response will be closed
            content = await response.read()
            response._content = content
            return response


async def create_gcp_attestation() -> WorkloadIdentityAttestation:
    """Tries to create a workload identity attestation for GCP.

    If the application isn't running on GCP or no credentials were found, raises an error.
    """
    res = await try_metadata_service_call(
        method="GET",
        url=f"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience={SNOWFLAKE_AUDIENCE}",
        headers={
            "Metadata-Flavor": "Google",
        },
    )

    jwt_str = res._content.decode("utf-8")
    _, subject = extract_iss_and_sub_without_signature_verification(jwt_str)
    return WorkloadIdentityAttestation(
        AttestationProvider.GCP, jwt_str, {"sub": subject}
    )


async def create_azure_attestation(
    snowflake_entra_resource: str,
) -> WorkloadIdentityAttestation:
    """Tries to create a workload identity attestation for Azure.

    If the application isn't running on Azure or no credentials were found, raises an error.
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
            raise ProgrammingError(
                msg="Managed identity is not enabled on this Azure function.",
                errno=ER_WIF_CREDENTIALS_NOT_FOUND,
            )

        # Azure Functions uses a different endpoint, headers and API version.
        url_without_query_string = identity_endpoint
        headers = {"X-IDENTITY-HEADER": identity_header}
        query_params = f"api-version=2019-08-01&resource={snowflake_entra_resource}"

    # Allow configuring an explicit client ID, which may be used in Azure Functions,
    # if there are user-assigned identities, or multiple managed identities available.
    managed_identity_client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")
    if managed_identity_client_id:
        query_params += f"&client_id={managed_identity_client_id}"

    res = await try_metadata_service_call(
        method="GET",
        url=f"{url_without_query_string}?{query_params}",
        headers=headers,
    )

    response_text = res._content.decode("utf-8")
    response_data = json.loads(response_text)
    jwt_str = response_data.get("access_token")
    if not jwt_str:
        raise ProgrammingError(
            msg="No access token found in Azure metadata service response.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    issuer, subject = extract_iss_and_sub_without_signature_verification(jwt_str)
    return WorkloadIdentityAttestation(
        AttestationProvider.AZURE, jwt_str, {"iss": issuer, "sub": subject}
    )


async def create_attestation(
    provider: AttestationProvider | None,
    entra_resource: str | None = None,
    token: str | None = None,
) -> WorkloadIdentityAttestation:
    """Entry point to create an attestation using the given provider.

    If an explicit entra_resource was provided to the connector, this will be used. Otherwise, the default Snowflake Entra resource will be used.
    """
    entra_resource = entra_resource or DEFAULT_ENTRA_SNOWFLAKE_RESOURCE

    if provider == AttestationProvider.AWS:
        return await create_aws_attestation()
    elif provider == AttestationProvider.AZURE:
        return await create_azure_attestation(entra_resource)
    elif provider == AttestationProvider.GCP:
        return await create_gcp_attestation()
    elif provider == AttestationProvider.OIDC:
        return create_oidc_attestation(token)
    else:
        raise ProgrammingError(
            msg=f"Unknown workload_identity_provider: '{provider.value}'.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )
