from __future__ import annotations

import json
import logging
import os
from base64 import b64encode

import jwt

from snowflake.connector.options import (
    aioboto3,
    aiobotocore,
    botocore,
    installed_aioboto,
)

from ..errorcode import ER_INVALID_WIF_SETTINGS, ER_WIF_CREDENTIALS_NOT_FOUND
from ..errors import MissingDependencyError, ProgrammingError
from ..wif_util import (
    AZURE_WIF_FEDERATION_AUDIENCE,
    DEFAULT_ENTRA_SNOWFLAKE_RESOURCE,
    SNOWFLAKE_AUDIENCE,
    AttestationProvider,
    WorkloadIdentityAttestation,
    create_oidc_attestation,
    extract_iss_and_sub_without_signature_verification,
    get_aws_sts_hostname,
)
from ._session_manager import SessionManager, SessionManagerFactory

logger = logging.getLogger(__name__)

GCP_METADATA_SERVICE_ACCOUNT_BASE_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default"


async def get_aws_region() -> str:
    """Get the current AWS workload's region."""
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")

    if not region:
        # Fallback for EC2 environments
        region = (
            await aiobotocore.utils.AioInstanceMetadataRegionFetcher().retrieve_region()
        )

    if not region:
        raise ProgrammingError(
            msg="No AWS region was found. Ensure the application is running on AWS.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )
    return region


async def get_aws_session(impersonation_path: list[str] | None = None):
    """Creates an aioboto3 session with the appropriate credentials.

    If impersonation_path is provided, this uses the role at the end of the path. Otherwise, this uses the role attached to the current workload.
    """
    session = aioboto3.Session()

    impersonation_path = impersonation_path or []
    for arn in impersonation_path:
        async with session.client("sts") as sts_client:
            response = await sts_client.assume_role(
                RoleArn=arn, RoleSessionName="identity-federation-session"
            )
        creds = response["Credentials"]
        session = aioboto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return session


async def create_aws_attestation(
    impersonation_path: list[str] | None = None,
) -> WorkloadIdentityAttestation:
    """Tries to create a workload identity attestation for AWS.

    If the application isn't running on AWS or no credentials were found, raises an error.
    """
    if not installed_aioboto:
        raise MissingDependencyError("aioboto3 or aiobotocore")

    session = await get_aws_session(impersonation_path)
    aws_creds = await session.get_credentials()
    if not aws_creds:
        raise ProgrammingError(
            msg="No AWS credentials were found. Ensure the application is running on AWS with an IAM role attached.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    region = await get_aws_region()
    partition = session.get_partition_for_region(region)
    sts_hostname = get_aws_sts_hostname(region, partition)
    request = botocore.awsrequest.AWSRequest(
        method="POST",
        url=f"https://{sts_hostname}/?Action=GetCallerIdentity&Version=2011-06-15",
        headers={
            "Host": sts_hostname,
            "X-Snowflake-Audience": SNOWFLAKE_AUDIENCE,
        },
    )

    # Freeze aiobotocore credentials for use with synchronous botocore signing
    frozen_creds = await aws_creds.get_frozen_credentials()
    botocore.auth.SigV4Auth(frozen_creds, "sts", region).add_auth(request)

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


async def get_gcp_access_token(session_manager: SessionManager) -> str:
    """Gets a GCP access token from the metadata server.

    If the application isn't running on GCP or no credentials were found, raises an error.
    """
    try:
        res = await session_manager.request(
            method="GET",
            url=f"{GCP_METADATA_SERVICE_ACCOUNT_BASE_URL}/token",
            headers={
                "Metadata-Flavor": "Google",
            },
        )

        content = await res.content.read()
        response_text = content.decode("utf-8")
        return json.loads(response_text)["access_token"]
    except Exception as e:
        raise ProgrammingError(
            msg=f"Error fetching GCP access token: {e}. Ensure the application is running on GCP.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )


async def get_gcp_identity_token_via_impersonation(
    impersonation_path: list[str], session_manager: SessionManager
) -> str:
    """Gets a GCP identity token from the metadata server.

    If the application isn't running on GCP or no credentials were found, raises an error.
    """
    if not impersonation_path:
        raise ProgrammingError(
            msg="Error: impersonation_path cannot be empty.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    current_sa_token = await get_gcp_access_token(session_manager)
    impersonation_path = [
        f"projects/-/serviceAccounts/{client_id}" for client_id in impersonation_path
    ]
    try:
        res = await session_manager.post(
            url=f"https://iamcredentials.googleapis.com/v1/{impersonation_path[-1]}:generateIdToken",
            headers={
                "Authorization": f"Bearer {current_sa_token}",
                "Content-Type": "application/json",
            },
            json={
                "delegates": impersonation_path[:-1],
                "audience": SNOWFLAKE_AUDIENCE,
            },
        )

        content = await res.content.read()
        response_text = content.decode("utf-8")
        return json.loads(response_text)["token"]
    except Exception as e:
        raise ProgrammingError(
            msg=f"Error fetching GCP identity token for impersonated GCP service account '{impersonation_path[-1]}': {e}. Ensure the application is running on GCP.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )


async def get_gcp_identity_token(session_manager: SessionManager) -> str:
    """Gets a GCP identity token from the metadata server.

    If the application isn't running on GCP or no credentials were found, raises an error.
    """
    try:
        res = await session_manager.request(
            method="GET",
            url=f"{GCP_METADATA_SERVICE_ACCOUNT_BASE_URL}/identity?audience={SNOWFLAKE_AUDIENCE}",
            headers={
                "Metadata-Flavor": "Google",
            },
        )

        content = await res.content.read()
        return content.decode("utf-8")
    except Exception as e:
        raise ProgrammingError(
            msg=f"Error fetching GCP identity token: {e}. Ensure the application is running on GCP.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )


async def create_gcp_attestation(
    session_manager: SessionManager,
    impersonation_path: list[str] | None = None,
) -> WorkloadIdentityAttestation:
    """Tries to create a workload identity attestation for GCP.

    If the application isn't running on GCP or no credentials were found, raises an error.
    """
    if impersonation_path:
        jwt_str = await get_gcp_identity_token_via_impersonation(
            impersonation_path, session_manager
        )
    else:
        jwt_str = await get_gcp_identity_token(session_manager)

    _, subject = extract_iss_and_sub_without_signature_verification(jwt_str)
    return WorkloadIdentityAttestation(
        AttestationProvider.GCP, jwt_str, {"sub": subject}
    )


async def get_azure_sp_token_via_impersonation(
    mi_token: str,
    sp_client_id: str,
    snowflake_entra_resource: str,
    session_manager: SessionManager,
) -> str:
    """Exchanges a managed identity token for a service principal token via the Entra ID token endpoint."""
    # Azure requires the MI and the app registration to be in the same tenant, so the
    # tid claim from the MI token is always the correct tenant for the token exchange endpoint.
    tenant_id = jwt.decode(mi_token, options={"verify_signature": False}).get("tid")
    if not tenant_id:
        raise ProgrammingError(
            msg="MI token is missing 'tid' claim; cannot determine tenant ID for impersonation.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )
    response_text = None
    try:
        res = await session_manager.post(
            url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": sp_client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": mi_token,
                "scope": f"{snowflake_entra_resource}/.default",
            },
        )
        content = await res.content.read()
        response_text = content.decode("utf-8")
        response_data = json.loads(response_text)
        res.raise_for_status()
    except Exception as e:
        raise ProgrammingError(
            msg=f"Error fetching SP token for Azure client_id '{sp_client_id}': {e}. Response: {response_text}",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    sp_token = response_data.get("access_token")
    if not sp_token:
        raise ProgrammingError(
            msg=f"No access token found in Entra ID response for client_id '{sp_client_id}'.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )
    return sp_token


async def create_azure_attestation(
    snowflake_entra_resource: str,
    session_manager: SessionManager | None = None,
    impersonation_path: list[str] | None = None,
) -> WorkloadIdentityAttestation:
    """Tries to create a workload identity attestation for Azure.

    If the application isn't running on Azure or no credentials were found, raises an error.
    """
    if impersonation_path:
        if len(impersonation_path) != 1:
            raise ProgrammingError(
                msg="Azure WIF impersonation only supports a single service principal (single-hop). impersonation_path must contain exactly one client_id.",
                errno=ER_INVALID_WIF_SETTINGS,
            )
    resource = (
        AZURE_WIF_FEDERATION_AUDIENCE
        if impersonation_path
        else snowflake_entra_resource
    )
    headers = {"Metadata": "true"}
    url_without_query_string = "http://169.254.169.254/metadata/identity/oauth2/token"
    query_params = f"api-version=2018-02-01&resource={resource}"

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
        query_params = f"api-version=2019-08-01&resource={resource}"

    # Allow configuring an explicit client ID, which may be used in Azure Functions,
    # if there are user-assigned identities, or multiple managed identities available.
    managed_identity_client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")
    if managed_identity_client_id:
        query_params += f"&client_id={managed_identity_client_id}"

    response_text = None
    try:
        res = await session_manager.request(
            method="GET",
            url=f"{url_without_query_string}?{query_params}",
            headers=headers,
        )

        content = await res.content.read()
        response_text = content.decode("utf-8")
        response_data = json.loads(response_text)
        res.raise_for_status()
    except Exception as e:
        raise ProgrammingError(
            msg=f"Error fetching Azure metadata: {e}. Response: {response_text}. Ensure the application is running on Azure.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    jwt_str = response_data.get("access_token")
    if not jwt_str:
        raise ProgrammingError(
            msg="No access token found in Azure metadata service response.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    if impersonation_path:
        jwt_str = await get_azure_sp_token_via_impersonation(
            jwt_str, impersonation_path[0], snowflake_entra_resource, session_manager
        )

    issuer, subject = extract_iss_and_sub_without_signature_verification(jwt_str)
    return WorkloadIdentityAttestation(
        AttestationProvider.AZURE, jwt_str, {"iss": issuer, "sub": subject}
    )


async def create_attestation(
    provider: AttestationProvider | None,
    entra_resource: str | None = None,
    token: str | None = None,
    impersonation_path: list[str] | None = None,
    session_manager: SessionManager | None = None,
) -> WorkloadIdentityAttestation:
    """Entry point to create an attestation using the given provider.

    If an explicit entra_resource was provided to the connector, this will be used. Otherwise, the default Snowflake Entra resource will be used.
    """
    entra_resource = entra_resource or DEFAULT_ENTRA_SNOWFLAKE_RESOURCE
    session_manager = (
        session_manager.clone()
        if session_manager
        else SessionManagerFactory.get_manager(use_pooling=True, max_retries=0)
    )

    if provider == AttestationProvider.AWS:
        return await create_aws_attestation(impersonation_path)
    elif provider == AttestationProvider.AZURE:
        return await create_azure_attestation(
            entra_resource, session_manager, impersonation_path
        )
    elif provider == AttestationProvider.GCP:
        return await create_gcp_attestation(session_manager, impersonation_path)
    elif provider == AttestationProvider.OIDC:
        return create_oidc_attestation(token)
    else:
        raise ProgrammingError(
            msg=f"Unknown workload_identity_provider: '{provider.value}'.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )
