from __future__ import annotations

import json
import logging
import os
from base64 import b64encode
from dataclasses import dataclass
from enum import Enum, unique

import jwt

from .options import (
    azure_identity,
    boto3,
    botocore,
    installed_azure_identity,
    installed_boto,
)

if installed_boto:
    SigV4Auth = botocore.auth.SigV4Auth
    AWSRequest = botocore.awsrequest.AWSRequest
    InstanceMetadataRegionFetcher = botocore.utils.InstanceMetadataRegionFetcher

from .errorcode import ER_INVALID_WIF_SETTINGS, ER_WIF_CREDENTIALS_NOT_FOUND
from .errors import MissingDependencyError, ProgrammingError
from .session_manager import SessionManager, SessionManagerFactory

logger = logging.getLogger(__name__)
SNOWFLAKE_AUDIENCE = "snowflakecomputing.com"
DEFAULT_ENTRA_SNOWFLAKE_RESOURCE = "api://fd3f753b-eed3-462c-b6a7-a4b5bb650aad"
GCP_METADATA_SERVICE_ACCOUNT_BASE_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default"
AZURE_WIF_FEDERATION_AUDIENCE = "api://AzureADTokenExchange"


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
        try:
            return AttestationProvider[provider.upper()]
        except KeyError:
            raise ProgrammingError(
                msg=f"Unknown workload_identity_provider: '{provider}'. Expected one of: {', '.join(AttestationProvider.all_string_values())}",
                errno=ER_INVALID_WIF_SETTINGS,
            )

    @staticmethod
    def all_string_values() -> list[str]:
        """Returns a list of all string values of the AttestationProvider enum."""
        return [provider.value for provider in AttestationProvider]


@dataclass
class WorkloadIdentityAttestation:
    provider: AttestationProvider
    credential: str
    user_identifier_components: dict


def extract_iss_and_sub_without_signature_verification(jwt_str: str) -> tuple[str, str]:
    """Extracts the 'iss' and 'sub' claims from the given JWT, without verifying the signature.

    Note: the real token verification (including signature verification) happens on the Snowflake side. The driver doesn't have
    the keys to verify these JWTs, and in any case that's not where the security boundary is drawn.

    We only decode the JWT here to get some basic claims, which will be used for a) a quick smoke test to ensure the token is well-formed,
    and b) to find the unique user being asserted and populate assertion_content. The latter may be used for logging
    and possibly caching.

    Any errors during token parsing will be bubbled up. Missing 'iss' or 'sub' claims will also raise an error.
    """
    try:
        claims = jwt.decode(jwt_str, options={"verify_signature": False})
    except jwt.InvalidTokenError as e:
        raise ProgrammingError(
            msg=f"Invalid JWT token: {e}",
            errno=ER_INVALID_WIF_SETTINGS,
        )

    if not ("iss" in claims and "sub" in claims):
        raise ProgrammingError(
            msg="Token is missing 'iss' or 'sub' claims.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    return claims["iss"], claims["sub"]


def get_aws_region() -> str:
    """Get the current AWS workload's region, or raises an error if it's missing."""

    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")

    if not region:
        # Fallback for EC2 environments
        # TODO: SNOW-2223669 Investigate if our adapters - containing settings of http traffic - should be passed here as boto urllib3session. Those requests go to local servers, so they do not need Proxy setup or Headers customization in theory. But we may want to have all the traffic going through one class (e.g. Adapter or mixin).
        region = InstanceMetadataRegionFetcher().retrieve_region()

    if not region:
        raise ProgrammingError(
            msg="No AWS region was found. Ensure the application is running on AWS.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    return region


def get_aws_sts_hostname(region: str, partition: str) -> str:
    """Constructs the AWS STS hostname for a given region and partition.

    Args:
        region (str): The AWS region (e.g., 'us-east-1', 'cn-north-1').
        partition (str): The AWS partition (e.g., 'aws', 'aws-cn', 'aws-us-gov').

    Returns:
        str: The AWS STS hostname (e.g., 'sts.us-east-1.amazonaws.com')
             if a valid hostname can be constructed, otherwise raises a ProgrammingError.

    References:
    - https://docs.aws.amazon.com/sdkref/latest/guide/feature-sts-regionalized-endpoints.html
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html
    - https://docs.aws.amazon.com/general/latest/gr/sts.html
    """
    if partition == "aws":
        # For the 'aws' partition, STS endpoints are generally regional
        # except for the global endpoint (sts.amazonaws.com) which is
        # generally resolved to us-east-1 under the hood by the SDKs
        # when a region is not explicitly specified.
        # However, for explicit regional endpoints, the format is sts.<region>.amazonaws.com
        return f"sts.{region}.amazonaws.com"
    elif partition == "aws-cn":
        # China regions have a different domain suffix
        return f"sts.{region}.amazonaws.com.cn"
    elif partition == "aws-us-gov":
        return (
            f"sts.{region}.amazonaws.com"  # GovCloud uses .com, but dedicated regions
        )
    else:
        raise ProgrammingError(
            msg=f"Invalid AWS partition: '{partition}'.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )


def get_aws_session(impersonation_path: list[str] | None = None):
    """Creates a boto3 session with the appropriate credentials.

    If impersonation_path is provided, this uses the role at the end of the path. Otherwise, this uses the role attached to the current workload.
    """
    session = boto3.session.Session()

    impersonation_path = impersonation_path or []
    for arn in impersonation_path:
        response = session.client("sts").assume_role(
            RoleArn=arn, RoleSessionName="identity-federation-session"
        )
        creds = response["Credentials"]
        session = boto3.session.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return session


def create_aws_attestation(
    impersonation_path: list[str] | None = None,
    aws_use_outbound_token: bool = False,
) -> WorkloadIdentityAttestation:
    """Tries to create a workload identity attestation for AWS.

    If the application isn't running on AWS or no credentials were found, raises an error.
    """
    if not installed_boto:
        raise MissingDependencyError(
            msg="AWS Workload Identity Federation can't be used because boto3 or botocore optional dependency is not installed. Try installing missing dependencies.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    # TODO: SNOW-2223669 Investigate if our adapters - containing settings of http traffic - should be passed here as boto urllib3session. Those requests go to local servers, so they do not need Proxy setup or Headers customization in theory. But we may want to have all the traffic going through one class (e.g. Adapter or mixin).
    session = get_aws_session(impersonation_path)

    aws_creds = session.get_credentials()
    if not aws_creds:
        raise ProgrammingError(
            msg="No AWS credentials were found. Ensure the application is running on AWS with an IAM role attached.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )
    region = get_aws_region()
    partition = session.get_partition_for_region(region)
    # The JWT-based GetWebIdentityToken method is opt-in via either the
    # workload_identity_aws_use_outbound_token connection option or the
    # SNOWFLAKE_ENABLE_AWS_WIF_OUTBOUND_TOKEN environment variable.
    #
    # Env variable is kept for backward compatibility as it's already
    # described in docs.snowflake.com :/
    env_outbound_token_enabled = (
        os.environ.get("SNOWFLAKE_ENABLE_AWS_WIF_OUTBOUND_TOKEN", "false").lower()
        == "true"
    )
    if aws_use_outbound_token or env_outbound_token_enabled:
        sts_client = session.client("sts", region_name=region)
        response = sts_client.get_web_identity_token(
            Audience=[SNOWFLAKE_AUDIENCE], SigningAlgorithm="ES384"
        )
        jwt_token = response["WebIdentityToken"]
        logger.debug("AWS outbound token prefix: %s", jwt_token[:10])
        return WorkloadIdentityAttestation(
            AttestationProvider.AWS,
            jwt_token,
            {"region": region, "partition": partition},
        )
    else:
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
        credential = b64encode(json.dumps(assertion_dict).encode("utf-8")).decode(
            "utf-8"
        )
        # Unlike other providers, for AWS, we only include general identifiers (region and partition)
        # rather than specific user identifiers, since we don't actually execute a GetCallerIdentity call.
        return WorkloadIdentityAttestation(
            AttestationProvider.AWS,
            credential,
            {"region": region, "partition": partition},
        )


def get_gcp_access_token(session_manager: SessionManager) -> str:
    """Gets a GCP access token from the metadata server.

    If the application isn't running on GCP or no credentials were found, raises an error.
    """
    try:
        res = session_manager.request(
            method="GET",
            url=f"{GCP_METADATA_SERVICE_ACCOUNT_BASE_URL}/token",
            headers={
                "Metadata-Flavor": "Google",
            },
        )
        res.raise_for_status()
        return res.json()["access_token"]
    except Exception as e:
        raise ProgrammingError(
            msg=f"Error fetching GCP access token: {e}. Ensure the application is running on GCP.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )


def get_gcp_identity_token_via_impersonation(
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

    current_sa_token = get_gcp_access_token(session_manager)
    impersonation_path = [
        f"projects/-/serviceAccounts/{client_id}" for client_id in impersonation_path
    ]
    try:
        res = session_manager.post(
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
        res.raise_for_status()
        return res.json()["token"]
    except Exception as e:
        raise ProgrammingError(
            msg=f"Error fetching GCP identity token for impersonated GCP service account '{impersonation_path[-1]}': {e}. Ensure the application is running on GCP.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )


def get_gcp_identity_token(session_manager: SessionManager) -> str:
    """Gets a GCP identity token from the metadata server.

    If the application isn't running on GCP or no credentials were found, raises an error.
    """
    try:
        res = session_manager.request(
            method="GET",
            url=f"{GCP_METADATA_SERVICE_ACCOUNT_BASE_URL}/identity?audience={SNOWFLAKE_AUDIENCE}",
            headers={
                "Metadata-Flavor": "Google",
            },
        )
        res.raise_for_status()
        return res.content.decode("utf-8")
    except Exception as e:
        raise ProgrammingError(
            msg=f"Error fetching GCP identity token: {e}. Ensure the application is running on GCP.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )


def create_gcp_attestation(
    session_manager: SessionManager,
    impersonation_path: list[str] | None = None,
) -> WorkloadIdentityAttestation:
    """Tries to create a workload identity attestation for GCP.

    If the application isn't running on GCP or no credentials were found, raises an error.
    """
    if impersonation_path:
        jwt_str = get_gcp_identity_token_via_impersonation(
            impersonation_path, session_manager
        )
    else:
        jwt_str = get_gcp_identity_token(session_manager)

    _, subject = extract_iss_and_sub_without_signature_verification(jwt_str)
    return WorkloadIdentityAttestation(
        AttestationProvider.GCP, jwt_str, {"sub": subject}
    )


def get_azure_mi_token_via_aks(resource: str) -> str:
    """Gets an Azure MI access token via WorkloadIdentityCredential on AKS."""
    if not installed_azure_identity:
        raise MissingDependencyError(
            "azure-identity (install with: pip install 'snowflake-connector-python[azure]')"
        )
    logger.debug(
        "Detected AKS workload identity environment, using WorkloadIdentityCredential"
    )
    try:
        credential = azure_identity.WorkloadIdentityCredential()
        return credential.get_token(f"{resource}/.default").token
    except Exception as e:
        raise ProgrammingError(
            msg=f"Error fetching Azure MI token via WorkloadIdentityCredential: {e}. Ensure the application is running on AKS with workload identity configured.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )


def get_azure_sp_token_via_impersonation(
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
        res = session_manager.post(
            url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": sp_client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": mi_token,
                "scope": f"{snowflake_entra_resource}/.default",
            },
        )
        response_text = res.text
        response_data = res.json()
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


def create_azure_attestation(
    snowflake_entra_resource: str,
    session_manager: SessionManager | None = None,
    impersonation_path: list[str] | None = None,
) -> WorkloadIdentityAttestation:
    """Tries to create a workload identity attestation for Azure.

    If the application isn't running on Azure or no credentials were found, raises an error.
    """
    # AKS Workload Identity path: the three env vars are injected by the AKS webhook,
    # and the token file is mounted by the Azure Workload Identity webhook.
    # Checking file existence (rather than KUBERNETES_SERVICE_HOST) correctly handles
    # pods with enableServiceLinks=false and avoids false positives on non-AKS K8s.
    _federated_token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE", "")
    is_aks = all(
        [
            os.environ.get("AZURE_CLIENT_ID"),
            os.environ.get("AZURE_TENANT_ID"),
            _federated_token_file,
            os.path.exists(_federated_token_file),
        ]
    )
    if is_aks:
        if impersonation_path:
            raise ProgrammingError(
                msg="workload_identity_impersonation_path is not supported on AKS.",
                errno=ER_INVALID_WIF_SETTINGS,
            )
        jwt_str = get_azure_mi_token_via_aks(snowflake_entra_resource)
    else:
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
        url_without_query_string = (
            "http://169.254.169.254/metadata/identity/oauth2/token"
        )
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
            res = session_manager.request(
                method="GET",
                url=f"{url_without_query_string}?{query_params}",
                headers=headers,
            )
            response_text = res.text
            response_data = res.json()
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
            jwt_str = get_azure_sp_token_via_impersonation(
                jwt_str,
                impersonation_path[0],
                snowflake_entra_resource,
                session_manager,
            )
    issuer, subject = extract_iss_and_sub_without_signature_verification(jwt_str)
    return WorkloadIdentityAttestation(
        AttestationProvider.AZURE, jwt_str, {"iss": issuer, "sub": subject}
    )


def create_oidc_attestation(token: str | None) -> WorkloadIdentityAttestation:
    """Tries to create an attestation using the given token.

    If this is not populated, raises an error.
    """
    if not token:
        raise ProgrammingError(
            msg="token must be provided if workload_identity_provider=OIDC",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )

    issuer, subject = extract_iss_and_sub_without_signature_verification(token)
    return WorkloadIdentityAttestation(
        AttestationProvider.OIDC, token, {"iss": issuer, "sub": subject}
    )


def create_attestation(
    provider: AttestationProvider,
    entra_resource: str | None = None,
    token: str | None = None,
    impersonation_path: list[str] | None = None,
    session_manager: SessionManager | None = None,
    aws_use_outbound_token: bool = False,
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
        return create_aws_attestation(impersonation_path, aws_use_outbound_token)
    elif provider == AttestationProvider.AZURE:
        return create_azure_attestation(
            entra_resource, session_manager, impersonation_path
        )
    elif provider == AttestationProvider.GCP:
        return create_gcp_attestation(session_manager, impersonation_path)
    elif provider == AttestationProvider.OIDC:
        return create_oidc_attestation(token)
    else:
        raise ProgrammingError(
            msg=f"Unknown workload_identity_provider: '{provider.value}'.",
            errno=ER_WIF_CREDENTIALS_NOT_FOUND,
        )
