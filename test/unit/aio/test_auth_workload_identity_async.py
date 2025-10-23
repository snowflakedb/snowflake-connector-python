#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import asyncio
import json
import logging
from base64 import b64decode
from unittest import mock
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlparse

import aiohttp
import jwt
import pytest

from snowflake.connector.aio._wif_util import AttestationProvider
from snowflake.connector.aio.auth import AuthByWorkloadIdentity
from snowflake.connector.errors import ProgrammingError

from ...csp_helpers import gen_dummy_access_token, gen_dummy_id_token
from .csp_helpers_async import FakeAwsEnvironmentAsync, FakeGceMetadataServiceAsync

logger = logging.getLogger(__name__)


async def extract_api_data(auth_class: AuthByWorkloadIdentity):
    """Extracts the 'data' portion of the request body populated by the given auth class."""
    req_body = {"data": {}}
    await auth_class.update_body(req_body)
    return req_body["data"]


def verify_aws_token(token: str, region: str):
    """Performs some basic checks on a 'token' produced for AWS, to ensure it includes the expected fields."""
    decoded_token = json.loads(b64decode(token))

    parsed_url = urlparse(decoded_token["url"])
    assert parsed_url.scheme == "https"
    assert parsed_url.hostname == f"sts.{region}.amazonaws.com"
    query_string = parse_qs(parsed_url.query)
    assert query_string.get("Action")[0] == "GetCallerIdentity"
    assert query_string.get("Version")[0] == "2011-06-15"

    assert decoded_token["method"] == "POST"

    headers = decoded_token["headers"]
    assert set(headers.keys()) == {
        "Host",
        "X-Snowflake-Audience",
        "X-Amz-Date",
        "X-Amz-Security-Token",
        "Authorization",
    }
    assert headers["Host"] == f"sts.{region}.amazonaws.com"
    assert headers["X-Snowflake-Audience"] == "snowflakecomputing.com"


def test_mro():
    """Ensure that methods from AuthByPluginAsync override those from AuthByPlugin."""
    from snowflake.connector.aio.auth import AuthByPlugin as AuthByPluginAsync
    from snowflake.connector.auth import AuthByPlugin as AuthByPluginSync

    assert AuthByWorkloadIdentity.mro().index(
        AuthByPluginAsync
    ) < AuthByWorkloadIdentity.mro().index(AuthByPluginSync)


@mock.patch("snowflake.connector.aio._network.SnowflakeRestful._post_request")
async def test_wif_authenticator_with_no_provider_raises_error(mock_post_request):
    from snowflake.connector.aio import SnowflakeConnection

    with pytest.raises(ProgrammingError) as excinfo:
        conn = SnowflakeConnection(
            account="account",
            authenticator="WORKLOAD_IDENTITY",
        )
        await conn.connect()
    assert (
        "workload_identity_provider must be set to one of AWS,AZURE,GCP,OIDC when authenticator is WORKLOAD_IDENTITY."
        in str(excinfo.value)
    )
    # Ensure no network requests were made
    mock_post_request.assert_not_called()


@mock.patch("snowflake.connector.aio._network.SnowflakeRestful._post_request")
async def test_wif_authenticator_with_invalid_provider_raises_error(mock_post_request):
    from snowflake.connector.aio import SnowflakeConnection

    with pytest.raises(ProgrammingError) as excinfo:
        conn = SnowflakeConnection(
            account="account",
            authenticator="WORKLOAD_IDENTITY",
            workload_identity_provider="INVALID",
        )
        await conn.connect()
    assert (
        "Unknown workload_identity_provider: 'INVALID'. Expected one of: AWS, AZURE, GCP, OIDC"
        in str(excinfo.value)
    )
    # Ensure no network requests were made
    mock_post_request.assert_not_called()


@mock.patch("snowflake.connector.aio._network.SnowflakeRestful._post_request")
@pytest.mark.parametrize("authenticator", ["WORKLOAD_IDENTITY", "workload_identity"])
async def test_wif_authenticator_is_case_insensitive(
    mock_post_request, fake_aws_environment, authenticator
):
    """Test that connect() with workload_identity authenticator creates AuthByWorkloadIdentity instance."""
    from snowflake.connector.aio import SnowflakeConnection

    # Mock the post request to prevent actual authentication attempt
    async def mock_post(*args, **kwargs):
        return {
            "success": True,
            "data": {
                "token": "fake-token",
                "masterToken": "fake-master-token",
                "sessionId": "fake-session-id",
            },
        }

    mock_post_request.side_effect = mock_post

    connection = SnowflakeConnection(
        account="testaccount",
        authenticator=authenticator,
        workload_identity_provider="AWS",
    )
    await connection.connect()

    # Verify that the auth instance is of the correct type
    assert isinstance(connection.auth_class, AuthByWorkloadIdentity)

    await connection.close()


# -- OIDC Tests --


async def test_explicit_oidc_valid_inline_token_plumbed_to_api():
    dummy_token = gen_dummy_id_token(sub="service-1", iss="issuer-1")
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.OIDC, token=dummy_token
    )
    await auth_class.prepare(conn=None)

    assert await extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "OIDC",
        "TOKEN": dummy_token,
    }


async def test_explicit_oidc_valid_inline_token_generates_unique_assertion_content():
    dummy_token = gen_dummy_id_token(sub="service-1", iss="issuer-1")
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.OIDC, token=dummy_token
    )
    await auth_class.prepare(conn=None)
    assert (
        auth_class.assertion_content
        == '{"_provider":"OIDC","iss":"issuer-1","sub":"service-1"}'
    )


async def test_explicit_oidc_invalid_inline_token_raises_error():
    invalid_token = "not-a-jwt"
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.OIDC, token=invalid_token
    )
    with pytest.raises(ProgrammingError) as excinfo:
        await auth_class.prepare(conn=None)
    assert "Invalid JWT token: " in str(excinfo.value)


async def test_explicit_oidc_no_token_raises_error():
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.OIDC, token=None)
    with pytest.raises(ProgrammingError) as excinfo:
        await auth_class.prepare(conn=None)
    assert "token must be provided if workload_identity_provider=OIDC" in str(
        excinfo.value
    )


# -- AWS Tests --


async def test_explicit_aws_no_auth_raises_error(
    fake_aws_environment: FakeAwsEnvironmentAsync,
):
    fake_aws_environment.credentials = None

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    with pytest.raises(ProgrammingError) as excinfo:
        await auth_class.prepare(conn=None)
    assert "No AWS credentials were found" in str(excinfo.value)


async def test_explicit_aws_encodes_audience_host_signature_to_api(
    fake_aws_environment: FakeAwsEnvironmentAsync,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    await auth_class.prepare(conn=None)

    data = await extract_api_data(auth_class)
    assert data["AUTHENTICATOR"] == "WORKLOAD_IDENTITY"
    assert data["PROVIDER"] == "AWS"
    verify_aws_token(data["TOKEN"], fake_aws_environment.region)


@pytest.mark.parametrize(
    "region,expected_hostname",
    [
        ("us-east-1", "sts.us-east-1.amazonaws.com"),
        ("af-south-1", "sts.af-south-1.amazonaws.com"),
        ("us-gov-west-1", "sts.us-gov-west-1.amazonaws.com"),
        ("cn-north-1", "sts.cn-north-1.amazonaws.com.cn"),
    ],
)
async def test_explicit_aws_uses_regional_hostnames(
    fake_aws_environment: FakeAwsEnvironmentAsync, region: str, expected_hostname: str
):
    fake_aws_environment.region = region

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    await auth_class.prepare(conn=None)

    data = await extract_api_data(auth_class)
    decoded_token = json.loads(b64decode(data["TOKEN"]))
    hostname_from_url = urlparse(decoded_token["url"]).hostname
    hostname_from_header = decoded_token["headers"]["Host"]

    assert expected_hostname == hostname_from_url
    assert expected_hostname == hostname_from_header


async def test_explicit_aws_generates_unique_assertion_content(
    fake_aws_environment: FakeAwsEnvironmentAsync,
):
    fake_aws_environment.arn = (
        "arn:aws:sts::123456789:assumed-role/A-Different-Role/i-34afe100cad287fab"
    )
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    await auth_class.prepare(conn=None)

    assert (
        '{"_provider":"AWS","partition":"aws","region":"us-east-1"}'
        == auth_class.assertion_content
    )


# -- GCP Tests --


def _mock_aiohttp_exception(exception):
    async def mock_request(*args, **kwargs):
        raise exception

    return mock_request


@pytest.mark.parametrize(
    "exception",
    [
        aiohttp.ClientError(),
        aiohttp.ConnectionTimeoutError(),
        asyncio.TimeoutError(),
    ],
)
async def test_explicit_gcp_metadata_server_error_bubbles_up(exception):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)

    mock_request = _mock_aiohttp_exception(exception)

    with mock.patch("aiohttp.ClientSession.request", side_effect=mock_request):
        with pytest.raises(ProgrammingError) as excinfo:
            await auth_class.prepare(conn=None)

    assert "Error fetching GCP identity token:" in str(excinfo.value)
    assert "Ensure the application is running on GCP." in str(excinfo.value)


async def test_explicit_gcp_plumbs_token_to_api(
    fake_gce_metadata_service: FakeGceMetadataServiceAsync,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)
    await auth_class.prepare(conn=None)

    assert await extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "GCP",
        "TOKEN": fake_gce_metadata_service.token,
    }


async def test_explicit_gcp_generates_unique_assertion_content(
    fake_gce_metadata_service: FakeGceMetadataServiceAsync,
):
    fake_gce_metadata_service.sub = "123456"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)
    await auth_class.prepare(conn=None)

    assert auth_class.assertion_content == '{"_provider":"GCP","sub":"123456"}'


@mock.patch("snowflake.connector.aio._session_manager.SessionManager.post")
async def test_gcp_calls_correct_apis_and_populates_auth_data_for_final_sa(
    mock_post_request, fake_gce_metadata_service: FakeGceMetadataServiceAsync
):
    fake_gce_metadata_service.sub = "sa1"
    impersonation_path = ["sa2", "sa3"]
    sa1_access_token = gen_dummy_access_token("sa1")
    sa3_id_token = gen_dummy_id_token("sa3")

    # Mock the POST request response
    class AsyncResponse:
        def __init__(self, content):
            self._content = content
            self.content = mock.Mock()
            self.content.read = AsyncMock(return_value=content)

    mock_post_request.return_value = AsyncResponse(
        json.dumps({"token": sa3_id_token}).encode("utf-8")
    )

    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.GCP, impersonation_path=impersonation_path
    )
    await auth_class.prepare(conn=None)

    mock_post_request.assert_called_once_with(
        url="https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa3:generateIdToken",
        headers={
            "Authorization": f"Bearer {sa1_access_token}",
            "Content-Type": "application/json",
        },
        json={
            "delegates": ["projects/-/serviceAccounts/sa2"],
            "audience": "snowflakecomputing.com",
        },
    )

    assert auth_class.assertion_content == '{"_provider":"GCP","sub":"sa3"}'
    assert await extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "GCP",
        "TOKEN": sa3_id_token,
    }


# -- Azure Tests --


@pytest.mark.parametrize(
    "exception",
    [
        aiohttp.ClientError(),
        asyncio.TimeoutError(),
        aiohttp.ConnectionTimeoutError(),
    ],
)
async def test_explicit_azure_metadata_server_error_bubbles_up(exception):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)

    mock_request = _mock_aiohttp_exception(exception)

    with mock.patch("aiohttp.ClientSession.request", side_effect=mock_request):
        with pytest.raises(ProgrammingError) as excinfo:
            await auth_class.prepare(conn=None)
    assert "Error fetching Azure metadata:" in str(excinfo.value)
    assert "Ensure the application is running on Azure." in str(excinfo.value)


@pytest.mark.parametrize(
    "issuer",
    [
        "https://sts.windows.net/067802cd-8f92-4c7c-bceb-ea8f15d31cc5",
        "https://login.microsoftonline.com/067802cd-8f92-4c7c-bceb-ea8f15d31cc5",
        "https://login.microsoftonline.com/067802cd-8f92-4c7c-bceb-ea8f15d31cc5/v2.0",
    ],
    ids=["v1", "v2_without_suffix", "v2_with_suffix"],
)
async def test_explicit_azure_v1_and_v2_issuers_accepted(
    fake_azure_metadata_service, issuer
):
    fake_azure_metadata_service.iss = issuer

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    await auth_class.prepare(conn=None)

    assert issuer == json.loads(auth_class.assertion_content)["iss"]


async def test_explicit_azure_plumbs_token_to_api(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    await auth_class.prepare(conn=None)

    assert await extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "AZURE",
        "TOKEN": fake_azure_metadata_service.token,
    }


async def test_explicit_azure_generates_unique_assertion_content(
    fake_azure_metadata_service,
):
    fake_azure_metadata_service.iss = (
        "https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd"
    )
    fake_azure_metadata_service.sub = "611ab25b-2e81-4e18-92a7-b21f2bebb269"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    await auth_class.prepare(conn=None)

    assert (
        '{"_provider":"AZURE","iss":"https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd","sub":"611ab25b-2e81-4e18-92a7-b21f2bebb269"}'
        == auth_class.assertion_content
    )


async def test_explicit_azure_uses_default_entra_resource_if_unspecified(
    fake_azure_metadata_service,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    await auth_class.prepare(conn=None)

    token = fake_azure_metadata_service.token
    parsed = jwt.decode(token, options={"verify_signature": False})
    assert (
        parsed["aud"] == "api://fd3f753b-eed3-462c-b6a7-a4b5bb650aad"
    )  # the default entra resource defined in wif_util.py.


async def test_explicit_azure_uses_explicit_entra_resource(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.AZURE, entra_resource="api://non-standard"
    )
    await auth_class.prepare(conn=None)

    token = fake_azure_metadata_service.token
    parsed = jwt.decode(token, options={"verify_signature": False})
    assert parsed["aud"] == "api://non-standard"


async def test_explicit_azure_omits_client_id_if_not_set(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    await auth_class.prepare(conn=None)
    assert fake_azure_metadata_service.requested_client_id is None


async def test_explicit_azure_uses_explicit_client_id_if_set(
    fake_azure_metadata_service, monkeypatch
):
    monkeypatch.setenv("MANAGED_IDENTITY_CLIENT_ID", "custom-client-id")
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    await auth_class.prepare(conn=None)

    assert fake_azure_metadata_service.requested_client_id == "custom-client-id"
