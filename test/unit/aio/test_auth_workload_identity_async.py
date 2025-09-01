#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import asyncio
import json
import logging
from base64 import b64decode
from unittest import mock
from urllib.parse import parse_qs, urlparse

import aiohttp
import jwt
import pytest

from snowflake.connector.aio._wif_util import AttestationProvider
from snowflake.connector.aio.auth import AuthByWorkloadIdentity
from snowflake.connector.errors import ProgrammingError

from ...csp_helpers import gen_dummy_id_token
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


# -- OIDC Tests --


async def test_explicit_oidc_valid_inline_token_plumbed_to_api():
    dummy_token = gen_dummy_id_token(sub="service-1", iss="issuer-1")
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.OIDC, token=dummy_token
    )
    await auth_class.prepare()

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
    await auth_class.prepare()
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
        await auth_class.prepare()
    assert "No workload identity credential was found for 'OIDC'" in str(excinfo.value)


async def test_explicit_oidc_no_token_raises_error():
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.OIDC, token=None)
    with pytest.raises(ProgrammingError) as excinfo:
        await auth_class.prepare()
    assert "No workload identity credential was found for 'OIDC'" in str(excinfo.value)


# -- AWS Tests --


async def test_explicit_aws_no_auth_raises_error(
    fake_aws_environment: FakeAwsEnvironmentAsync,
):
    fake_aws_environment.credentials = None

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    with pytest.raises(ProgrammingError) as excinfo:
        await auth_class.prepare()
    assert "No workload identity credential was found for 'AWS'" in str(excinfo.value)


async def test_explicit_aws_encodes_audience_host_signature_to_api(
    fake_aws_environment: FakeAwsEnvironmentAsync,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    await auth_class.prepare()

    data = await extract_api_data(auth_class)
    assert data["AUTHENTICATOR"] == "WORKLOAD_IDENTITY"
    assert data["PROVIDER"] == "AWS"
    verify_aws_token(data["TOKEN"], fake_aws_environment.region)


async def test_explicit_aws_uses_regional_hostname(
    fake_aws_environment: FakeAwsEnvironmentAsync,
):
    fake_aws_environment.region = "antarctica-northeast-3"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    await auth_class.prepare()

    data = await extract_api_data(auth_class)
    decoded_token = json.loads(b64decode(data["TOKEN"]))
    hostname_from_url = urlparse(decoded_token["url"]).hostname
    hostname_from_header = decoded_token["headers"]["Host"]

    expected_hostname = "sts.antarctica-northeast-3.amazonaws.com"
    assert expected_hostname == hostname_from_url
    assert expected_hostname == hostname_from_header


async def test_explicit_aws_generates_unique_assertion_content(
    fake_aws_environment: FakeAwsEnvironmentAsync,
):
    fake_aws_environment.arn = (
        "arn:aws:sts::123456789:assumed-role/A-Different-Role/i-34afe100cad287fab"
    )
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    await auth_class.prepare()

    assert (
        '{"_provider":"AWS","arn":"arn:aws:sts::123456789:assumed-role/A-Different-Role/i-34afe100cad287fab"}'
        == auth_class.assertion_content
    )


# -- GCP Tests --


def _mock_aiohttp_exception(exception):
    class MockResponse:
        def __init__(self, exception):
            self.exception = exception

        async def __aenter__(self):
            raise self.exception

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    def mock_request(*args, **kwargs):
        return MockResponse(exception)

    return mock_request


@pytest.mark.parametrize(
    "exception",
    [
        aiohttp.ClientError(),
        aiohttp.ConnectionTimeoutError(),
        asyncio.TimeoutError(),
    ],
)
async def test_explicit_gcp_metadata_server_error_raises_auth_error(exception):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)

    mock_request = _mock_aiohttp_exception(exception)

    with mock.patch("aiohttp.ClientSession.request", side_effect=mock_request):
        with pytest.raises(ProgrammingError) as excinfo:
            await auth_class.prepare()
        assert "No workload identity credential was found for 'GCP'" in str(
            excinfo.value
        )


async def test_explicit_gcp_wrong_issuer_raises_error(
    fake_gce_metadata_service: FakeGceMetadataServiceAsync,
):
    fake_gce_metadata_service.iss = "not-google"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)
    with pytest.raises(ProgrammingError) as excinfo:
        await auth_class.prepare()
    assert "No workload identity credential was found for 'GCP'" in str(excinfo.value)


async def test_explicit_gcp_plumbs_token_to_api(
    fake_gce_metadata_service: FakeGceMetadataServiceAsync,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)
    await auth_class.prepare()

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
    await auth_class.prepare()

    assert auth_class.assertion_content == '{"_provider":"GCP","sub":"123456"}'


# -- Azure Tests --


@pytest.mark.parametrize(
    "exception",
    [
        aiohttp.ClientError(),
        asyncio.TimeoutError(),
        aiohttp.ConnectionTimeoutError(),
    ],
)
async def test_explicit_azure_metadata_server_error_raises_auth_error(exception):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)

    mock_request = _mock_aiohttp_exception(exception)

    with mock.patch("aiohttp.ClientSession.request", side_effect=mock_request):
        with pytest.raises(ProgrammingError) as excinfo:
            await auth_class.prepare()
        assert "No workload identity credential was found for 'AZURE'" in str(
            excinfo.value
        )


async def test_explicit_azure_wrong_issuer_raises_error(fake_azure_metadata_service):
    fake_azure_metadata_service.iss = "not-azure"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    with pytest.raises(ProgrammingError) as excinfo:
        await auth_class.prepare()
    assert "No workload identity credential was found for 'AZURE'" in str(excinfo.value)


async def test_explicit_azure_plumbs_token_to_api(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    await auth_class.prepare()

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
    await auth_class.prepare()

    assert (
        '{"_provider":"AZURE","iss":"https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd","sub":"611ab25b-2e81-4e18-92a7-b21f2bebb269"}'
        == auth_class.assertion_content
    )


async def test_explicit_azure_uses_default_entra_resource_if_unspecified(
    fake_azure_metadata_service,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    await auth_class.prepare()

    token = fake_azure_metadata_service.token
    parsed = jwt.decode(token, options={"verify_signature": False})
    assert (
        parsed["aud"] == "api://fd3f753b-eed3-462c-b6a7-a4b5bb650aad"
    )  # the default entra resource defined in wif_util.py.


async def test_explicit_azure_uses_explicit_entra_resource(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.AZURE, entra_resource="api://non-standard"
    )
    await auth_class.prepare()

    token = fake_azure_metadata_service.token
    parsed = jwt.decode(token, options={"verify_signature": False})
    assert parsed["aud"] == "api://non-standard"
