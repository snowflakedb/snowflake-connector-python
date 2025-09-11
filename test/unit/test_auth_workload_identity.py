import json
import logging
from base64 import b64decode
from unittest import mock
from urllib.parse import parse_qs, urlparse

import jwt
import pytest

from snowflake.connector.auth import AuthByWorkloadIdentity
from snowflake.connector.errors import ProgrammingError
from snowflake.connector.vendored.requests.exceptions import (
    ConnectTimeout,
    HTTPError,
    Timeout,
)
from snowflake.connector.wif_util import AttestationProvider, get_aws_sts_hostname

from ..csp_helpers import (
    FakeAwsEnvironment,
    FakeGceMetadataService,
    build_response,
    gen_dummy_access_token,
    gen_dummy_id_token,
)

logger = logging.getLogger(__name__)


def extract_api_data(auth_class: AuthByWorkloadIdentity):
    """Extracts the 'data' portion of the request body populated by the given auth class."""
    req_body = {"data": {}}
    auth_class.update_body(req_body)
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


@mock.patch("snowflake.connector.network.SnowflakeRestful._post_request")
def test_wif_authenticator_with_no_provider_raises_error(mock_post_request):
    from snowflake.connector import connect

    with pytest.raises(ProgrammingError) as excinfo:
        connect(
            account="account",
            authenticator="WORKLOAD_IDENTITY",
        )
    assert (
        "workload_identity_provider must be set to one of AWS,AZURE,GCP,OIDC when authenticator is WORKLOAD_IDENTITY."
        in str(excinfo.value)
    )
    # Ensure no network requests were made
    mock_post_request.assert_not_called()


@mock.patch("snowflake.connector.network.SnowflakeRestful._post_request")
def test_wif_authenticator_with_invalid_provider_raises_error(mock_post_request):
    from snowflake.connector import connect

    with pytest.raises(ProgrammingError) as excinfo:
        connect(
            account="account",
            authenticator="WORKLOAD_IDENTITY",
            workload_identity_provider="INVALID",
        )
    assert (
        "Unknown workload_identity_provider: 'INVALID'. Expected one of: AWS, AZURE, GCP, OIDC"
        in str(excinfo.value)
    )
    # Ensure no network requests were made
    mock_post_request.assert_not_called()


@mock.patch("snowflake.connector.network.SnowflakeRestful._post_request")
@pytest.mark.parametrize("authenticator", ["WORKLOAD_IDENTITY", "workload_identity"])
def test_wif_authenticator_is_case_insensitive(
    mock_post_request, fake_aws_environment, authenticator
):
    """Test that connect() with workload_identity authenticator creates AuthByWorkloadIdentity instance."""
    from snowflake.connector import connect

    # Mock the post request to prevent actual authentication attempt
    mock_post_request.return_value = {
        "success": True,
        "data": {
            "token": "fake-token",
            "masterToken": "fake-master-token",
            "sessionId": "fake-session-id",
        },
    }

    connection = connect(
        account="testaccount",
        authenticator=authenticator,
        workload_identity_provider="AWS",
    )

    # Verify that the auth instance is of the correct type
    assert isinstance(connection.auth_class, AuthByWorkloadIdentity)


# -- OIDC Tests --


def test_explicit_oidc_valid_inline_token_plumbed_to_api():
    dummy_token = gen_dummy_id_token(sub="service-1", iss="issuer-1")
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.OIDC, token=dummy_token
    )
    auth_class.prepare(conn=None)

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "OIDC",
        "TOKEN": dummy_token,
    }


def test_explicit_oidc_valid_inline_token_generates_unique_assertion_content():
    dummy_token = gen_dummy_id_token(sub="service-1", iss="issuer-1")
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.OIDC, token=dummy_token
    )
    auth_class.prepare(conn=None)
    assert (
        auth_class.assertion_content
        == '{"_provider":"OIDC","iss":"issuer-1","sub":"service-1"}'
    )


def test_explicit_oidc_invalid_inline_token_raises_error():
    invalid_token = "not-a-jwt"
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.OIDC, token=invalid_token
    )
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare(conn=None)
    assert "Invalid JWT token: " in str(excinfo.value)


def test_explicit_oidc_no_token_raises_error():
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.OIDC, token=None)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare(conn=None)
    assert "token must be provided if workload_identity_provider=OIDC" in str(
        excinfo.value
    )


# -- AWS Tests --


def test_explicit_aws_no_auth_raises_error(fake_aws_environment: FakeAwsEnvironment):
    fake_aws_environment.credentials = None

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare(conn=None)
    assert "No AWS credentials were found" in str(excinfo.value)


def test_explicit_aws_encodes_audience_host_signature_to_api(
    fake_aws_environment: FakeAwsEnvironment,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    auth_class.prepare(conn=None)

    data = extract_api_data(auth_class)
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
def test_explicit_aws_uses_regional_hostnames(
    fake_aws_environment: FakeAwsEnvironment, region: str, expected_hostname: str
):
    fake_aws_environment.region = region

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    auth_class.prepare(conn=None)

    data = extract_api_data(auth_class)
    decoded_token = json.loads(b64decode(data["TOKEN"]))
    hostname_from_url = urlparse(decoded_token["url"]).hostname
    hostname_from_header = decoded_token["headers"]["Host"]

    assert expected_hostname == hostname_from_url
    assert expected_hostname == hostname_from_header


def test_explicit_aws_generates_unique_assertion_content(
    fake_aws_environment: FakeAwsEnvironment,
):
    fake_aws_environment.region = "us-east-1"
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    auth_class.prepare(conn=None)

    assert (
        '{"_provider":"AWS","partition":"aws","region":"us-east-1"}'
        == auth_class.assertion_content
    )


@pytest.mark.parametrize(
    "region, partition, expected_hostname",
    [
        # AWS partition
        ("us-east-1", "aws", "sts.us-east-1.amazonaws.com"),
        ("eu-west-2", "aws", "sts.eu-west-2.amazonaws.com"),
        ("ap-southeast-1", "aws", "sts.ap-southeast-1.amazonaws.com"),
        (
            "us-east-1",
            "aws",
            "sts.us-east-1.amazonaws.com",
        ),  # Redundant but good for coverage
        # AWS China partition
        ("cn-north-1", "aws-cn", "sts.cn-north-1.amazonaws.com.cn"),
        ("cn-northwest-1", "aws-cn", "sts.cn-northwest-1.amazonaws.com.cn"),
        # AWS GovCloud partition
        ("us-gov-west-1", "aws-us-gov", "sts.us-gov-west-1.amazonaws.com"),
        ("us-gov-east-1", "aws-us-gov", "sts.us-gov-east-1.amazonaws.com"),
    ],
)
def test_get_aws_sts_hostname_valid_inputs(region, partition, expected_hostname):
    assert get_aws_sts_hostname(region, partition) == expected_hostname


@pytest.mark.parametrize(
    "region, partition",
    [
        ("us-east-1", "unknown-partition"),  # Unknown partition
        ("some-region", "invalid-partition"),  # Invalid partition
        ("us-east-1", None),  # None partition
        ("us-east-1", 456),  # Non-string partition
        ("", ""),  # Empty region and partition
        ("us-east-1", ""),  # Empty partition
    ],
)
def test_get_aws_sts_hostname_invalid_inputs(region, partition):
    with pytest.raises(ProgrammingError) as excinfo:
        get_aws_sts_hostname(region, partition)
    assert "Invalid AWS partition" in str(excinfo.value)


def test_aws_impersonation_calls_correct_apis_for_each_role_in_impersonation_path(
    fake_aws_environment: FakeAwsEnvironment,
):
    impersonation_path = [
        "arn:aws:iam::123456789:role/role2",
        "arn:aws:iam::123456789:role/role3",
    ]
    fake_aws_environment.assumption_path = impersonation_path
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.AWS, impersonation_path=impersonation_path
    )
    auth_class.prepare(conn=None)

    assert fake_aws_environment.assume_role_call_count == 2


# -- GCP Tests --


@pytest.mark.parametrize(
    "exception",
    [
        HTTPError(),
        Timeout(),
        ConnectTimeout(),
    ],
)
def test_explicit_gcp_metadata_server_error_bubbles_up(exception):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)
    with mock.patch(
        "snowflake.connector.vendored.requests.sessions.Session.request",
        side_effect=exception,
    ):
        with pytest.raises(ProgrammingError) as excinfo:
            auth_class.prepare(conn=None)

    assert "Error fetching GCP identity token:" in str(excinfo.value)
    assert "Ensure the application is running on GCP." in str(excinfo.value)


def test_explicit_gcp_plumbs_token_to_api(
    fake_gce_metadata_service: FakeGceMetadataService,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)
    auth_class.prepare(conn=None)

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "GCP",
        "TOKEN": fake_gce_metadata_service.token,
    }


def test_explicit_gcp_generates_unique_assertion_content(
    fake_gce_metadata_service: FakeGceMetadataService,
):
    fake_gce_metadata_service.sub = "123456"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)
    auth_class.prepare(conn=None)

    assert auth_class.assertion_content == '{"_provider":"GCP","sub":"123456"}'


@mock.patch("snowflake.connector.session_manager.SessionManager.post")
def test_gcp_calls_correct_apis_and_populates_auth_data_for_final_sa(
    mock_post_request, fake_gce_metadata_service: FakeGceMetadataService
):
    fake_gce_metadata_service.sub = "sa1"
    impersonation_path = ["sa2", "sa3"]
    sa1_access_token = gen_dummy_access_token("sa1")
    sa3_id_token = gen_dummy_id_token("sa3")

    mock_post_request.return_value = build_response(
        json.dumps({"token": sa3_id_token}).encode("utf-8")
    )

    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.GCP, impersonation_path=impersonation_path
    )
    auth_class.prepare(conn=None)

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
    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "GCP",
        "TOKEN": sa3_id_token,
    }


# -- Azure Tests --


@pytest.mark.parametrize(
    "exception",
    [
        HTTPError(),
        Timeout(),
        ConnectTimeout(),
    ],
)
def test_explicit_azure_metadata_server_error_bubbles_up(exception):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    with mock.patch(
        "snowflake.connector.vendored.requests.sessions.Session.request",
        side_effect=exception,
    ):
        with pytest.raises(ProgrammingError) as excinfo:
            auth_class.prepare(conn=None)
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
def test_explicit_azure_v1_and_v2_issuers_accepted(fake_azure_metadata_service, issuer):
    fake_azure_metadata_service.iss = issuer

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    auth_class.prepare(conn=None)

    assert issuer == json.loads(auth_class.assertion_content)["iss"]


def test_explicit_azure_plumbs_token_to_api(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    auth_class.prepare(conn=None)

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "AZURE",
        "TOKEN": fake_azure_metadata_service.token,
    }


def test_explicit_azure_generates_unique_assertion_content(fake_azure_metadata_service):
    fake_azure_metadata_service.iss = (
        "https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd"
    )
    fake_azure_metadata_service.sub = "611ab25b-2e81-4e18-92a7-b21f2bebb269"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    auth_class.prepare(conn=None)

    assert (
        '{"_provider":"AZURE","iss":"https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd","sub":"611ab25b-2e81-4e18-92a7-b21f2bebb269"}'
        == auth_class.assertion_content
    )


def test_explicit_azure_uses_default_entra_resource_if_unspecified(
    fake_azure_metadata_service,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    auth_class.prepare(conn=None)

    token = fake_azure_metadata_service.token
    parsed = jwt.decode(token, options={"verify_signature": False})
    assert (
        parsed["aud"] == "api://fd3f753b-eed3-462c-b6a7-a4b5bb650aad"
    )  # the default entra resource defined in wif_util.py.


def test_explicit_azure_uses_explicit_entra_resource(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.AZURE, entra_resource="api://non-standard"
    )
    auth_class.prepare(conn=None)

    token = fake_azure_metadata_service.token
    parsed = jwt.decode(token, options={"verify_signature": False})
    assert parsed["aud"] == "api://non-standard"


def test_explicit_azure_omits_client_id_if_not_set(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    auth_class.prepare(conn=None)
    assert fake_azure_metadata_service.requested_client_id is None


def test_explicit_azure_uses_explicit_client_id_if_set(
    fake_azure_metadata_service, monkeypatch
):
    monkeypatch.setenv("MANAGED_IDENTITY_CLIENT_ID", "custom-client-id")
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    auth_class.prepare(conn=None)

    assert fake_azure_metadata_service.requested_client_id == "custom-client-id"
