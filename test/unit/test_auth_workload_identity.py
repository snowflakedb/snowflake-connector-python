#
# Copyright (c) 2012-2025 Snowflake Computing Inc. All rights reserved.
#

from base64 import b64decode
from unittest import mock
import datetime
import json
import jwt
from time import time
import pytest
from urllib.parse import urlparse, parse_qs

from snowflake.connector.auth import AuthByWorkloadIdentity
from snowflake.connector.errors import ProgrammingError
from snowflake.connector.wif_util import AttestationProvider

from botocore.credentials import Credentials
from botocore.awsrequest import AWSRequest

from snowflake.connector.vendored.requests.models import Response
from snowflake.connector.vendored.requests.exceptions import HTTPError, Timeout, ConnectTimeout


DUMMY_AWS_ARN = "arn:aws:sts::376129840140:assumed-role/Outgoing-EC2-Role/i-08b76420b06af883c"
DUMMY_AWS_REGION = "us-east-1"


def gen_dummy_id_token(sub = "test-subject", iss = "test-issuer") -> str:
    """Generates a dummy ID token using the given subject and issuer."""
    now = int(time())
    key = "secret"
    return jwt.encode(
        payload={
            "sub": sub,
            "iss": iss,
            "aud": "snowflakecomputing.com",
            "iat": now,
            "exp": now + 60 * 60,
        },
        key=key,
        algorithm="HS256",
    )


def extract_api_data(auth_class: AuthByWorkloadIdentity):
    """Extracts the 'data' portion of the request body populated by the given auth class."""
    req_body = {"data": {}}
    auth_class.update_body(req_body)
    return req_body["data"]


def fake_sign_aws_req(request: AWSRequest):
    """Produces a fake Sigv4 signature on an AWS request."""
    request.headers.add_header("X-Amz-Date", datetime.time().isoformat())
    request.headers.add_header("X-Amz-Security-Token", "<TOKEN>")
    request.headers.add_header(
        "Authorization",
        f"AWS4-HMAC-SHA256 Credential=<cred>, SignedHeaders={';'.join(request.headers.keys())}, Signature=<sig>"
    )


@pytest.fixture
def fake_aws_imds():
    with mock.patch("boto3.session.Session.get_credentials", return_value=Credentials(access_key="ak", secret_key="sk")):
        with mock.patch("botocore.auth.SigV4Auth.add_auth", side_effect=fake_sign_aws_req):
            with mock.patch("snowflake.connector.wif_util.get_aws_region", return_value=DUMMY_AWS_REGION):
                with mock.patch("snowflake.connector.wif_util.get_aws_arn", return_value=DUMMY_AWS_ARN):
                    yield


def verify_aws_token(token: str):
    """Performs some basic checks on a 'token' produced for AWS, to ensure it includes the expected fields."""
    decoded_token = json.loads(b64decode(token))
    assert "Action=GetCallerIdentity" in decoded_token["url"]
    assert decoded_token["method"] == "POST"
    
    headers = decoded_token["headers"]
    assert set(headers.keys()) == set(["Host", "X-Snowflake-Audience", "X-Amz-Date", "X-Amz-Security-Token", "Authorization"])
    assert headers["X-Snowflake-Audience"] == "snowflakecomputing.com"


def fake_response_string(content: str) -> Response:
    """Builds a requests.Response where the HTTP response content is the given string."""
    resp = Response()
    resp.status_code = 200
    resp._content = content.encode("utf-8")
    return resp


def fake_response_json(fields: dict) -> Response:
    """Builds a requests.Response where the HTTP response content is JSON based on the given dictionary."""
    resp = Response()
    resp.status_code = 200
    resp._content = json.dumps(fields).encode("utf-8")
    return resp


def is_azure_metadata_req(method: str, url: str, headers: dict) -> bool:
    """Checks whether the given request is targeted to the Azure metadata service."""
    return method == "GET" and url.startswith("http://169.254.169.254/metadata/identity/oauth2/token") and headers.get("Metadata") == "True"


def is_gcp_metadata_req(method: str, url: str, headers: dict) -> bool:
    """Checks whether the given request is targeted to the GCP metadata service."""
    return method == "GET" and url.startswith("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity") and headers.get("Metadata-Flavor") == "Google"


# -- OIDC Tests --


def test_explicit_oidc_valid_inline_token_plumbed_to_api():
    dummy_token = gen_dummy_id_token(sub="service-1", iss="issuer-1")
    auth_class = AuthByWorkloadIdentity(AttestationProvider.OIDC, dummy_token)
    auth_class.prepare()

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "OIDC",
        "TOKEN": dummy_token,
    }


def test_explicit_oidc_valid_inline_token_generates_unique_assertion_content():
    dummy_token = gen_dummy_id_token(sub="service-1", iss="issuer-1")
    auth_class = AuthByWorkloadIdentity(AttestationProvider.OIDC, dummy_token)
    auth_class.prepare()
    assert auth_class.assertion_content == '{"_provider":"OIDC","iss":"issuer-1","sub":"service-1"}'


def test_explicit_oidc_invalid_inline_token_raises_error():
    invalid_token = 'not-a-jwt'
    auth_class = AuthByWorkloadIdentity(AttestationProvider.OIDC, invalid_token)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "token is not a valid JWT" in str(excinfo.value)


def test_explicit_oidc_no_token_raises_error():
    auth_class = AuthByWorkloadIdentity(AttestationProvider.OIDC, token=None)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "No workload identity credential was found for 'OIDC'" in str(excinfo.value)


# -- AWS Tests --


@mock.patch("boto3.session.Session.get_credentials", return_value=None)
def test_explicit_aws_no_auth_raises_error(_):
    auth_class = AuthByWorkloadIdentity(AttestationProvider.AWS)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "No workload identity credential was found for 'AWS'" in str(excinfo.value)


def test_explicit_aws_encodes_audience_host_signature_to_api(fake_aws_imds):
    auth_class = AuthByWorkloadIdentity(AttestationProvider.AWS)
    auth_class.prepare()

    data = extract_api_data(auth_class)
    assert data["AUTHENTICATOR"] == "WORKLOAD_IDENTITY"
    assert data["PROVIDER"] == "AWS"
    verify_aws_token(data["TOKEN"])


def test_explicit_aws_uses_regional_hostname(fake_aws_imds):
    auth_class = AuthByWorkloadIdentity(AttestationProvider.AWS)
    auth_class.prepare()

    data = extract_api_data(auth_class)
    decoded_token = json.loads(b64decode(data["TOKEN"]))
    hostname_in_url = urlparse(decoded_token["url"]).hostname
    hostname_in_header = decoded_token["headers"]["Host"]

    expected_hostname = f"sts.{DUMMY_AWS_REGION}.amazonaws.com"
    assert expected_hostname == hostname_in_url
    assert expected_hostname == hostname_in_header


def test_explicit_aws_generates_unique_assertion_content(fake_aws_imds):
    auth_class = AuthByWorkloadIdentity(AttestationProvider.AWS)
    auth_class.prepare()

    expected_assertion_content = '{"_provider":"AWS","arn":"%s"}' % DUMMY_AWS_ARN
    assert expected_assertion_content == auth_class.assertion_content


# -- GCP Tests --


@pytest.mark.parametrize("exception", [
    HTTPError(),
    Timeout(),
    ConnectTimeout(),
])
def test_explicit_gcp_metadata_server_error_raises_auth_error(exception):
    auth_class = AuthByWorkloadIdentity(AttestationProvider.GCP)
    with mock.patch("snowflake.connector.vendored.requests.request", side_effect=exception):
        with pytest.raises(ProgrammingError) as excinfo:
            auth_class.prepare()
        assert "No workload identity credential was found for 'GCP'" in str(excinfo.value)


@mock.patch("snowflake.connector.vendored.requests.request", return_value=fake_response_string(gen_dummy_id_token(iss="not-google")))
def test_explicit_gcp_wrong_issuer_raises_error(_):
    auth_class = AuthByWorkloadIdentity(AttestationProvider.GCP)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "No workload identity credential was found for 'GCP'" in str(excinfo.value)


def test_explicit_gcp_plumbs_token_to_api():
    dummy_token = gen_dummy_id_token(sub="123456", iss="https://accounts.google.com")
    with mock.patch("snowflake.connector.vendored.requests.request", return_value=fake_response_string(dummy_token)):
        auth_class = AuthByWorkloadIdentity(AttestationProvider.GCP)
        auth_class.prepare()

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "GCP",
        "TOKEN": dummy_token,
    }


def test_explicit_gcp_generates_unique_assertion_content():
    dummy_token = gen_dummy_id_token(sub="123456", iss="https://accounts.google.com")
    with mock.patch("snowflake.connector.vendored.requests.request", return_value=fake_response_string(dummy_token)):
        auth_class = AuthByWorkloadIdentity(AttestationProvider.GCP)
        auth_class.prepare()

    assert auth_class.assertion_content == '{"_provider":"GCP","sub":"123456"}'


# -- Azure Tests --


@pytest.mark.parametrize("exception", [
    HTTPError(),
    Timeout(),
    ConnectTimeout(),
])
def test_explicit_azure_metadata_server_error_raises_auth_error(exception):
    auth_class = AuthByWorkloadIdentity(AttestationProvider.AZURE)
    with mock.patch("snowflake.connector.vendored.requests.request", side_effect=exception):
        with pytest.raises(ProgrammingError) as excinfo:
            auth_class.prepare()
        assert "No workload identity credential was found for 'AZURE'" in str(excinfo.value)


@mock.patch("snowflake.connector.vendored.requests.request", return_value=fake_response_json({"access_token": gen_dummy_id_token(iss="not-azure")}))
def test_explicit_azure_wrong_issuer_raises_error(_):
    auth_class = AuthByWorkloadIdentity(AttestationProvider.AZURE)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "No workload identity credential was found for 'AZURE'" in str(excinfo.value)


def test_explicit_azure_plumbs_token_to_api():
    dummy_token = gen_dummy_id_token(sub="611ab25b-2e81-4e18-92a7-b21f2bebb269", iss="https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd")
    with mock.patch("snowflake.connector.vendored.requests.request", return_value=fake_response_json({"access_token": dummy_token})):
        auth_class = AuthByWorkloadIdentity(AttestationProvider.AZURE)
        auth_class.prepare()

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "AZURE",
        "TOKEN": dummy_token,
    }


def test_explicit_azure_generates_unique_assertion_content():
    dummy_token = gen_dummy_id_token(sub="611ab25b-2e81-4e18-92a7-b21f2bebb269", iss="https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd")
    with mock.patch("snowflake.connector.vendored.requests.request", return_value=fake_response_json({"access_token": dummy_token})):
        auth_class = AuthByWorkloadIdentity(AttestationProvider.AZURE)
        auth_class.prepare()

    assert auth_class.assertion_content == '{"_provider":"AZURE","iss":"https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd","sub":"611ab25b-2e81-4e18-92a7-b21f2bebb269"}'


def test_explicit_azure_uses_default_entra_resource_if_unspecified():
    dummy_token = gen_dummy_id_token(sub="611ab25b-2e81-4e18-92a7-b21f2bebb269", iss="https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd")
    with mock.patch("snowflake.connector.vendored.requests.request", return_value=fake_response_json({"access_token": dummy_token})) as mock_request:
        auth_class = AuthByWorkloadIdentity(AttestationProvider.AZURE)
        auth_class.prepare()

        _, request_kwargs = mock_request.call_args
        url = urlparse(request_kwargs["url"])
        query_string = parse_qs(url.query)
        assert query_string.get("resource")[0] == "api://snowflakecomputing.com"  # the default entra resource defined in wif_util.py.


def test_explicit_azure_uses_explicit_entra_resource():
    dummy_token = gen_dummy_id_token(sub="611ab25b-2e81-4e18-92a7-b21f2bebb269", iss="https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd")
    with mock.patch("snowflake.connector.vendored.requests.request", return_value=fake_response_json({"access_token": dummy_token})) as mock_request:
        auth_class = AuthByWorkloadIdentity(AttestationProvider.AZURE, entra_resource="api://non-standard")
        auth_class.prepare()

        _, request_kwargs = mock_request.call_args
        url = urlparse(request_kwargs["url"])
        query_string = parse_qs(url.query)
        assert query_string.get("resource")[0] == "api://non-standard"


# -- Auto-detect Tests --


@mock.patch("snowflake.connector.vendored.requests.request", side_effect=ConnectTimeout())
def test_autodetect_aws_present(mock_metadata_request, fake_aws_imds):
    auth_class = AuthByWorkloadIdentity(provider=None)
    auth_class.prepare()

    data = extract_api_data(auth_class)
    assert data["AUTHENTICATOR"] == "WORKLOAD_IDENTITY"
    assert data["PROVIDER"] == "AWS"
    verify_aws_token(data["TOKEN"])


@mock.patch("boto3.session.Session.get_credentials", return_value=None)
def test_autodetect_gcp_present(_):
    dummy_token = gen_dummy_id_token(sub="12345", iss="https://accounts.google.com")
    def gcp_metadata_server(method, url, headers, timeout):
        if is_gcp_metadata_req(method, url, headers):
            return fake_response_string(dummy_token)
        raise ConnectTimeout()

    with mock.patch("snowflake.connector.vendored.requests.request", side_effect=gcp_metadata_server):
        auth_class = AuthByWorkloadIdentity(provider=None)
        auth_class.prepare()

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "GCP",
        "TOKEN": dummy_token,
    }


@mock.patch("boto3.session.Session.get_credentials", return_value=None)
def test_autodetect_azure_present(_):
    dummy_token = gen_dummy_id_token(sub="611ab25b-2e81-4e18-92a7-b21f2bebb269", iss="https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd")
    def azure_metadata_server(method, url, headers, timeout):
        if is_azure_metadata_req(method, url, headers):
            return fake_response_json({"access_token": dummy_token})
        raise ConnectTimeout()

    with mock.patch("snowflake.connector.vendored.requests.request", side_effect=azure_metadata_server):
        auth_class = AuthByWorkloadIdentity(provider=None)
        auth_class.prepare()

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "AZURE",
        "TOKEN": dummy_token,
    }


@mock.patch("boto3.session.Session.get_credentials", return_value=None)
@mock.patch("snowflake.connector.vendored.requests.request", side_effect=ConnectTimeout())
def test_autodetect_oidc_present(mock_metadata_request, mock_get_creds):
    dummy_token = gen_dummy_id_token(sub="service-1", iss="issuer-1")
    auth_class = AuthByWorkloadIdentity(provider=None, token=dummy_token)
    auth_class.prepare()

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "OIDC",
        "TOKEN": dummy_token,
    }


@mock.patch("boto3.session.Session.get_credentials", return_value=None)
@mock.patch("snowflake.connector.vendored.requests.request", side_effect=ConnectTimeout())
def test_autodetect_no_provider_raises_error(mock_metadata_request, mock_get_creds):
    auth_class = AuthByWorkloadIdentity(provider=None, token=None)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "No workload identity credential was found for 'auto-detect" in str(excinfo.value)
