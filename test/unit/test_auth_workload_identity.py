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
from snowflake.connector.wif_util import (
    AZURE_ISSUER_PREFIXES,
    AttestationProvider,
    _partition_from_region,
    _sts_host_from_region,
)

from ..csp_helpers import FakeAwsEnvironment, FakeGceMetadataService, gen_dummy_id_token

logger = logging.getLogger(__name__)


def extract_api_data(auth_class: AuthByWorkloadIdentity):
    """Extracts the 'data' portion of the request body populated by the given auth class."""
    req_body = {"data": {}}
    auth_class.update_body(req_body)
    return req_body["data"]


def verify_aws_token(token: str, region: str):
    """Accepts both SigV4 variants (with / without session token)."""
    decoded_payload = json.loads(b64decode(token))

    # URL validation
    sts_request_url = urlparse(decoded_payload["url"])
    assert sts_request_url.scheme == "https"
    assert sts_request_url.hostname == f"sts.{region}.amazonaws.com"

    query_params = parse_qs(sts_request_url.query)
    assert query_params["Action"][0] == "GetCallerIdentity"
    assert query_params["Version"][0] == "2011-06-15"

    # Method validation
    assert decoded_payload["method"] == "POST"

    # Header validation
    headers = {k.lower(): v for k, v in decoded_payload["headers"].items()}

    mandatory_headers = {
        "host",
        "x-snowflake-audience",
        "x-amz-date",
        "authorization",
    }
    optional_headers = {"x-amz-security-token"}

    assert mandatory_headers.issubset(headers)
    assert set(headers).issubset(mandatory_headers | optional_headers)
    assert headers["host"] == f"sts.{region}.amazonaws.com"
    assert headers["x-snowflake-audience"] == "snowflakecomputing.com"


# -- OIDC Tests --


def test_explicit_oidc_valid_inline_token_plumbed_to_api():
    dummy_token = gen_dummy_id_token(sub="service-1", iss="issuer-1")
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.OIDC, token=dummy_token
    )
    auth_class.prepare()

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
    auth_class.prepare()
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
        auth_class.prepare()
    assert "No workload identity credential was found for 'OIDC'" in str(excinfo.value)


def test_explicit_oidc_no_token_raises_error():
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.OIDC, token=None)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "No workload identity credential was found for 'OIDC'" in str(excinfo.value)


# -- AWS Tests --


def test_explicit_aws_no_auth_raises_error(
    malformed_aws_environment: FakeAwsEnvironment,
):
    malformed_aws_environment.credentials = None

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "No workload identity credential was found for 'AWS'" in str(excinfo.value)


def test_explicit_aws_encodes_audience_host_signature_to_api(
    fake_aws_environment: FakeAwsEnvironment,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    auth_class.prepare()

    data = extract_api_data(auth_class)
    assert data["AUTHENTICATOR"] == "WORKLOAD_IDENTITY"
    assert data["PROVIDER"] == "AWS"
    verify_aws_token(data["TOKEN"], fake_aws_environment.region)


def test_explicit_aws_uses_regional_hostname(fake_aws_environment: FakeAwsEnvironment):
    fake_aws_environment.region = "antarctica-northeast-3"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    auth_class.prepare()

    data = extract_api_data(auth_class)
    decoded_token = json.loads(b64decode(data["TOKEN"]))
    hostname_from_url = urlparse(decoded_token["url"]).hostname
    hostname_from_header = decoded_token["headers"]["host"]

    expected_hostname = "sts.antarctica-northeast-3.amazonaws.com"
    assert expected_hostname == hostname_from_url
    assert expected_hostname == hostname_from_header


def test_explicit_aws_generates_unique_assertion_content(
    fake_aws_environment: FakeAwsEnvironment,
):
    # Change region to ensure assertion_content updates accordingly.
    fake_aws_environment.region = "antarctica-northeast-3"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    auth_class.prepare()

    expected = '{"_provider":"AWS","region":"' + fake_aws_environment.region + '"}'
    assert auth_class.assertion_content == expected


@pytest.mark.parametrize(
    "arn_env_var",
    [
        "AWS_ROLE_ARN",
        "AWS_EC2_METADATA_ARN",
        "AWS_SESSION_ARN",
    ],
)
def test_explicit_aws_includes_arn_when_env_present(
    fake_aws_environment: FakeAwsEnvironment,
    monkeypatch,
    arn_env_var,
):
    dummy_arn = "arn:aws:sts::123456789012:assumed-role/MyRole/i-abcdef123456"
    monkeypatch.setenv(arn_env_var, dummy_arn)

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    auth_class.prepare()

    # Parse the JSON to ignore ordering.
    assertion_data = json.loads(auth_class.assertion_content)

    assert assertion_data["_provider"] == "AWS"
    assert assertion_data["region"] == fake_aws_environment.region
    assert assertion_data["arn"] == dummy_arn


@pytest.mark.parametrize(
    "region, expected_partition",
    [
        # — happy-path AWS commercial
        ("us-east-1", "aws"),
        ("eu-central-1", "aws"),
        ("ap-south-1", "aws"),
        # — China partitions
        ("cn-north-1", "aws-cn"),
        ("cn-northwest-1", "aws-cn"),
        # — GovCloud partitions
        ("us-gov-west-1", "aws-us-gov"),
        ("us-gov-east-1", "aws-us-gov"),
        # - Weird values also fall back to commercial
        ("invalid-region", "aws"),
        ("", "aws"),
    ],
)
def test_partition_from_region(region, expected_partition):
    assert _partition_from_region(region).value == expected_partition


@pytest.mark.parametrize(
    "region, expected_hostname",
    [
        # commercial partition
        ("us-east-1", "sts.us-east-1.amazonaws.com"),
        ("eu-west-2", "sts.eu-west-2.amazonaws.com"),
        # China
        ("cn-north-1", "sts.cn-north-1.amazonaws.com.cn"),
        # GovCloud
        ("us-gov-east-1", "sts.us-gov-east-1.amazonaws.com"),
        # unknown but syntactically valid - still formatted
        ("invalid-region", "sts.invalid-region.amazonaws.com"),
        ("", None),
        (None, None),
        (123, None),
    ],
)
def test_sts_host_from_region_valid_inputs(region, expected_hostname):
    assert _sts_host_from_region(region) == expected_hostname


# -- GCP Tests --


@pytest.mark.parametrize(
    "exception",
    [
        HTTPError(),
        Timeout(),
        ConnectTimeout(),
    ],
)
def test_explicit_gcp_metadata_server_error_raises_auth_error(exception):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)
    with mock.patch(
        "snowflake.connector.vendored.requests.request", side_effect=exception
    ):
        with pytest.raises(ProgrammingError) as excinfo:
            auth_class.prepare()
        assert "No workload identity credential was found for 'GCP'" in str(
            excinfo.value
        )


def test_explicit_gcp_wrong_issuer_raises_error(
    fake_gce_metadata_service: FakeGceMetadataService,
):
    fake_gce_metadata_service.iss = "not-google"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "No workload identity credential was found for 'GCP'" in str(excinfo.value)


def test_explicit_gcp_plumbs_token_to_api(
    fake_gce_metadata_service: FakeGceMetadataService,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.GCP)
    auth_class.prepare()

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
    auth_class.prepare()

    assert auth_class.assertion_content == '{"_provider":"GCP","sub":"123456"}'


# -- Azure Tests --


@pytest.mark.parametrize(
    "exception",
    [
        HTTPError(),
        Timeout(),
        ConnectTimeout(),
    ],
)
def test_explicit_azure_metadata_server_error_raises_auth_error(exception):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    with mock.patch(
        "snowflake.connector.vendored.requests.request", side_effect=exception
    ):
        with pytest.raises(ProgrammingError) as excinfo:
            auth_class.prepare()
        assert "No workload identity credential was found for 'AZURE'" in str(
            excinfo.value
        )


def test_explicit_azure_wrong_issuer_raises_error(fake_azure_metadata_service):
    fake_azure_metadata_service.iss = "https://notazure.com"

    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "No workload identity credential was found for 'AZURE'" in str(excinfo.value)


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
    auth_class.prepare()

    assert issuer == json.loads(auth_class.assertion_content)["iss"]


def test_explicit_azure_plumbs_token_to_api(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    auth_class.prepare()

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
    auth_class.prepare()

    assert (
        '{"_provider":"AZURE","iss":"https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd","sub":"611ab25b-2e81-4e18-92a7-b21f2bebb269"}'
        == auth_class.assertion_content
    )


def test_explicit_azure_uses_default_entra_resource_if_unspecified(
    fake_azure_metadata_service,
):
    auth_class = AuthByWorkloadIdentity(provider=AttestationProvider.AZURE)
    auth_class.prepare()

    token = fake_azure_metadata_service.token
    parsed = jwt.decode(token, options={"verify_signature": False})
    assert (
        parsed["aud"] == "api://fd3f753b-eed3-462c-b6a7-a4b5bb650aad"
    )  # the default entra resource defined in wif_util.py.


def test_explicit_azure_uses_explicit_entra_resource(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(
        provider=AttestationProvider.AZURE, entra_resource="api://non-standard"
    )
    auth_class.prepare()

    token = fake_azure_metadata_service.token
    parsed = jwt.decode(token, options={"verify_signature": False})
    assert parsed["aud"] == "api://non-standard"


@pytest.mark.parametrize(
    "issuer",
    [
        "https://sts.windows.net/067802cd-8f92-4c7c-bceb-ea8f15d31cc5",
        "https://sts.chinacloudapi.cn/067802cd-8f92-4c7c-bceb-ea8f15d31cc5",
        "https://login.microsoftonline.com/067802cd-8f92-4c7c-bceb-ea8f15d31cc5/v2.0",
        "https://login.microsoftonline.us/067802cd-8f92-4c7c-bceb-ea8f15d31cc5/v2.0",
        "https://login.partner.microsoftonline.cn/067802cd-8f92-4c7c-bceb-ea8f15d31cc5/v2.0",
    ],
)
def test_azure_issuer_prefixes(issuer):
    assert any(
        issuer.startswith(issuer_prefix) for issuer_prefix in AZURE_ISSUER_PREFIXES
    )


# -- Auto-detect Tests --


def test_autodetect_aws_present(
    no_metadata_service, fake_aws_environment: FakeAwsEnvironment
):
    auth_class = AuthByWorkloadIdentity(provider=None)
    auth_class.prepare()

    data = extract_api_data(auth_class)
    assert data["AUTHENTICATOR"] == "WORKLOAD_IDENTITY"
    assert data["PROVIDER"] == "AWS"
    verify_aws_token(data["TOKEN"], fake_aws_environment.region)


def test_autodetect_gcp_present(fake_gce_metadata_service: FakeGceMetadataService):
    auth_class = AuthByWorkloadIdentity(provider=None)
    auth_class.prepare()

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "GCP",
        "TOKEN": fake_gce_metadata_service.token,
    }


def test_autodetect_azure_present(fake_azure_metadata_service):
    auth_class = AuthByWorkloadIdentity(provider=None)
    auth_class.prepare()

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "AZURE",
        "TOKEN": fake_azure_metadata_service.token,
    }


def test_autodetect_oidc_present(no_metadata_service):
    dummy_token = gen_dummy_id_token(sub="service-1", iss="issuer-1")
    auth_class = AuthByWorkloadIdentity(provider=None, token=dummy_token)
    auth_class.prepare()

    assert extract_api_data(auth_class) == {
        "AUTHENTICATOR": "WORKLOAD_IDENTITY",
        "PROVIDER": "OIDC",
        "TOKEN": dummy_token,
    }


def test_autodetect_no_provider_raises_error(no_metadata_service):
    auth_class = AuthByWorkloadIdentity(provider=None, token=None)
    with pytest.raises(ProgrammingError) as excinfo:
        auth_class.prepare()
    assert "No workload identity credential was found for 'auto-detect" in str(
        excinfo.value
    )


def test_explicit_aws_region_falls_back_to_imds(imds_only_aws_environment):
    """
    When region env-vars are absent, the connector must discover the region via
    the runtime metadata service (IMDS / task-metadata / lambda env).
    """
    # Advertise a non-default region through the fake metadata service
    imds_only_aws_environment.region = "us-west-2"

    auth = AuthByWorkloadIdentity(provider=AttestationProvider.AWS)
    auth.prepare()

    verify_aws_token(extract_api_data(auth)["TOKEN"], "us-west-2")


def test_autodetect_prefers_gcp_when_no_aws_env(fake_gce_metadata_service):
    """
    No AWS env-vars + a responsive GCP metadata server  -> GCP selected.
    """
    auth_class = AuthByWorkloadIdentity(provider=None)
    auth_class.prepare()

    assert extract_api_data(auth_class)["PROVIDER"] == "GCP"
    assert extract_api_data(auth_class)["TOKEN"] == fake_gce_metadata_service.token
