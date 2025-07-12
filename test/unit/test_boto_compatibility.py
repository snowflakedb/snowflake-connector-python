import urllib.parse as _urlparse

import pytest
from botocore import session as _botocore_session  # type: ignore
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from snowflake.connector import _aws_credentials
from snowflake.connector._aws_sign_v4 import sign_get_caller_identity
from snowflake.connector.wif_util import _sts_host_from_region


@pytest.mark.parametrize(
    "region",
    [
        "us-east-1",
        "eu-west-1",
        "us-gov-west-1",
    ],
)
def test_sign_get_caller_identity_matches_botocore(region):
    """Ensure our lightweight SigV4 signing implementation stays in lock-step with botocore.

    The main reason for this test is to detect any behavioural changes introduced
    by new botocore versions that we might need to replicate in our stripped-down
    implementation. The test uses static credentials and a fixed request template
    (POST GetCallerIdentity) so that both implementations should end up with an
    identical *Authorization* header.
    """
    url = f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"

    access_key = "AKIDEXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

    driver_implementation_headers = sign_get_caller_identity(
        url=url,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
    )

    botocore_request = AWSRequest(
        method="POST",
        url=url,
        headers={
            "Host": f"sts.{region}.amazonaws.com",
            "X-Amz-Date": driver_implementation_headers["x-amz-date"],
            "X-Snowflake-Audience": "snowflakecomputing.com",
        },
    )

    creds = Credentials(access_key, secret_key)
    SigV4Auth(creds, "sts", region).add_auth(botocore_request)

    botocore_headers = {
        k.lower(): v
        for k, v in botocore_request.headers.items()
        if k.lower() != "user-agent"
    }

    driver_implementation_headers_normalized = {
        k.lower(): v for k, v in driver_implementation_headers.items()
    }

    assert (
        driver_implementation_headers_normalized["authorization"]
        == botocore_headers["authorization"]
    )
    assert (
        driver_implementation_headers_normalized["x-amz-date"]
        == botocore_headers["x-amz-date"]
    )
    # All headers our implementation produces must be present in botocore's output.
    assert set(driver_implementation_headers_normalized.keys()).issubset(
        set(botocore_headers.keys())
    )


@pytest.mark.parametrize(
    "region",
    [
        "us-east-1",
        "eu-west-1",
        "us-gov-west-1",
    ],
)
def test_sign_get_caller_identity_with_session_token_matches_botocore(region):
    """SigV4 signing **with** temporary-session credentials must stay bit-for-bit compatible."""

    url = f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"

    access_key = "AKIDEXAMPLE"
    secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    session_token = "IQoJb3JpZ2luX2VjEPr//////////wEaCXVzLWVhc3QtMSJHMEUCIQDO0f6o"

    driver_implementation_headers = sign_get_caller_identity(
        url=url,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
    )

    botocore_request = AWSRequest(
        method="POST",
        url=url,
        headers={
            "Host": f"sts.{region}.amazonaws.com",
            "X-Amz-Date": driver_implementation_headers["x-amz-date"],
            "X-Snowflake-Audience": "snowflakecomputing.com",
            "X-Amz-Security-Token": session_token,
        },
    )

    creds = Credentials(access_key, secret_key, token=session_token)
    SigV4Auth(creds, "sts", region).add_auth(botocore_request)

    botocore_headers = {
        k.lower(): v
        for k, v in botocore_request.headers.items()
        if k.lower() != "user-agent"
    }

    driver_implementation_headers_normalized = {
        k.lower(): v for k, v in driver_implementation_headers.items()
    }

    assert (
        driver_implementation_headers_normalized["authorization"]
        == botocore_headers["authorization"]
    )
    assert (
        driver_implementation_headers_normalized["x-amz-date"]
        == botocore_headers["x-amz-date"]
    )
    assert (
        driver_implementation_headers_normalized["x-amz-security-token"]
        == botocore_headers["x-amz-security-token"]
    )
    assert set(driver_implementation_headers_normalized.keys()).issubset(
        set(botocore_headers.keys())
    )


@pytest.mark.parametrize(
    "region",
    [
        "us-east-1",
        "eu-west-1",
        "us-gov-west-1",
        "cn-north-1",
    ],
)
def test_sts_host_from_region_matches_botocore(region):
    """Ensure we derive the same STS endpoint as botocore."""

    driver_implementation_host = _sts_host_from_region(region)

    session = _botocore_session.Session()
    client = session.create_client(
        "sts",
        region_name=region,
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
    )
    boto_host = _urlparse.urlparse(client.meta.endpoint_url).netloc.lower()

    assert driver_implementation_host == boto_host


@pytest.mark.parametrize("env_var", ["AWS_REGION", "AWS_DEFAULT_REGION"])
def test_get_region_matches_botocore(monkeypatch, env_var):
    """Our region helper should respect the same env-var precedence as botocore."""

    test_region = "ap-southeast-2"

    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.setenv(env_var, test_region)

    driver_region = _aws_credentials.get_region()

    session = _botocore_session.Session()
    s3_client = session.create_client(
        "s3",
        region_name=None,
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
    )
    boto_region = s3_client.meta.region_name

    assert driver_region == boto_region == test_region
