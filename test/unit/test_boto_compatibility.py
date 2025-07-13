from __future__ import annotations

import datetime
import urllib.parse as urlparse

import pytest
from botocore import session as boto_session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from snowflake.connector import _aws_credentials
from snowflake.connector._aws_sign_v4 import sign_get_caller_identity
from snowflake.connector.wif_util import _sts_host_from_region


def _normalise_headers(headers: dict[str, str]) -> dict[str, str]:
    """Lower-case keys, trim values, drop User-Agent (botocore adds it)."""
    return {
        k.lower(): v.strip() for k, v in headers.items() if k.lower() != "user-agent"
    }


@pytest.fixture
def freeze_utcnow(monkeypatch: pytest.MonkeyPatch):
    """Freeze `datetime.datetime.utcnow()` for deterministic SigV4 signatures."""
    fixed = datetime.datetime(2025, 1, 1, 0, 0, 0)

    class _FrozenDateTime(datetime.datetime):
        @classmethod
        def utcnow(cls):  # type: ignore[override]
            return fixed

    monkeypatch.setattr(datetime, "datetime", _FrozenDateTime)
    yield


@pytest.mark.parametrize("region", ["us-east-1", "eu-west-1", "us-gov-west-1"])
def test_sigv4_parity_with_botocore(region: str, freeze_utcnow):
    url = (
        f"https://{_sts_host_from_region(region)}"
        "/?Action=GetCallerIdentity&Version=2011-06-15"
    )

    access_key_id = "AKIDEXAMPLE"
    secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

    sf_driver_aws_headers = sign_get_caller_identity(
        url=url,
        region=region,
        access_key=access_key_id,
        secret_key=secret_access_key,
    )

    boto_req = AWSRequest(
        method="POST",
        url=url,
        headers={
            "Host": sf_driver_aws_headers["host"],
            "X-Snowflake-Audience": "snowflakecomputing.com",
            "X-Amz-Date": datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"),
        },
    )
    SigV4Auth(Credentials(access_key_id, secret_access_key), "sts", region).add_auth(
        boto_req
    )

    assert "authorization" in sf_driver_aws_headers
    assert _normalise_headers(sf_driver_aws_headers) == _normalise_headers(
        boto_req.headers
    )


@pytest.mark.parametrize("region", ["us-east-1", "eu-west-1", "us-gov-west-1"])
def test_sigv4_parity_with_session_token(region: str, freeze_utcnow):
    url = (
        f"https://{_sts_host_from_region(region)}"
        "/?Action=GetCallerIdentity&Version=2011-06-15"
    )

    access_key_id = "AKIDEXAMPLE"
    secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    session_token = "IQoJb3JpZ2luX2VjEPr//////////wEaCXVzLWFz"

    sf_driver_aws_headers = sign_get_caller_identity(
        url=url,
        region=region,
        access_key=access_key_id,
        secret_key=secret_access_key,
        session_token=session_token,
    )

    boto_req = AWSRequest(
        method="POST",
        url=url,
        headers={
            "Host": sf_driver_aws_headers["host"],
            "X-Snowflake-Audience": "snowflakecomputing.com",
            "X-Amz-Date": sf_driver_aws_headers["x-amz-date"],
            "X-Amz-Security-Token": session_token,
        },
    )
    SigV4Auth(
        Credentials(access_key_id, secret_access_key, token=session_token),
        "sts",
        region,
    ).add_auth(boto_req)

    assert _normalise_headers(sf_driver_aws_headers) == _normalise_headers(
        boto_req.headers
    )


@pytest.mark.parametrize(
    "region", ["us-east-1", "eu-west-1", "us-gov-west-1", "cn-north-1"]
)
def test_sts_host_from_region_matches_botocore(
    monkeypatch: pytest.MonkeyPatch, region: str
):
    sf_host = _sts_host_from_region(region)

    # Force botocore into **regional** mode so that it doesn’t fall back to the
    # legacy global host (sts.amazonaws.com) for the particular regions (like us-east-1).
    # Both approaches work correctly.
    monkeypatch.setenv("AWS_STS_REGIONAL_ENDPOINTS", "regional")

    boto_host = urlparse.urlparse(
        boto_session.Session()
        .create_client(
            "sts", region_name=region, aws_access_key_id="x", aws_secret_access_key="y"
        )
        .meta.endpoint_url
    ).netloc.lower()

    assert sf_host == boto_host


def test_region_env_var_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Both libraries should resolve the region from AWS_DEFAULT_REGION
    without any extra hints.
    """
    expected_region = "ap-southeast-2"
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.setenv("AWS_DEFAULT_REGION", expected_region)

    # Driver
    sf_region = _aws_credentials.get_region()
    assert sf_region == expected_region

    # Botocore
    boto_region = (
        boto_session.Session()
        .create_client("s3", aws_access_key_id="x", aws_secret_access_key="y")
        .meta.region_name
    )
    assert boto_region == sf_region


def test_region_env_var_legacy(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    AWS_REGION is *ignored* by botocore currently, but should be introduced in the future: https://docs.aws.amazon.com/sdkref/latest/guide/feature-region.html
    Therefore for now we set it as env_var for the driver and pass via explicit parameter to botocore.
    """
    desired_region = "ca-central-1"
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.setenv("AWS_REGION", desired_region)

    # Snowflake helper sees AWS_REGION
    sf_region = _aws_credentials.get_region()
    assert sf_region == desired_region

    # botocore needs an explicit region_name when AWS_REGION is set
    boto_region = (
        boto_session.Session()
        .create_client(
            "s3",
            region_name=desired_region,
            aws_access_key_id="x",
            aws_secret_access_key="y",
        )
        .meta.region_name
    )
    assert boto_region == desired_region
