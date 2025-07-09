"""
Lightweight AWS credential resolution without boto3.

This replicates the standard AWS SDK credential chain (environment → container → EC2 IMDSv2).
It purposely returns a `botocore.credentials.Credentials` instance so existing
code that relies on `SigV4Auth` continues to work unchanged while we phase out
boto3 usage incrementally.
"""

from __future__ import annotations

import logging
import os

from .vendored import requests

try:
    from botocore.credentials import Credentials  # type: ignore
except Exception:  # pragma: no cover
    # botocore is still available at this migration stage; if it isn’t we’ll
    # replace it in a later step.
    Credentials = None  # type: ignore

logger = logging.getLogger(__name__)

# Internal constants
_ECS_CREDENTIALS_BASE_URI = "http://169.254.170.2"
_IMDS_BASE_URI = "http://169.254.169.254"


def _credentials_from_env() -> Credentials | None:
    """Load credentials from environment variables."""
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    if access_key and secret_key:
        token = os.getenv("AWS_SESSION_TOKEN")
        return Credentials(access_key, secret_key, token) if Credentials else None
    return None


def _credentials_from_container() -> Credentials | None:
    """Retrieve credentials from ECS / EKS task metadata (IAM Roles for Tasks)."""
    rel_uri = os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    full_uri = os.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    if not rel_uri and not full_uri:
        return None
    creds_url = full_uri or f"{_ECS_CREDENTIALS_BASE_URI}{rel_uri}"
    try:
        res = requests.get(creds_url, timeout=2)
        if res.ok:
            data = res.json()
            return (
                Credentials(
                    data["AccessKeyId"],
                    data["SecretAccessKey"],
                    data.get("Token"),
                )
                if Credentials
                else None
            )
    except Exception as exc:
        logger.debug("Failed to fetch container credentials: %s", exc, exc_info=True)
    return None


def _imds_v2_token() -> str | None:
    """Fetch an IMDSv2 session token (falls back silently if IMDSv1)."""
    try:
        res = requests.put(
            f"{_IMDS_BASE_URI}/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=1,
        )
        if res.ok:
            return res.text
    except Exception:
        pass
    return None


def _credentials_from_imds() -> Credentials | None:
    """Retrieve credentials from the EC2 Instance Metadata Service (IMDS)."""
    token = _imds_v2_token()
    headers = {"X-aws-ec2-metadata-token": token} if token else {}
    try:
        role_res = requests.get(
            f"{_IMDS_BASE_URI}/latest/meta-data/iam/security-credentials/",
            headers=headers,
            timeout=1,
        )
        if not role_res.ok:
            return None
        role_name = role_res.text.strip()
        creds_res = requests.get(
            f"{_IMDS_BASE_URI}/latest/meta-data/iam/security-credentials/{role_name}",
            headers=headers,
            timeout=1,
        )
        if not creds_res.ok:
            return None
        data = creds_res.json()
        return (
            Credentials(
                data["AccessKeyId"],
                data["SecretAccessKey"],
                data.get("Token"),
            )
            if Credentials
            else None
        )
    except Exception as exc:
        logger.debug("Failed to fetch IMDS credentials: %s", exc, exc_info=True)
        return None


def load_default_credentials() -> Credentials | None:
    """Attempt to load AWS credentials using the default resolution order.

    Order: environment → ECS/EKS task role → EC2 instance profile (IMDS).
    Returns `None` if no credentials are found.
    """
    for provider in (
        _credentials_from_env,
        _credentials_from_container,
        _credentials_from_imds,
    ):
        creds = provider()
        if creds is not None:
            return creds
    return None
