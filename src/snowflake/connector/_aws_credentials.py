"""
Lightweight AWS credential resolution without boto3.

Resolves credentials in the order: environment → ECS/EKS task metadata → EC2 IMDSv2.
Returns a minimal `SfAWSCredentials` object that can be passed to SigV4 signing
helpers unchanged.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import partial
from typing import Callable

from .vendored import requests

logger = logging.getLogger(__name__)

_ECS_CRED_BASE_URL = "http://169.254.170.2"
_IMDS_BASE_URL = "http://169.254.169.254"
_IMDS_TOKEN_PATH = "/latest/api/token"
_IMDS_ROLE_PATH = "/latest/meta-data/iam/security-credentials/"
_IMDS_AZ_PATH = "/latest/meta-data/placement/availability-zone"


@dataclass
class SfAWSCredentials:
    """Minimal stand-in for ``botocore.credentials.Credentials``."""

    access_key: str
    secret_key: str
    token: str | None = None


def get_env_credentials() -> SfAWSCredentials | None:
    key, secret = os.getenv("AWS_ACCESS_KEY_ID"), os.getenv("AWS_SECRET_ACCESS_KEY")
    if key and secret:
        return SfAWSCredentials(key, secret, os.getenv("AWS_SESSION_TOKEN"))
    return None


def get_container_credentials(*, timeout: float) -> SfAWSCredentials | None:
    """Credentials from ECS/EKS task-metadata endpoint."""
    rel_uri = os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    full_uri = os.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    if not rel_uri and not full_uri:
        return None

    url = full_uri or f"{_ECS_CRED_BASE_URL}{rel_uri}"
    try:
        response = requests.get(url, timeout=timeout)
        if response.ok:
            data = response.json()
            return SfAWSCredentials(
                data["AccessKeyId"], data["SecretAccessKey"], data.get("Token")
            )
    except (requests.Timeout, requests.ConnectionError, ValueError) as exc:
        logger.debug("ECS credential fetch failed: %s", exc, exc_info=True)
    return None


def _get_imds_v2_token(timeout: float) -> str | None:
    try:
        response = requests.put(
            f"{_IMDS_BASE_URL}{_IMDS_TOKEN_PATH}",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=timeout,
        )
        return response.text if response.ok else None
    except (requests.Timeout, requests.ConnectionError):
        return None


def get_imds_credentials(*, timeout: float) -> SfAWSCredentials | None:
    """Instance-profile credentials from the EC2 metadata service."""
    token = _get_imds_v2_token(timeout)
    headers = {"X-aws-ec2-metadata-token": token} if token else {}

    try:
        role_resp = requests.get(
            f"{_IMDS_BASE_URL}{_IMDS_ROLE_PATH}", headers=headers, timeout=timeout
        )
        if not role_resp.ok:
            return None
        role_name = role_resp.text.strip()

        cred_resp = requests.get(
            f"{_IMDS_BASE_URL}{_IMDS_ROLE_PATH}{role_name}",
            headers=headers,
            timeout=timeout,
        )
        if cred_resp.ok:
            data = cred_resp.json()
            return SfAWSCredentials(
                data["AccessKeyId"], data["SecretAccessKey"], data.get("Token")
            )
    except (requests.Timeout, requests.ConnectionError, ValueError) as exc:
        logger.debug("IMDS credential fetch failed: %s", exc, exc_info=True)
    return None


def load_default_credentials(timeout: float = 2.0) -> SfAWSCredentials | None:
    """Resolve credentials using the default AWS chain (env → task → IMDS)."""
    providers: tuple[Callable[[], SfAWSCredentials | None], ...] = (
        get_env_credentials,
        partial(get_container_credentials, timeout=timeout),
        partial(get_imds_credentials, timeout=timeout),
    )
    for try_fetch_credentials in providers:
        credentials = try_fetch_credentials()
        if credentials:
            return credentials
    return None


def get_region(timeout: float = 1.0) -> str | None:
    """Return the current AWS region if it can be discovered."""
    if region := os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"):
        return region

    token = _get_imds_v2_token(timeout)
    headers = {"X-aws-ec2-metadata-token": token} if token else {}
    try:
        response = requests.get(
            f"{_IMDS_BASE_URL}{_IMDS_AZ_PATH}", headers=headers, timeout=timeout
        )
        if response.ok:
            az = response.text.strip()
            return az[:-1] if az and az[-1].isalpha() else None
    except (requests.Timeout, requests.ConnectionError) as exc:
        logger.debug("IMDS region lookup failed: %s", exc, exc_info=True)

    return None
