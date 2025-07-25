from __future__ import annotations

import os
import re
from concurrent.futures.thread import ThreadPoolExecutor
from enum import Enum

import boto3
from botocore.config import Config
from botocore.utils import IMDSFetcher

from .vendored import requests
from .wif_util import DEFAULT_ENTRA_SNOWFLAKE_RESOURCE


class _DetectionState(Enum):
    """Internal enum to represent the detection state of a platform."""

    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    TIMEOUT = "timeout"


def is_ec2_instance(timeout):
    try:
        fetcher = IMDSFetcher(timeout=timeout, num_attempts=1)
        document = fetcher._get_request(
            "/latest/dynamic/instance-identity/document",
            None,
            fetcher._fetch_metadata_token(),
        )
        return (
            _DetectionState.DETECTED
            if document.content
            else _DetectionState.NOT_DETECTED
        )
    except Exception:
        return _DetectionState.NOT_DETECTED


def is_aws_lambda():
    return (
        _DetectionState.DETECTED
        if "LAMBDA_TASK_ROOT" in os.environ
        else _DetectionState.NOT_DETECTED
    )


def is_valid_arn_for_wif(arn: str) -> bool:
    patterns = [
        r"^arn:[^:]+:iam::[^:]+:user/.+$",
        r"^arn:[^:]+:sts::[^:]+:assumed-role/.+$",
    ]
    return any(re.match(p, arn) for p in patterns)


def has_aws_identity(timeout):
    try:
        config = Config(
            connect_timeout=timeout,
            read_timeout=timeout,
            retries={"total_max_attempts": 1},
        )
        caller_identity = boto3.client("sts", config=config).get_caller_identity()
        if not caller_identity or "Arn" not in caller_identity:
            return _DetectionState.NOT_DETECTED
        else:
            return (
                _DetectionState.DETECTED
                if is_valid_arn_for_wif(caller_identity["Arn"])
                else _DetectionState.NOT_DETECTED
            )
    except Exception:
        return _DetectionState.NOT_DETECTED


def is_azure_vm(timeout):
    try:
        token_resp = requests.get(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            headers={"Metadata": "true"},
            timeout=timeout,
        )
        return (
            _DetectionState.DETECTED
            if token_resp.status_code == 200
            else _DetectionState.NOT_DETECTED
        )
    except requests.Timeout:
        return _DetectionState.TIMEOUT
    except requests.RequestException:
        return _DetectionState.NOT_DETECTED


def is_azure_function():
    service_vars = [
        "FUNCTIONS_WORKER_RUNTIME",
        "FUNCTIONS_EXTENSION_VERSION",
        "AzureWebJobsStorage",
    ]
    return (
        _DetectionState.DETECTED
        if all(var in os.environ for var in service_vars)
        else _DetectionState.NOT_DETECTED
    )


def is_managed_identity_available_on_azure_vm(
    timeout, resource=DEFAULT_ENTRA_SNOWFLAKE_RESOURCE
):
    endpoint = f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}"
    headers = {"Metadata": "true"}
    try:
        response = requests.get(endpoint, headers=headers, timeout=timeout)
        return (
            _DetectionState.DETECTED
            if response.status_code == 200
            else _DetectionState.NOT_DETECTED
        )
    except requests.Timeout:
        return _DetectionState.TIMEOUT
    except requests.RequestException:
        return _DetectionState.NOT_DETECTED


def has_azure_managed_identity(on_azure_vm, on_azure_function, timeout):
    if on_azure_function == _DetectionState.DETECTED:
        return (
            _DetectionState.DETECTED
            if os.environ.get("IDENTITY_HEADER")
            else _DetectionState.NOT_DETECTED
        )
    if on_azure_vm == _DetectionState.DETECTED:
        return is_managed_identity_available_on_azure_vm(timeout)
    if (
        on_azure_vm == _DetectionState.TIMEOUT
        or on_azure_function == _DetectionState.TIMEOUT
    ):
        return _DetectionState.TIMEOUT
    return _DetectionState.NOT_DETECTED


def is_gce_vm(timeout):
    try:
        response = requests.get("http://metadata.google.internal", timeout=timeout)
        return (
            _DetectionState.DETECTED
            if response.headers.get("Metadata-Flavor") == "Google"
            else _DetectionState.NOT_DETECTED
        )
    except requests.Timeout:
        return _DetectionState.TIMEOUT
    except requests.RequestException:
        return _DetectionState.NOT_DETECTED


def is_gce_cloud_run_service():
    service_vars = ["K_SERVICE", "K_REVISION", "K_CONFIGURATION"]
    return (
        _DetectionState.DETECTED
        if all(var in os.environ for var in service_vars)
        else _DetectionState.NOT_DETECTED
    )


def is_gce_cloud_run_job():
    job_vars = ["CLOUD_RUN_JOB", "CLOUD_RUN_EXECUTION"]
    return (
        _DetectionState.DETECTED
        if all(var in os.environ for var in job_vars)
        else _DetectionState.NOT_DETECTED
    )


def has_gcp_identity(timeout):
    try:
        response = requests.get(
            "http://metadata/computeMetadata/v1/instance/service-accounts/default/email",
            headers={"Metadata-Flavor": "Google"},
            timeout=timeout,
        )
        response.raise_for_status()
        return (
            _DetectionState.DETECTED if response.text else _DetectionState.NOT_DETECTED
        )
    except requests.Timeout:
        return _DetectionState.TIMEOUT
    except requests.RequestException:
        return _DetectionState.NOT_DETECTED


def is_github_action():
    return (
        _DetectionState.DETECTED
        if "GITHUB_ACTIONS" in os.environ
        else _DetectionState.NOT_DETECTED
    )


def detect_platforms(timeout: int | float | None) -> list[str]:
    if timeout is None:
        timeout = 0.2

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            "is_ec2_instance": executor.submit(is_ec2_instance, timeout),
            "is_aws_lambda": executor.submit(is_aws_lambda),
            "has_aws_identity": executor.submit(has_aws_identity, timeout),
            "is_azure_vm": executor.submit(is_azure_vm, timeout),
            "is_azure_function": executor.submit(is_azure_function),
            "is_gce_vm": executor.submit(is_gce_vm, timeout),
            "is_gce_cloud_run_service": executor.submit(is_gce_cloud_run_service),
            "is_gce_cloud_run_job": executor.submit(is_gce_cloud_run_job),
            "has_gcp_identity": executor.submit(has_gcp_identity, timeout),
            "is_github_action": executor.submit(is_github_action),
        }

        platforms = {key: future.result() for key, future in futures.items()}

    platforms["azure_managed_identity"] = has_azure_managed_identity(
        platforms["is_azure_vm"], platforms["is_azure_function"], timeout
    )

    detected_platforms = []
    for platform_name, detection_state in platforms.items():
        if detection_state == _DetectionState.DETECTED:
            detected_platforms.append(platform_name)
        elif detection_state == _DetectionState.TIMEOUT:
            detected_platforms.append(f"{platform_name}_timeout")
        elif detection_state == _DetectionState.NOT_DETECTED:
            pass

    return detected_platforms
