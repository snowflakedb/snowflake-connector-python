from __future__ import annotations

import os
import re
from concurrent.futures.thread import ThreadPoolExecutor
from enum import Enum
from functools import cache

import boto3
from botocore.config import Config
from botocore.utils import IMDSFetcher

from .vendored import requests


class _DetectionState(Enum):
    """Internal enum to represent the detection state of a platform."""

    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    TIMEOUT = "timeout"


def is_ec2_instance(timeout_seconds: float):
    """
    Check if the current environment is running on an AWS EC2 instance.

    If we query the AWS Instance Metadata Service (IMDS) for the instance identity document
    and receive content back, then we assume we are running on an EC2 instance.
    This function is compatible with IMDSv1 and IMDSv2 since we send the token in the request.
    It will ignore the token if on IMDSv1 and use the token if on IMDSv2.

    Args:
        timeout_seconds: Timeout value for the metadata service request.

    Returns:
        _DetectionState: DETECTED if running on EC2, NOT_DETECTED otherwise.
    """
    try:
        fetcher = IMDSFetcher(timeout=timeout_seconds, num_attempts=1)
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
    """
    Check if the current environment is running in AWS Lambda.

    If we check for the LAMBDA_TASK_ROOT environment variable and it exists,
    then we assume we are running in AWS Lambda.

    Returns:
        _DetectionState: DETECTED if LAMBDA_TASK_ROOT env var exists, NOT_DETECTED otherwise.
    """
    return (
        _DetectionState.DETECTED
        if "LAMBDA_TASK_ROOT" in os.environ
        else _DetectionState.NOT_DETECTED
    )


def is_valid_arn_for_wif(arn: str) -> bool:
    """
    Validate if an AWS ARN is suitable for Web Identity Federation (WIF).

    Args:
        arn: The AWS ARN string to validate.

    Returns:
        bool: True if ARN is valid for WIF, False otherwise.
    """
    patterns = [
        r"^arn:[^:]+:iam::[^:]+:user/.+$",
        r"^arn:[^:]+:sts::[^:]+:assumed-role/.+$",
    ]
    return any(re.match(p, arn) for p in patterns)


def has_aws_identity(timeout_seconds: float):
    """
    Check if the current environment has a valid AWS identity for authentication.

    If we retrieve an ARN from the caller identity and it is a valid WIF ARN,
    then we assume we have a valid AWS identity for authentication.

    Args:
        timeout_seconds: Timeout value for AWS API calls.

    Returns:
        _DetectionState: DETECTED if valid AWS identity exists, NOT_DETECTED otherwise.
    """
    try:
        config = Config(
            connect_timeout=timeout_seconds,
            read_timeout=timeout_seconds,
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


def is_azure_vm(timeout_seconds: float):
    """
    Check if the current environment is running on an Azure Virtual Machine.

    If we query the Azure Instance Metadata Service and receive an HTTP 200 response,
    then we assume we are running on an Azure VM.

    Args:
        timeout_seconds: Timeout value for the metadata service request.

    Returns:
        _DetectionState: DETECTED if on Azure VM, TIMEOUT if request times out,
                        NOT_DETECTED otherwise.
    """
    try:
        token_resp = requests.get(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            headers={"Metadata": "true"},
            timeout=timeout_seconds,
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
    """
    Check if the current environment is running in Azure Functions.

    If we check for Azure Functions environment variables (FUNCTIONS_WORKER_RUNTIME,
    FUNCTIONS_EXTENSION_VERSION, AzureWebJobsStorage) and they all exist,
    then we assume we are running in Azure Functions.

    Returns:
        _DetectionState: DETECTED if all Azure Functions env vars are present,
                        NOT_DETECTED otherwise.
    """
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
    timeout_seconds, resource="https://management.azure.com/"
):
    """
    Check if Azure Managed Identity is available and accessible on an Azure VM.

    If we attempt to mint an access token from the Azure Instance Metadata Service
    managed identity endpoint and receive an HTTP 200 response,
    then we assume managed identity is available.

    Args:
        timeout_seconds: Timeout value for the metadata service request.
        resource: The Azure resource URI to request a token for.

    Returns:
        _DetectionState: DETECTED if managed identity is available, TIMEOUT if request
                        times out, NOT_DETECTED otherwise.
    """
    endpoint = f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}"
    headers = {"Metadata": "true"}
    try:
        response = requests.get(endpoint, headers=headers, timeout=timeout_seconds)
        return (
            _DetectionState.DETECTED
            if response.status_code == 200
            else _DetectionState.NOT_DETECTED
        )
    except requests.Timeout:
        return _DetectionState.TIMEOUT
    except requests.RequestException:
        return _DetectionState.NOT_DETECTED


def has_azure_managed_identity(on_azure_vm, on_azure_function, timeout_seconds: float):
    """
    Determine if Azure Managed Identity is available in the current environment.

    If we are on Azure Functions and the IDENTITY_HEADER environment variable exists,
    then we assume managed identity is available.
    If we are on an Azure VM and can mint an access token from the managed identity endpoint,
    then we assume managed identity is available.
    Assumes timeout state if either VM or Function detection timed out.

    Args:
        on_azure_vm: Detection state for Azure VM.
        on_azure_function: Detection state for Azure Function.
        timeout_seconds: Timeout value for managed identity checks.

    Returns:
        _DetectionState: DETECTED if managed identity is available, TIMEOUT if
                        detection timed out, NOT_DETECTED otherwise.
    """
    if on_azure_function == _DetectionState.DETECTED:
        return (
            _DetectionState.DETECTED
            if os.environ.get("IDENTITY_HEADER")
            else _DetectionState.NOT_DETECTED
        )
    if on_azure_vm == _DetectionState.DETECTED:
        return is_managed_identity_available_on_azure_vm(timeout_seconds)
    if (
        on_azure_vm == _DetectionState.TIMEOUT
        or on_azure_function == _DetectionState.TIMEOUT
    ):
        return _DetectionState.TIMEOUT
    return _DetectionState.NOT_DETECTED


def is_gce_vm(timeout_seconds: float):
    """
    Check if the current environment is running on Google Compute Engine (GCE).

    If we query the Google metadata server and receive a response with the
    "Metadata-Flavor: Google" header, then we assume we are running on GCE.

    Args:
        timeout_seconds: Timeout value for the metadata service request.

    Returns:
        _DetectionState: DETECTED if on GCE, TIMEOUT if request times out,
                        NOT_DETECTED otherwise.
    """
    try:
        response = requests.get(
            "http://metadata.google.internal", timeout=timeout_seconds
        )
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
    """
    Check if the current environment is running in Google Cloud Run service.

    If we check for Cloud Run service environment variables (K_SERVICE, K_REVISION,
    K_CONFIGURATION) and they all exist, then we assume we are running in Cloud Run service.

    Returns:
        _DetectionState: DETECTED if all Cloud Run service env vars are present,
                        NOT_DETECTED otherwise.
    """
    service_vars = ["K_SERVICE", "K_REVISION", "K_CONFIGURATION"]
    return (
        _DetectionState.DETECTED
        if all(var in os.environ for var in service_vars)
        else _DetectionState.NOT_DETECTED
    )


def is_gce_cloud_run_job():
    """
    Check if the current environment is running in Google Cloud Run job.

    If we check for Cloud Run job environment variables (CLOUD_RUN_JOB, CLOUD_RUN_EXECUTION)
    and they both exist, then we assume we are running in a Cloud Run job.

    Returns:
        _DetectionState: DETECTED if all Cloud Run job env vars are present,
                        NOT_DETECTED otherwise.
    """
    job_vars = ["CLOUD_RUN_JOB", "CLOUD_RUN_EXECUTION"]
    return (
        _DetectionState.DETECTED
        if all(var in os.environ for var in job_vars)
        else _DetectionState.NOT_DETECTED
    )


def has_gcp_identity(timeout_seconds: float):
    """
    Check if the current environment has a valid Google Cloud Platform identity.

    If we query the GCP metadata service for the default service account email
    and receive a non-empty response, then we assume we have a valid GCP identity.

    Args:
        timeout_seconds: Timeout value for the metadata service request.

    Returns:
        _DetectionState: DETECTED if valid GCP identity exists, TIMEOUT if request
                        times out, NOT_DETECTED otherwise.
    """
    try:
        response = requests.get(
            "http://metadata/computeMetadata/v1/instance/service-accounts/default/email",
            headers={"Metadata-Flavor": "Google"},
            timeout=timeout_seconds,
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
    """
    Check if the current environment is running in GitHub Actions.

    If we check for the GITHUB_ACTIONS environment variable and it exists,
    then we assume we are running in GitHub Actions.

    Returns:
        _DetectionState: DETECTED if GITHUB_ACTIONS env var exists, NOT_DETECTED otherwise.
    """
    return (
        _DetectionState.DETECTED
        if "GITHUB_ACTIONS" in os.environ
        else _DetectionState.NOT_DETECTED
    )


@cache
def detect_platforms(timeout_seconds: float | None) -> list[str]:
    """
    Detect all potential platforms that the current environment may be running on.

    Args:
        timeout_seconds: Timeout value for platform detection requests. Defaults to 0.2 seconds
                if None is provided.

    Returns:
        list[str]: List of detected platform names. Platforms that timed out will have
                  "_timeout" suffix appended to their name.
    """
    if timeout_seconds is None:
        timeout_seconds = 0.2

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            "is_ec2_instance": executor.submit(is_ec2_instance, timeout_seconds),
            "is_aws_lambda": executor.submit(is_aws_lambda),
            "has_aws_identity": executor.submit(has_aws_identity, timeout_seconds),
            "is_azure_vm": executor.submit(is_azure_vm, timeout_seconds),
            "is_azure_function": executor.submit(is_azure_function),
            "is_gce_vm": executor.submit(is_gce_vm, timeout_seconds),
            "is_gce_cloud_run_service": executor.submit(is_gce_cloud_run_service),
            "is_gce_cloud_run_job": executor.submit(is_gce_cloud_run_job),
            "has_gcp_identity": executor.submit(has_gcp_identity, timeout_seconds),
            "is_github_action": executor.submit(is_github_action),
        }

        platforms = {key: future.result() for key, future in futures.items()}

    platforms["azure_managed_identity"] = has_azure_managed_identity(
        platforms["is_azure_vm"], platforms["is_azure_function"], timeout_seconds
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
