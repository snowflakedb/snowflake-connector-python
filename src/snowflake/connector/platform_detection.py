from __future__ import annotations

import os
import re
from concurrent.futures.thread import ThreadPoolExecutor
from enum import Enum
from functools import cache

import boto3
from botocore.config import Config
from botocore.utils import IMDSFetcher

from .session_manager import SessionManager
from .vendored.requests import RequestException, Timeout


class _DetectionState(Enum):
    """Internal enum to represent the detection state of a platform."""

    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    TIMEOUT = "timeout"


def is_ec2_instance(platform_detection_timeout_seconds: float):
    """
    Check if the current environment is running on an AWS EC2 instance.

    If we query the AWS Instance Metadata Service (IMDS) for the instance identity document
    and receive content back, then we assume we are running on an EC2 instance.
    This function is compatible with IMDSv1 and IMDSv2 since we send the token in the request.
    It will ignore the token if on IMDSv1 and use the token if on IMDSv2.

    Args:
        platform_detection_timeout_seconds: Timeout value for the metadata service request.

    Returns:
        _DetectionState: DETECTED if running on EC2, NOT_DETECTED otherwise.
    """
    try:
        fetcher = IMDSFetcher(
            timeout=platform_detection_timeout_seconds, num_attempts=1
        )
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
    Validate if an AWS ARN is suitable for use with Snowflake's Workload Identity Federation (WIF).

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


def has_aws_identity(platform_detection_timeout_seconds: float):
    """
    Check if the current environment has a valid AWS identity for authentication.

    If we retrieve an ARN from the caller identity and it is a valid WIF ARN,
    then we assume we have a valid AWS identity for authentication.

    Args:
        platform_detection_timeout_seconds: Timeout value for AWS API calls.

    Returns:
        _DetectionState: DETECTED if valid AWS identity exists, NOT_DETECTED otherwise.
    """
    try:
        config = Config(
            connect_timeout=platform_detection_timeout_seconds,
            read_timeout=platform_detection_timeout_seconds,
            retries={"total_max_attempts": 1},
        )
        caller_identity = boto3.client("sts", config=config).get_caller_identity()
        if not caller_identity or "Arn" not in caller_identity:
            return _DetectionState.NOT_DETECTED
        return (
            _DetectionState.DETECTED
            if is_valid_arn_for_wif(caller_identity["Arn"])
            else _DetectionState.NOT_DETECTED
        )
    except Exception:
        return _DetectionState.NOT_DETECTED


def is_azure_vm(
    platform_detection_timeout_seconds: float, session_manager: SessionManager
):
    """
    Check if the current environment is running on an Azure Virtual Machine.

    If we query the Azure Instance Metadata Service and receive an HTTP 200 response,
    then we assume we are running on an Azure VM.

    Args:
        platform_detection_timeout_seconds: Timeout value for the metadata service request.
        session_manager: SessionManager instance for making HTTP requests.

    Returns:
        _DetectionState: DETECTED if on Azure VM, TIMEOUT if request times out,
                        NOT_DETECTED otherwise.
    """
    try:
        token_resp = session_manager.get(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            headers={"Metadata": "True"},
            timeout=platform_detection_timeout_seconds,
        )
        return (
            _DetectionState.DETECTED
            if token_resp.status_code == 200
            else _DetectionState.NOT_DETECTED
        )
    except Timeout:
        return _DetectionState.TIMEOUT
    except RequestException:
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
    platform_detection_timeout_seconds,
    session_manager: SessionManager,
    resource="https://management.azure.com",
):
    """
    Check if Azure Managed Identity is available and accessible on an Azure VM.

    If we attempt to mint an access token from the Azure Instance Metadata Service
    managed identity endpoint and receive an HTTP 200 response,
    then we assume managed identity is available.

    Args:
        platform_detection_timeout_seconds: Timeout value for the metadata service request.
        session_manager: SessionManager instance for making HTTP requests.
        resource: The Azure resource URI to request a token for.

    Returns:
        _DetectionState: DETECTED if managed identity is available, TIMEOUT if request
                        times out, NOT_DETECTED otherwise.
    """
    endpoint = f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}"
    headers = {"Metadata": "true"}
    try:
        response = session_manager.get(
            endpoint, headers=headers, timeout=platform_detection_timeout_seconds
        )
        return (
            _DetectionState.DETECTED
            if response.status_code == 200
            else _DetectionState.NOT_DETECTED
        )
    except Timeout:
        return _DetectionState.TIMEOUT
    except RequestException:
        return _DetectionState.NOT_DETECTED


def is_managed_identity_available_on_azure_function():
    return bool(os.environ.get("IDENTITY_HEADER"))


def has_azure_managed_identity(
    platform_detection_timeout_seconds: float, session_manager: SessionManager
):
    """
    Determine if Azure Managed Identity is available in the current environment.

    If we are on Azure Functions and the IDENTITY_HEADER environment variable exists,
    then we assume managed identity is available.
    If we are on an Azure VM and can mint an access token from the managed identity endpoint,
    then we assume managed identity is available.
    Handles Azure Functions first since the checks are faster
    Handles Azure VM checks second since they involve network calls.

    Args:
        platform_detection_timeout_seconds: Timeout value for managed identity checks.
        session_manager: SessionManager instance for making HTTP requests.

    Returns:
        _DetectionState: DETECTED if managed identity is available, TIMEOUT if
                        detection timed out, NOT_DETECTED otherwise.
    """
    # short circuit early to save on latency and avoid minting an unnecessary token
    if is_azure_function() == _DetectionState.DETECTED:
        return (
            _DetectionState.DETECTED
            if is_managed_identity_available_on_azure_function()
            else _DetectionState.NOT_DETECTED
        )
    return is_managed_identity_available_on_azure_vm(
        platform_detection_timeout_seconds, session_manager
    )


def is_gce_vm(
    platform_detection_timeout_seconds: float, session_manager: SessionManager
):
    """
    Check if the current environment is running on Google Compute Engine (GCE).

    If we query the Google metadata server and receive a response with the
    "Metadata-Flavor: Google" header, then we assume we are running on GCE.

    Args:
        platform_detection_timeout_seconds: Timeout value for the metadata service request.
        session_manager: SessionManager instance for making HTTP requests.

    Returns:
        _DetectionState: DETECTED if on GCE, TIMEOUT if request times out,
                        NOT_DETECTED otherwise.
    """
    try:
        response = session_manager.get(
            "http://metadata.google.internal",
            timeout=platform_detection_timeout_seconds,
        )
        return (
            _DetectionState.DETECTED
            if response.headers and response.headers.get("Metadata-Flavor") == "Google"
            else _DetectionState.NOT_DETECTED
        )
    except Timeout:
        return _DetectionState.TIMEOUT
    except RequestException:
        return _DetectionState.NOT_DETECTED


def is_gcp_cloud_run_service():
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


def is_gcp_cloud_run_job():
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


def has_gcp_identity(
    platform_detection_timeout_seconds: float, session_manager: SessionManager
):
    """
    Check if the current environment has a valid Google Cloud Platform identity.

    If we query the GCP metadata service for the default service account email
    and receive a non-empty response, then we assume we have a valid GCP identity.

    Args:
        platform_detection_timeout_seconds: Timeout value for the metadata service request.
        session_manager: SessionManager instance for making HTTP requests.
    Returns:
        _DetectionState: DETECTED if valid GCP identity exists, TIMEOUT if request
                        times out, NOT_DETECTED otherwise.
    """
    try:
        response = session_manager.get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
            headers={"Metadata-Flavor": "Google"},
            timeout=platform_detection_timeout_seconds,
        )
        return (
            _DetectionState.DETECTED
            if response.status_code == 200
            else _DetectionState.NOT_DETECTED
        )
    except Timeout:
        return _DetectionState.TIMEOUT
    except RequestException:
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
def detect_platforms(
    platform_detection_timeout_seconds: float | None,
    session_manager: SessionManager | None = None,
) -> list[str]:
    """
    Detect all potential platforms that the current environment may be running on.
    Swallows all exceptions and returns an empty list if any exception occurs to not affect main driver functionality.

    Args:
        platform_detection_timeout_seconds: Timeout value for platform detection requests. Defaults to 0.2 seconds
                if None is provided.
        session_manager: SessionManager instance for making HTTP requests. If None, a new instance will be created.

    Returns:
        list[str]: List of detected platform names. Platforms that timed out will have
                  "_timeout" suffix appended to their name. Returns empty list if any
                  exception occurs during detection.
    """
    try:
        if platform_detection_timeout_seconds is None:
            platform_detection_timeout_seconds = 0.2

        if session_manager is None:
            # This should never happen - we expect session manager to be passed from the outer scope
            session_manager = SessionManager(use_pooling=False, max_retries=0)

        # Run environment-only checks synchronously (no network calls, no threading overhead)
        platforms = {
            "is_aws_lambda": is_aws_lambda(),
            "is_azure_function": is_azure_function(),
            "is_gce_cloud_run_service": is_gcp_cloud_run_service(),
            "is_gce_cloud_run_job": is_gcp_cloud_run_job(),
            "is_github_action": is_github_action(),
        }

        # Run network-calling functions in parallel
        if platform_detection_timeout_seconds != 0.0:
            with ThreadPoolExecutor(max_workers=6) as executor:
                futures = {
                    "is_ec2_instance": executor.submit(
                        is_ec2_instance, platform_detection_timeout_seconds
                    ),
                    "has_aws_identity": executor.submit(
                        has_aws_identity, platform_detection_timeout_seconds
                    ),
                    "is_azure_vm": executor.submit(
                        is_azure_vm, platform_detection_timeout_seconds, session_manager
                    ),
                    "has_azure_managed_identity": executor.submit(
                        has_azure_managed_identity,
                        platform_detection_timeout_seconds,
                        session_manager,
                    ),
                    "is_gce_vm": executor.submit(
                        is_gce_vm, platform_detection_timeout_seconds, session_manager
                    ),
                    "has_gcp_identity": executor.submit(
                        has_gcp_identity,
                        platform_detection_timeout_seconds,
                        session_manager,
                    ),
                }

                platforms.update(
                    {key: future.result() for key, future in futures.items()}
                )

        detected_platforms = []
        for platform_name, detection_state in platforms.items():
            if detection_state == _DetectionState.DETECTED:
                detected_platforms.append(platform_name)
            elif detection_state == _DetectionState.TIMEOUT:
                detected_platforms.append(f"{platform_name}_timeout")

        return detected_platforms
    except Exception:
        return []
