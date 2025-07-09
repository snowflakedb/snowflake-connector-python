from __future__ import annotations

import os
import re
from concurrent.futures.thread import ThreadPoolExecutor

import boto3
from botocore.utils import IMDSFetcher

from .vendored import requests
from .wif_util import DEFAULT_ENTRA_SNOWFLAKE_RESOURCE


def is_ec2_instance(timeout=0.5):
    try:
        fetcher = IMDSFetcher(timeout=timeout, num_attempts=2)
        document = fetcher._get_request(
            "/latest/dynamic/instance-identity/document",
            None,
            fetcher._fetch_metadata_token(),
        )
        return bool(document.content)
    except Exception:
        return False


def is_aws_lambda():
    return "LAMBDA_TASK_ROOT" in os.environ


def is_valid_arn_for_wif(arn: str) -> bool:
    patterns = [
        r"^arn:[^:]+:iam::[^:]+:user/.+$",
        r"^arn:[^:]+:sts::[^:]+:assumed-role/.+$",
    ]
    return any(re.match(p, arn) for p in patterns)


def has_aws_identity():
    try:
        caller_identity = boto3.client("sts").get_caller_identity()
        if not caller_identity or "Arn" not in caller_identity:
            return False
        else:
            return is_valid_arn_for_wif(caller_identity["Arn"])
    except Exception:
        return False


def is_azure_vm(timeout=0.5):
    try:
        token_resp = requests.get(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            headers={"Metadata": "true"},
            timeout=timeout,
        )
        return token_resp.status_code == 200
    except requests.RequestException:
        return False


def is_azure_function():
    service_vars = [
        "FUNCTIONS_WORKER_RUNTIME",
        "FUNCTIONS_EXTENSION_VERSION",
        "AzureWebJobsStorage",
    ]
    return all(var in os.environ for var in service_vars)


def is_managed_identity_available_on_azure_vm(
    resource=DEFAULT_ENTRA_SNOWFLAKE_RESOURCE, timeout=0.5
):
    endpoint = f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}"
    headers = {"Metadata": "true"}
    try:
        response = requests.get(endpoint, headers=headers, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException:
        return False


def has_azure_managed_identity(on_azure_vm, on_azure_function):
    if on_azure_function:
        return bool(os.environ.get("IDENTITY_HEADER"))
    if on_azure_vm:
        return is_managed_identity_available_on_azure_vm()
    return False


def is_gce_vm(timeout=0.5):
    try:
        response = requests.get("http://metadata.google.internal", timeout=timeout)
        return response.headers.get("Metadata-Flavor") == "Google"
    except requests.RequestException:
        return False


def is_gce_cloud_run_service():
    service_vars = ["K_SERVICE", "K_REVISION", "K_CONFIGURATION"]
    return all(var in os.environ for var in service_vars)


def is_gce_cloud_run_job():
    job_vars = ["CLOUD_RUN_JOB", "CLOUD_RUN_EXECUTION"]
    return all(var in os.environ for var in job_vars)


def has_gcp_identity(timeout=0.5):
    try:
        response = requests.get(
            "http://metadata/computeMetadata/v1/instance/service-accounts/default/email",
            headers={"Metadata-Flavor": "Google"},
            timeout=timeout,
        )
        response.raise_for_status()
        return bool(response.text)
    except requests.RequestException:
        return False


def is_github_action():
    return "GITHUB_ACTIONS" in os.environ


def detect_platforms() -> list[str]:
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            "is_ec2_instance": executor.submit(is_ec2_instance),
            "is_aws_lambda": executor.submit(is_aws_lambda),
            "has_aws_identity": executor.submit(has_aws_identity),
            "is_azure_vm": executor.submit(is_azure_vm),
            "is_azure_function": executor.submit(is_azure_function),
            "is_gce_vm": executor.submit(is_gce_vm),
            "is_gce_cloud_run_service": executor.submit(is_gce_cloud_run_service),
            "is_gce_cloud_run_job": executor.submit(is_gce_cloud_run_job),
            "has_gcp_identity": executor.submit(has_gcp_identity),
            "is_github_action": executor.submit(is_github_action),
        }

        platforms = {key: future.result() for key, future in futures.items()}

    platforms["azure_managed_identity"] = has_azure_managed_identity(
        platforms["is_azure_vm"], platforms["is_azure_function"]
    )

    detected_platforms = [
        platform for platform, detected in platforms.items() if detected
    ]

    return detected_platforms
