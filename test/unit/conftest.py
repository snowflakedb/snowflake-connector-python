from __future__ import annotations

import pytest

from snowflake.connector.telemetry_oob import TelemetryService

from ..csp_helpers import (
    FakeAwsEnvironment,
    FakeAwsLambdaEnvironment,
    FakeAzureFunctionMetadataService,
    FakeAzureVmMetadataService,
    FakeGceCloudRunJobService,
    FakeGceCloudRunServiceService,
    FakeGceMetadataService,
    FakeGitHubActionsService,
    UnavailableMetadataService,
)


@pytest.fixture(autouse=True, scope="session")
def disable_oob_telemetry():
    oob_telemetry_service = TelemetryService.get_instance()
    original_state = oob_telemetry_service.enabled
    oob_telemetry_service.disable()
    yield None
    if original_state:
        oob_telemetry_service.enable()


@pytest.fixture
def unavailable_metadata_service():
    """Emulates an environment where all metadata services are unavailable."""
    with UnavailableMetadataService() as server:
        yield server


@pytest.fixture
def fake_aws_environment():
    """Emulates the AWS environment, returning dummy credentials."""
    with FakeAwsEnvironment() as env:
        yield env


@pytest.fixture
def fake_aws_lambda_environment():
    """Emulates the AWS Lambda environment, returning dummy credentials."""
    with FakeAwsLambdaEnvironment() as env:
        yield env


@pytest.fixture(
    params=[FakeAzureFunctionMetadataService(), FakeAzureVmMetadataService()],
    ids=["azure_function", "azure_vm"],
)
def fake_azure_metadata_service(request):
    """Parameterized fixture that emulates both the Azure VM and Azure Functions metadata services."""
    with request.param as server:
        yield server


@pytest.fixture
def fake_azure_vm_metadata_service():
    """Fixture that emulates only the Azure VM metadata service."""
    with FakeAzureVmMetadataService() as server:
        yield server


@pytest.fixture
def fake_azure_function_metadata_service():
    """Fixture that emulates only the Azure Function metadata service."""
    with FakeAzureFunctionMetadataService() as server:
        yield server


@pytest.fixture
def fake_gce_metadata_service():
    """Emulates the GCE metadata service, returning a dummy token."""
    with FakeGceMetadataService() as server:
        yield server


@pytest.fixture
def fake_gce_cloud_run_service_metadata_service():
    """Emulates the GCE Cloud Run Service metadata service."""
    with FakeGceCloudRunServiceService() as server:
        yield server


@pytest.fixture
def fake_gce_cloud_run_job_metadata_service():
    """Emulates the GCE Cloud Job metadata service."""
    with FakeGceCloudRunJobService() as server:
        yield server


@pytest.fixture
def fake_github_actions_metadata_service():
    """Emulates the GitHub Actions metadata service."""
    with FakeGitHubActionsService() as server:
        yield server


@pytest.fixture(autouse=True)
def crl_cache_tmpdir(request, tmp_path, monkeypatch):
    """
    Fixture that patches the CRL cache directory to use a temporary directory.

    This prevents tests from creating the cache folder in the real system location
    (e.g., ~/Library/Caches/Snowflake/crls on macOS) and ensures test isolation.
    """
    # Exclude test checking default cache path
    if "test_platform_specific_cache_path" in request.node.name:
        return None

    from snowflake.connector import crl_cache

    # Create a temporary cache directory for this test
    temp_crl_cache = tmp_path / "crl_cache"
    temp_crl_cache.mkdir(mode=0o700)

    # Patch the function that returns the default cache path
    monkeypatch.setattr(
        crl_cache, "_get_default_crl_cache_path", lambda: temp_crl_cache
    )

    # Also reset the file cache singleton to ensure each test gets a fresh cache
    monkeypatch.setattr(crl_cache.CRLCacheFactory, "_file_cache_instance", None)

    return temp_crl_cache
