from __future__ import annotations

import pytest

from snowflake.connector.telemetry_oob import TelemetryService

from ..csp_helpers import (
    BrokenMetadataService,
    FakeAwsEnvironment,
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
def broken_metadata_service():
    """Emulates an environment without any metadata service."""
    with BrokenMetadataService() as server:
        yield server


@pytest.fixture
def fake_aws_environment():
    """Emulates the AWS environment, returning dummy credentials."""
    with FakeAwsEnvironment() as env:
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
