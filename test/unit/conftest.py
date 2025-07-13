from __future__ import annotations

import pytest

from snowflake.connector.telemetry_oob import TelemetryService

from ..csp_helpers import (
    FakeAwsEc2,
    FakeAwsEcs,
    FakeAwsLambda,
    FakeAwsNoCreds,
    FakeAzureFunctionMetadataService,
    FakeAzureVmMetadataService,
    FakeGceMetadataService,
    NoMetadataService,
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
def no_metadata_service():
    """Emulates an environment without any metadata service."""
    with NoMetadataService() as server:
        yield server


@pytest.fixture(
    params=[FakeAwsEc2, FakeAwsEcs, FakeAwsLambda],
    ids=["aws_ec2", "aws_ecs", "aws_lambda"],
)
def fake_aws_environment(request):
    """Runtimes that *do* expose credentials."""
    with request.param() as env:
        yield env


@pytest.fixture(params=[FakeAwsNoCreds], ids=["aws_no_creds"])
def malformed_aws_environment(request):
    """Runtime where *no* credentials are discoverable (negative-path)."""
    with request.param() as env:
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
def fake_gce_metadata_service():
    """Emulates the GCE metadata service, returning a dummy token."""
    with FakeGceMetadataService() as server:
        yield server
