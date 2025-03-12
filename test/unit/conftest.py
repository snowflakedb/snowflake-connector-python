#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

from snowflake.connector.telemetry_oob import TelemetryService

from ..csp_helpers import (
    FakeAwsEnvironment,
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
def fake_gce_metadata_service():
    """Emulates the GCE metadata service, returning a dummy token."""
    with FakeGceMetadataService() as server:
        yield server
