#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

from .csp_helpers_async import (
    FakeAwsEnvironmentAsync,
    FakeAzureFunctionMetadataServiceAsync,
    FakeAzureVmMetadataServiceAsync,
    FakeGceMetadataServiceAsync,
    NoMetadataServiceAsync,
)


@pytest.fixture
def no_metadata_service():
    """Emulates an environment without any metadata service."""
    with NoMetadataServiceAsync() as server:
        yield server


@pytest.fixture
def fake_aws_environment():
    with FakeAwsEnvironmentAsync() as env:
        yield env


@pytest.fixture(
    params=[FakeAzureFunctionMetadataServiceAsync(), FakeAzureVmMetadataServiceAsync()],
    ids=["azure_function", "azure_vm"],
)
def fake_azure_metadata_service(request):
    """Parameterized fixture that emulates both the Azure VM and Azure Functions metadata services."""
    with request.param as server:
        yield server


@pytest.fixture
def fake_gce_metadata_service():
    """Emulates the GCE metadata service, returning a dummy token."""
    with FakeGceMetadataServiceAsync() as server:
        yield server
