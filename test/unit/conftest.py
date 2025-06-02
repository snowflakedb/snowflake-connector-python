from __future__ import annotations

from typing import Callable

import pytest

from snowflake.connector.http_interceptor import Headers, HeadersCustomizer, RequestDTO
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


@pytest.fixture
def sample_request_factory():
    def _factory(
        url="https://test.snowflakecomputing.com/api/v1",
        method="GET",
        headers=None,
    ):
        return RequestDTO(
            url=url,
            method=method,
            headers=headers or {"User-Agent": "SnowflakeDriver/1.0"},
        )

    return _factory


@pytest.fixture
def headers_customizer_factory():
    def _customizer_factory(
        applies: Callable[[RequestDTO], bool] | bool = True,
        invoke_once: bool = True,
        headers: Callable[[RequestDTO], Headers] | Headers = None,
    ):
        class MockCustomizer(HeadersCustomizer):
            def applies_to(self, request: RequestDTO) -> bool:
                if callable(applies):
                    return applies(request)
                return applies

            def is_invoked_once(self) -> bool:
                return invoke_once

            def get_new_headers(self, request: RequestDTO) -> Headers:
                if callable(headers):
                    return headers(request)
                return headers or {}

        return MockCustomizer()

    return _customizer_factory


@pytest.fixture
def dynamic_customizer_factory():
    def _dynamic_factory():
        counter = {"count": 0}

        class DynamicCustomizer(HeadersCustomizer):
            def applies_to(self, request: RequestDTO) -> bool:
                return True

            def is_invoked_once(self) -> bool:
                return False

            def get_new_headers(self, request: RequestDTO) -> Headers:
                counter["count"] += 1
                return {
                    f"X-Dynamic-{counter['count']}": f"DynamicVal-{counter['count']}"
                }

        return DynamicCustomizer()

    return _dynamic_factory
