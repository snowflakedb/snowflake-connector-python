from typing import Callable, Union
from unittest.mock import Mock

import pytest

from snowflake.connector.http_interceptor import (
    Headers,
    HeadersCustomizer,
    HeadersCustomizerInterceptor,
    HttpInterceptor,
    RequestDTO,
    get_request_info,
    verify_headers,
    verify_method,
    verify_url,
)

# TODO: test_headers_customizer_trying_to_overwrite_headers add tests that conflict of headers is resolved - we keep the original ones


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
        applies: Union[Callable[[RequestDTO], bool], bool] = True,
        invoke_once: bool = False,
        headers: Union[Callable[[RequestDTO], Headers], Headers] = None,
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
def dynamic_customizer():
    counter = {"count": 0}

    class DynamicCustomizer(HeadersCustomizer):
        def applies_to(self, request: RequestDTO) -> bool:
            return True

        def is_invoked_once(self) -> bool:
            return False

        def get_new_headers(self, request: RequestDTO) -> Headers:
            counter["count"] += 1
            return {"X-Dynamic": f"DynamicVal-{counter['count']}"}

    return DynamicCustomizer()


# === Verification tests ===


def test_verify_method_valid():
    assert verify_method("get") == "GET"
    assert verify_method("POST") == "POST"
    assert verify_method("invalid") is None
    assert verify_method("GETs") is None
    assert verify_method(None) is None


def test_verify_url_valid():
    assert verify_url("http://example.com") == "http://example.com"
    assert verify_url(None) is None
    assert verify_url(12345) is None


def test_verify_headers_valid():
    assert verify_headers({"X-Test": "Value"}) == {"X-Test": "Value"}
    assert verify_headers(None) is None
    assert verify_headers("not-a-dict") is None


def test_get_request_info_combines_verified():
    dto = get_request_info("get", "http://example.com", {"X-Test": "Value"})
    assert dto.method == "GET"
    assert dto.url == "http://example.com"
    assert dto.headers == {"X-Test": "Value"}


# === Interceptor behavior ===


def test_no_interceptors_does_nothing(sample_request_factory):
    request = sample_request_factory()
    interceptor = HeadersCustomizerInterceptor([])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request
    )
    assert result == request


def test_non_applying_interceptor_does_nothing(
    sample_request_factory, headers_customizer_factory
):
    request = sample_request_factory()
    customizer = headers_customizer_factory(applies=False)
    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request
    )
    assert result == request


def test_non_applying_interceptor_not_called(sample_request_factory):
    request = sample_request_factory()

    # Create a mock customizer with applies_to returning False
    customizer = Mock(spec=HeadersCustomizer)
    customizer.applies_to.return_value = False
    customizer.is_invoked_once.return_value = False
    customizer.get_new_headers.return_value = {}

    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request
    )

    # Assert result is unchanged
    assert result == request

    # Check call counts
    customizer.applies_to.assert_called_once_with(request)
    customizer.get_new_headers.assert_not_called()


@pytest.mark.parametrize("invoke_once", [True, False])
def test_static_hook_respects_invoked_once_flag(
    sample_request_factory, headers_customizer_factory, invoke_once
):
    request = sample_request_factory()
    customizer = headers_customizer_factory(
        applies=True, invoke_once=invoke_once, headers={"X-Test": "Value"}
    )
    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request
    )

    if invoke_once:
        assert result.headers["X-Test"] == "Value"
    else:
        assert "X-Test" not in result.headers


def test_dynamic_customizer_adds_different_headers(
    sample_request_factory, dynamic_customizer
):
    request = sample_request_factory()
    interceptor = HeadersCustomizerInterceptor([dynamic_customizer])

    result1 = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_EACH_RETRY, request
    )
    result2 = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_EACH_RETRY, request
    )

    assert result1.headers["X-Dynamic-1"] != result2.headers["X-Dynamic-2"]


def test_invoke_once_skips_on_retry(sample_request_factory, headers_customizer_factory):
    request = sample_request_factory()
    customizer = headers_customizer_factory(applies=True, invoke_once=True)
    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_EACH_RETRY, request
    )
    assert result == request


def test_invoke_always_runs_on_retry(
    sample_request_factory, headers_customizer_factory
):
    request = sample_request_factory()
    customizer = headers_customizer_factory(
        applies=True, invoke_once=False, headers={"X-Retry": "RetryVal"}
    )
    interceptor = HeadersCustomizerInterceptor([customizer])
    result1 = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_EACH_RETRY, request
    )
    result2 = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_EACH_RETRY, request
    )
    assert result1.headers["X-Retry"] == "RetryVal"
    assert result2.headers["X-Retry"] == "RetryVal"


def test_prevents_header_overwrite(sample_request_factory, headers_customizer_factory):
    request = sample_request_factory(headers={"User-Agent": "SnowflakeDriver/1.0"})
    customizer = headers_customizer_factory(
        applies=True, headers={"User-Agent": "MaliciousAgent"}
    )
    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request
    )
    assert result.headers["User-Agent"] == "SnowflakeDriver/1.0"
    assert result.headers["User-Agent"] != "MaliciousAgent"


def test_multiple_customizers_add_headers(
    sample_request_factory, headers_customizer_factory
):
    request = sample_request_factory()
    customizer1 = headers_customizer_factory(
        applies=True, headers={"X-Custom1": "Val1"}
    )
    customizer2 = headers_customizer_factory(
        applies=True, headers={"X-Custom2": "Val2"}
    )
    interceptor = HeadersCustomizerInterceptor([customizer1, customizer2])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request
    )
    assert result.headers["X-Custom1"] == "Val1"
    assert result.headers["X-Custom2"] == "Val2"


def test_multi_value_headers(sample_request_factory, headers_customizer_factory):
    request = sample_request_factory()
    customizer = headers_customizer_factory(
        applies=True, headers={"X-Multi": ["ValA", "ValB"]}
    )
    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request
    )
    values = result.headers["X-Multi"]
    if isinstance(values, list):
        assert "ValA" in values
        assert "ValB" in values
    else:
        assert "ValA" in values or "ValB" in values


@pytest.mark.parametrize(
    "url,should_apply",
    [
        ("https://test.snowflakecomputing.com/api", True),
        ("https://example.com/api", False),
    ],
)
def test_customizer_applies_only_to_specific_domain(
    sample_request_factory, headers_customizer_factory, url, should_apply
):
    request = sample_request_factory(url=url)

    def snowflake_only(req):
        return "snowflakecomputing.com" in req.url

    customizer = headers_customizer_factory(
        applies=snowflake_only, headers={"X-Domain-Specific": "True"}
    )
    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request
    )

    if should_apply:
        assert result.headers["X-Domain-Specific"] == "True"
    else:
        assert "X-Domain-Specific" not in result.headers
