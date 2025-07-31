from unittest.mock import Mock

import pytest

try:
    from snowflake.connector.http_interceptor import (
        HeadersCustomizer,
        HeadersCustomizerInterceptor,
        HttpInterceptor,
    )
except ImportError:
    pass


@pytest.mark.skipolddriver
def test_no_interceptors_does_nothing(sample_request_factory):
    request = sample_request_factory()
    interceptor = HeadersCustomizerInterceptor([])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_REQUEST_ISSUED, request
    )
    assert result == request


@pytest.mark.skipolddriver
def test_non_applying_interceptor_does_nothing(
    sample_request_factory, headers_customizer_factory
):
    request = sample_request_factory()
    customizer = headers_customizer_factory(applies=False)
    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_REQUEST_ISSUED, request
    )
    assert result == request


@pytest.mark.skipolddriver
def test_non_applying_interceptor_not_called(sample_request_factory):
    request = sample_request_factory()

    # Create a mock customizer with applies_to returning False
    customizer = Mock(spec=HeadersCustomizer)
    customizer.applies_to.return_value = False
    customizer.is_invoked_once.return_value = True
    customizer.get_new_headers.return_value = {}

    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_REQUEST_ISSUED, request
    )

    # Assert result is unchanged
    assert result == request

    # Check call counts
    customizer.applies_to.assert_called_once_with(request)
    customizer.get_new_headers.assert_not_called()


@pytest.mark.skipolddriver
def test_dynamic_customizer_adds_different_headers(
    sample_request_factory, dynamic_customizer_factory
):
    request = sample_request_factory()
    interceptor = HeadersCustomizerInterceptor([dynamic_customizer_factory()])

    result1 = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_RETRY, request
    )
    result2 = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_RETRY, request
    )

    assert result1.headers["X-Dynamic-1"] != result2.headers["X-Dynamic-2"]


@pytest.mark.skipolddriver
def test_invoke_once_skips_on_retry(sample_request_factory, headers_customizer_factory):
    request = sample_request_factory()
    customizer = headers_customizer_factory(applies=True, invoke_once=True)
    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_RETRY, request
    )
    assert result == request


@pytest.mark.skipolddriver
def test_invoke_always_runs_on_retry(
    sample_request_factory, headers_customizer_factory
):
    request = sample_request_factory()
    customizer = headers_customizer_factory(
        applies=True, invoke_once=False, headers={"X-Retry": "RetryVal"}
    )
    interceptor = HeadersCustomizerInterceptor([customizer])
    result1 = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_RETRY, request
    )
    result2 = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_RETRY, request
    )
    assert result1.headers["X-Retry"] == "RetryVal"
    assert result2.headers["X-Retry"] == "RetryVal"


@pytest.mark.skipolddriver
def test_prevents_header_overwrite(sample_request_factory, headers_customizer_factory):
    request = sample_request_factory(headers={"User-Agent": "SnowflakeDriver/1.0"})
    customizer = headers_customizer_factory(
        applies=True, invoke_once=True, headers={"User-Agent": "MaliciousAgent"}
    )
    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_REQUEST_ISSUED, request
    )
    assert result.headers["User-Agent"] == "SnowflakeDriver/1.0"
    assert result.headers["User-Agent"] != "MaliciousAgent"


@pytest.mark.skipolddriver
def test_partial_header_overwrite_ignores_only_conflicting_keys(
    sample_request_factory, headers_customizer_factory
):
    request = sample_request_factory(headers={"User-Agent": "SnowflakeDriver/1.0"})

    customizer = headers_customizer_factory(
        applies=True,
        invoke_once=True,
        headers={
            "User-Agent": "MaliciousAgent",  # should be blocked
            "X-New-Header": "NewValue",  # should be added
        },
    )

    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_REQUEST_ISSUED, request
    )

    # Original value preserved
    assert result.headers["User-Agent"] == "SnowflakeDriver/1.0"
    assert result.headers["User-Agent"] != "MaliciousAgent"

    # Non-conflicting key added
    assert result.headers["X-New-Header"] == "NewValue"


@pytest.mark.skipolddriver
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
        HttpInterceptor.InterceptionHook.BEFORE_REQUEST_ISSUED, request
    )
    assert result.headers["X-Custom1"] == "Val1"
    assert result.headers["X-Custom2"] == "Val2"


@pytest.mark.skipolddriver
def test_multi_value_headers(sample_request_factory, headers_customizer_factory):
    request = sample_request_factory()
    customizer = headers_customizer_factory(
        applies=True, headers={"X-Multi": ["ValA", "ValB"]}
    )
    interceptor = HeadersCustomizerInterceptor([customizer])
    result = interceptor.intercept_on(
        HttpInterceptor.InterceptionHook.BEFORE_REQUEST_ISSUED, request
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
@pytest.mark.skipolddriver
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
        HttpInterceptor.InterceptionHook.BEFORE_REQUEST_ISSUED, request
    )

    if should_apply:
        assert result.headers["X-Domain-Specific"] == "True"
    else:
        assert "X-Domain-Specific" not in result.headers
