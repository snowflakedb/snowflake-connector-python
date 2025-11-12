#!/usr/bin/env python


from __future__ import annotations

from test.unit.test_telemetry import (
    assert_telemetry_data_for_http_error,
    assert_telemetry_data_for_revocation_check_error,
    get_retry_ctx,
)
from unittest import mock
from unittest.mock import AsyncMock, Mock

import aiohttp
import pytest

import snowflake.connector.aio._telemetry
import snowflake.connector.telemetry
from snowflake.connector.aio._network import SnowflakeRestful
from snowflake.connector.errors import (
    BadGatewayError,
    BadRequest,
    ForbiddenError,
    HttpError,
    InternalServerError,
    RevocationCheckError,
    ServiceUnavailableError,
)
from src.snowflake.connector.compat import (
    BAD_GATEWAY,
    BAD_REQUEST,
    FORBIDDEN,
    INTERNAL_SERVER_ERROR,
    SERVICE_UNAVAILABLE,
)
from src.snowflake.connector.errorcode import ER_OCSP_RESPONSE_UNAVAILABLE


def test_telemetry_data_to_dict():
    """Tests that TelemetryData instances are properly converted to dicts."""
    assert snowflake.connector.telemetry.TelemetryData({}, 2000).to_dict() == {
        "message": {},
        "timestamp": "2000",
    }

    d = {"type": "test", "query_id": "1", "value": 20}
    assert snowflake.connector.telemetry.TelemetryData(d, 1234).to_dict() == {
        "message": d,
        "timestamp": "1234",
    }


def get_client_and_mock():
    rest_call = Mock()
    rest_call.return_value = {"success": True}
    rest = Mock()
    rest.attach_mock(rest_call, "request")
    client = snowflake.connector.aio._telemetry.TelemetryClient(rest, 2)
    return client, rest_call


async def test_telemetry_simple_flush():
    """Tests that metrics are properly enqueued and sent to telemetry."""
    client, rest_call = get_client_and_mock()

    await client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    await client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 3000))
    assert rest_call.call_count == 1


async def test_telemetry_close():
    """Tests that remaining metrics are flushed on close."""
    client, rest_call = get_client_and_mock()

    await client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    await client.close()
    assert rest_call.call_count == 1
    assert client.is_closed


async def test_telemetry_close_empty():
    """Tests that no calls are made on close if there are no metrics to flush."""
    client, rest_call = get_client_and_mock()

    await client.close()
    assert rest_call.call_count == 0
    assert client.is_closed


async def test_telemetry_send_batch():
    """Tests that metrics are sent with the send_batch method."""
    client, rest_call = get_client_and_mock()

    await client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    await client.send_batch()
    assert rest_call.call_count == 1


async def test_telemetry_send_batch_empty():
    """Tests that send_batch does nothing when there are no metrics to send."""
    client, rest_call = get_client_and_mock()

    await client.send_batch()
    assert rest_call.call_count == 0


async def test_telemetry_send_batch_clear():
    """Tests that send_batch clears the first batch and will not send anything on a second call."""
    client, rest_call = get_client_and_mock()

    await client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    await client.send_batch()
    assert rest_call.call_count == 1

    await client.send_batch()
    assert rest_call.call_count == 1


async def test_telemetry_auto_disable():
    """Tests that the client will automatically disable itself if a request fails."""
    client, rest_call = get_client_and_mock()
    rest_call.return_value = {"success": False}

    await client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert client.is_enabled()

    await client.send_batch()
    assert not client.is_enabled()


async def test_telemetry_add_batch_disabled():
    """Tests that the client will not add logs if disabled."""
    client, _ = get_client_and_mock()

    client.disable()
    await client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))

    assert client.buffer_size() == 0


async def test_telemetry_send_batch_disabled():
    """Tests that the client will not send logs if disabled."""
    client, rest_call = get_client_and_mock()

    await client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert client.buffer_size() == 1

    client.disable()

    await client.send_batch()
    assert client.buffer_size() == 1
    assert rest_call.call_count == 0


async def test_raising_error_generates_telemetry_event_when_connection_is_present():
    mock_connection = get_mocked_telemetry_connection()

    with pytest.raises(RevocationCheckError):
        raise RevocationCheckError(
            msg="Response unavailable",
            errno=ER_OCSP_RESPONSE_UNAVAILABLE,
            connection=mock_connection,
            send_telemetry=True,
        )

    mock_connection._log_telemetry.assert_called_once()
    assert_telemetry_data_for_revocation_check_error(
        mock_connection._log_telemetry.call_args[0][0]
    )


async def test_raising_error_with_send_telemetry_off_does_not_generate_telemetry_event_when_connection_is_present():
    mock_connection = get_mocked_telemetry_connection()

    with pytest.raises(RevocationCheckError):
        raise RevocationCheckError(
            msg="Response unavailable",
            errno=ER_OCSP_RESPONSE_UNAVAILABLE,
            connection=mock_connection,
            send_telemetry=False,
        )

    mock_connection._log_telemetry.assert_not_called()


async def test_request_throws_revocation_check_error():
    retry_ctx = get_retry_ctx()
    mock_connection = get_mocked_telemetry_connection()

    with mock.patch.object(SnowflakeRestful, "_request_exec") as _request_exec_mocked:
        _request_exec_mocked.side_effect = RevocationCheckError(
            msg="Response unavailable", errno=ER_OCSP_RESPONSE_UNAVAILABLE
        )
        mock_restful = SnowflakeRestful(connection=mock_connection)
        with pytest.raises(RevocationCheckError):
            await mock_restful._request_exec_wrapper(
                None,
                None,
                None,
                None,
                None,
                retry_ctx,
            )
        mock_connection._log_telemetry.assert_called_once()
        assert_telemetry_data_for_revocation_check_error(
            mock_connection._log_telemetry.call_args[0][0]
        )


@pytest.mark.parametrize(
    "status_code",
    [
        401,  # 401 - non-retryable
        404,  # Not Found - non-retryable
        402,  # Payment Required - non-retryable
        406,  # Not Acceptable - non-retryable
        409,  # Conflict - non-retryable
        410,  # Gone - non-retryable
    ],
)
async def test_request_throws_http_exception_for_non_retryable(status_code):
    retry_ctx = get_retry_ctx()
    mock_connection = get_mocked_telemetry_connection()

    mock_response = Mock()
    mock_response.status = status_code
    mock_response.reason = f"HTTP {status_code} Error"
    mock_response.close = AsyncMock()

    with mock.patch.object(
        aiohttp.ClientSession, "request", new_callable=AsyncMock
    ) as request_mocked:
        request_mocked.return_value = mock_response
        mock_restful = SnowflakeRestful(connection=mock_connection)

        with pytest.raises(HttpError):
            await mock_restful._request_exec_wrapper(
                aiohttp.ClientSession(),
                "GET",
                "https://example.com/path",
                {},
                None,
                retry_ctx,
            )
        mock_connection._log_telemetry.assert_called_once()
        assert_telemetry_data_for_http_error(
            mock_connection._log_telemetry.call_args[0][0], status_code
        )


@pytest.mark.parametrize(
    "status_code,expected_exception",
    [
        (INTERNAL_SERVER_ERROR, InternalServerError),  # 500
        (BAD_GATEWAY, BadGatewayError),  # 502
        (SERVICE_UNAVAILABLE, ServiceUnavailableError),  # 503
        (BAD_REQUEST, BadRequest),  # 400 - retryable
        (FORBIDDEN, ForbiddenError),
    ],
)
async def test_request_throws_http_exception_for_retryable(
    status_code, expected_exception
):
    retry_ctx = get_retry_ctx()
    mock_connection = get_mocked_telemetry_connection()

    mock_response = Mock()
    mock_response.status = status_code
    mock_response.reason = f"HTTP {status_code} Error"
    mock_response.close = AsyncMock()

    with mock.patch.object(
        aiohttp.ClientSession, "request", new_callable=AsyncMock
    ) as request_mocked:
        request_mocked.return_value = mock_response
        mock_restful = SnowflakeRestful(connection=mock_connection)

        with pytest.raises(expected_exception):
            await mock_restful._request_exec_wrapper(
                aiohttp.ClientSession(),
                "GET",
                "https://example.com/path",
                {},
                None,
                retry_ctx,
            )


def get_mocked_telemetry_connection(telemetry_enabled: bool = True) -> AsyncMock:
    mock_connection = AsyncMock()
    mock_connection.application = "test_application"
    mock_connection.telemetry_enabled = telemetry_enabled
    mock_connection.is_closed = False
    mock_connection.socket_timeout = None
    mock_connection.messages = []

    from src.snowflake.connector.errors import Error

    mock_connection.errorhandler = Error.default_errorhandler

    mock_connection._log_telemetry = AsyncMock()

    mock_telemetry = AsyncMock()
    mock_telemetry.is_closed = False
    mock_connection._telemetry = mock_telemetry

    return mock_connection
