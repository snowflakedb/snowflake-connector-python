#!/usr/bin/env python
from __future__ import annotations

from unittest import mock
from unittest.mock import Mock

import pytest

import snowflake.connector.telemetry
from snowflake.connector.description import CLIENT_NAME, SNOWFLAKE_CONNECTOR_VERSION
from src.snowflake.connector.errorcode import ER_OCSP_RESPONSE_UNAVAILABLE
from src.snowflake.connector.errors import RevocationCheckError
from src.snowflake.connector.network import SnowflakeRestful
from src.snowflake.connector.telemetry import TelemetryData, TelemetryField


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
    client = snowflake.connector.telemetry.TelemetryClient(rest, 2)
    return client, rest_call


def test_telemetry_simple_flush():
    """Tests that metrics are properly enqueued and sent to telemetry."""
    client, rest_call = get_client_and_mock()

    client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 3000))
    assert rest_call.call_count == 1


def test_telemetry_close():
    """Tests that remaining metrics are flushed on close."""
    client, rest_call = get_client_and_mock()

    client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    client.close()
    assert rest_call.call_count == 1
    assert client.is_closed


def test_telemetry_close_empty():
    """Tests that no calls are made on close if there are no metrics to flush."""
    client, rest_call = get_client_and_mock()

    client.close()
    assert rest_call.call_count == 0
    assert client.is_closed


def test_telemetry_send_batch():
    """Tests that metrics are sent with the send_batch method."""
    client, rest_call = get_client_and_mock()

    client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    client.send_batch()
    assert rest_call.call_count == 1


def test_telemetry_send_batch_empty():
    """Tests that send_batch does nothing when there are no metrics to send."""
    client, rest_call = get_client_and_mock()

    client.send_batch()
    assert rest_call.call_count == 0


def test_telemetry_send_batch_clear():
    """Tests that send_batch clears the first batch and will not send anything on a second call."""
    client, rest_call = get_client_and_mock()

    client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    client.send_batch()
    assert rest_call.call_count == 1

    client.send_batch()
    assert rest_call.call_count == 1


def test_telemetry_auto_disable():
    """Tests that the client will automatically disable itself if a request fails."""
    client, rest_call = get_client_and_mock()
    rest_call.return_value = {"success": False}

    client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert client.is_enabled()

    client.send_batch()
    assert not client.is_enabled()


def test_telemetry_add_batch_disabled():
    """Tests that the client will not add logs if disabled."""
    client, _ = get_client_and_mock()

    client.disable()
    client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))

    assert client.buffer_size() == 0


def test_telemetry_send_batch_disabled():
    """Tests that the client will not send logs if disabled."""
    client, rest_call = get_client_and_mock()

    client.add_log_to_batch(snowflake.connector.telemetry.TelemetryData({}, 2000))
    assert client.buffer_size() == 1

    client.disable()

    client.send_batch()
    assert client.buffer_size() == 1
    assert rest_call.call_count == 0


def test_generate_telemetry_data_dict_with_basic_info():
    assert snowflake.connector.telemetry.generate_telemetry_data_dict() == {
        snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_TYPE.value: CLIENT_NAME,
        snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_VERSION.value: SNOWFLAKE_CONNECTOR_VERSION,
        snowflake.connector.telemetry.TelemetryField.KEY_SOURCE.value: CLIENT_NAME,
    }

    assert snowflake.connector.telemetry.generate_telemetry_data_dict(from_dict={}) == {
        snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_TYPE.value: CLIENT_NAME,
        snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_VERSION.value: SNOWFLAKE_CONNECTOR_VERSION,
        snowflake.connector.telemetry.TelemetryField.KEY_SOURCE.value: CLIENT_NAME,
    }

    assert snowflake.connector.telemetry.generate_telemetry_data_dict(
        from_dict={"key": "value"}
    ) == {
        snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_TYPE.value: CLIENT_NAME,
        snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_VERSION.value: SNOWFLAKE_CONNECTOR_VERSION,
        snowflake.connector.telemetry.TelemetryField.KEY_SOURCE.value: CLIENT_NAME,
        "key": "value",
    }

    assert snowflake.connector.telemetry.generate_telemetry_data_dict(
        from_dict={
            snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_TYPE.value: "CUSTOM_CLIENT_NAME",
            snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_VERSION.value: "1.2.3",
            "key": "value",
        }
    ) == {
        snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_TYPE.value: "CUSTOM_CLIENT_NAME",
        snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_VERSION.value: "1.2.3",
        snowflake.connector.telemetry.TelemetryField.KEY_SOURCE.value: CLIENT_NAME,
        "key": "value",
    }

    mock_connection = Mock()
    mock_connection.application = "test_application"
    assert snowflake.connector.telemetry.generate_telemetry_data_dict(
        from_dict={
            snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_TYPE.value: "CUSTOM_CLIENT_NAME",
            snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_VERSION.value: "1.2.3",
            "key": "value",
        },
        connection=mock_connection,
    ) == {
        snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_TYPE.value: "CUSTOM_CLIENT_NAME",
        snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_VERSION.value: "1.2.3",
        snowflake.connector.telemetry.TelemetryField.KEY_SOURCE.value: mock_connection.application,
        "key": "value",
    }


def test_generate_telemetry_data():
    telemetry_data = (
        snowflake.connector.telemetry.TelemetryData.from_telemetry_data_dict(
            from_dict={}, timestamp=123
        )
    )
    assert (
        telemetry_data.message
        == {
            snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_TYPE.value: CLIENT_NAME,
            snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_VERSION.value: SNOWFLAKE_CONNECTOR_VERSION,
            snowflake.connector.telemetry.TelemetryField.KEY_SOURCE.value: CLIENT_NAME,
        }
        and telemetry_data.timestamp == 123
    )

    mock_connection = Mock()
    mock_connection.application = "test_application"
    telemetry_data = (
        snowflake.connector.telemetry.TelemetryData.from_telemetry_data_dict(
            from_dict={},
            timestamp=123,
            connection=mock_connection,
        )
    )
    assert (
        telemetry_data.message
        == {
            snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_TYPE.value: CLIENT_NAME,
            snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_VERSION.value: SNOWFLAKE_CONNECTOR_VERSION,
            snowflake.connector.telemetry.TelemetryField.KEY_SOURCE.value: mock_connection.application,
        }
        and telemetry_data.timestamp == 123
    )

    telemetry_data = (
        snowflake.connector.telemetry.TelemetryData.from_telemetry_data_dict(
            from_dict={"key": "value"},
            timestamp=123,
            connection=mock_connection,
        )
    )
    assert (
        telemetry_data.message
        == {
            snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_TYPE.value: CLIENT_NAME,
            snowflake.connector.telemetry.TelemetryField.KEY_DRIVER_VERSION.value: SNOWFLAKE_CONNECTOR_VERSION,
            snowflake.connector.telemetry.TelemetryField.KEY_SOURCE.value: mock_connection.application,
            "key": "value",
        }
        and telemetry_data.timestamp == 123
    )


def test_raising_error_generates_telemetry_event_when_connection_is_present():
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


def test_raising_error_with_send_telemetry_off_does_not_generate_telemetry_event_when_connection_is_present():
    mock_connection = get_mocked_telemetry_connection()

    with pytest.raises(RevocationCheckError):
        raise RevocationCheckError(
            msg="Response unavailable",
            errno=ER_OCSP_RESPONSE_UNAVAILABLE,
            connection=mock_connection,
            send_telemetry=False,
        )

    mock_connection._log_telemetry.assert_not_called()


def test_request_throws_revocation_check_error():
    retry_ctx = Mock()
    retry_ctx.current_retry_count = 0
    retry_ctx.timeout = 10
    retry_ctx.add_retry_params.return_value = "https://example.com"

    mock_connection = get_mocked_telemetry_connection()

    with mock.patch.object(SnowflakeRestful, "_request_exec") as _request_exec_mocked:
        _request_exec_mocked.side_effect = RevocationCheckError(
            msg="Response unavailable", errno=ER_OCSP_RESPONSE_UNAVAILABLE
        )
        mock_restful = SnowflakeRestful(connection=mock_connection)
        with pytest.raises(RevocationCheckError):
            mock_restful._request_exec_wrapper(
                None,
                None,
                None,
                None,
                None,
                retry_ctx,
            )
        mock_restful._connection._log_telemetry.assert_called_once()
        assert_telemetry_data_for_revocation_check_error(
            mock_connection._log_telemetry.call_args[0][0]
        )


def get_mocked_telemetry_connection(telemetry_enabled: bool = True) -> Mock:
    mock_connection = Mock()
    mock_connection.application = "test_application"
    mock_connection.telemetry_enabled = telemetry_enabled
    mock_connection.is_closed = False

    mock_connection._log_telemetry = Mock()

    mock_telemetry = Mock()
    mock_telemetry.is_closed = False
    mock_connection._telemetry = mock_telemetry

    return mock_connection


def assert_telemetry_data_for_revocation_check_error(telemetry_data: TelemetryData):
    assert telemetry_data.message[TelemetryField.KEY_DRIVER_TYPE.value] == CLIENT_NAME
    assert (
        telemetry_data.message[TelemetryField.KEY_DRIVER_VERSION.value]
        == SNOWFLAKE_CONNECTOR_VERSION
    )
    assert telemetry_data.message[TelemetryField.KEY_SOURCE.value] == "test_application"
    assert (
        telemetry_data.message[TelemetryField.KEY_TYPE.value]
        == TelemetryField.OCSP_EXCEPTION.value
    )
    assert telemetry_data.message[TelemetryField.KEY_ERROR_NUMBER.value] == str(
        ER_OCSP_RESPONSE_UNAVAILABLE
    )
    assert (
        telemetry_data.message[TelemetryField.KEY_EXCEPTION.value]
        == "RevocationCheckError"
    )
    assert (
        "Response unavailable"
        in telemetry_data.message[TelemetryField.KEY_ERROR_MESSAGE.value]
    )
    assert TelemetryField.KEY_STACKTRACE.value in telemetry_data.message
    assert TelemetryField.KEY_REASON.value in telemetry_data.message
