#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from unittest.mock import Mock

import snowflake.connector.telemetry
from snowflake.connector.description import CLIENT_NAME, SNOWFLAKE_CONNECTOR_VERSION
from snowflake.connector.telemetry import TelemetryField, generate_telemetry_data


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


def test_generate_telemetry_with_driver_info():
    telemetry_data = generate_telemetry_data()
    assert (
        len(telemetry_data) == 2
        and telemetry_data[TelemetryField.KEY_DRIVER_TYPE.value] == CLIENT_NAME
        and telemetry_data[TelemetryField.KEY_DRIVER_VERSION.value]
        == SNOWFLAKE_CONNECTOR_VERSION
    )

    telemetry_data = generate_telemetry_data(from_dict={})
    assert (
        len(telemetry_data) == 2
        and telemetry_data[TelemetryField.KEY_DRIVER_TYPE.value] == CLIENT_NAME
        and telemetry_data[TelemetryField.KEY_DRIVER_VERSION.value]
        == SNOWFLAKE_CONNECTOR_VERSION
    )

    telemetry_data = generate_telemetry_data(from_dict={"key": "value"})
    assert (
        len(telemetry_data) == 3
        and telemetry_data[TelemetryField.KEY_DRIVER_TYPE.value] == CLIENT_NAME
        and telemetry_data[TelemetryField.KEY_DRIVER_VERSION.value]
        == SNOWFLAKE_CONNECTOR_VERSION
        and telemetry_data["key"] == "value"
    )

    telemetry_data = generate_telemetry_data(
        from_dict={
            TelemetryField.KEY_DRIVER_TYPE.value: "CUSTOM_CLIENT_NAME",
            TelemetryField.KEY_DRIVER_VERSION.value: "1.2.3",
            "key": "value",
        }
    )
    assert (
        len(telemetry_data) == 3
        and telemetry_data[TelemetryField.KEY_DRIVER_TYPE.value] == "CUSTOM_CLIENT_NAME"
        and telemetry_data[TelemetryField.KEY_DRIVER_VERSION.value] == "1.2.3"
        and telemetry_data["key"] == "value"
    )
