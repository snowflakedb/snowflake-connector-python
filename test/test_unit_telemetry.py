#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Snowflake Computing Inc. All right reserved.
#
from snowflake.connector.compat import PY2
from snowflake.connector.telemetry import *

if PY2:
    from mock import Mock
else:
    from unittest.mock import Mock


def test_telemetry_data_to_dict():
    """
    Test that TelemetryData instances are properly converted to dicts
    """
    assert TelemetryData({}, 2000).to_dict() == {'message': {}, 'timestamp': '2000'}

    d = {'type': 'test', 'query_id': '1', 'value': 20}
    assert TelemetryData(d, 1234).to_dict() == {'message': d, 'timestamp': '1234'}


def get_client_and_mock():
    rest_call = Mock()
    rest_call.return_value = {u'success': True}
    rest = Mock()
    rest.attach_mock(rest_call, 'request')
    client = TelemetryClient(rest, 2)
    return (client, rest_call)


def test_telemetry_simple_flush():
    """
    Test that metrics are properly enqueued and sent to telemetry
    """
    client, rest_call = get_client_and_mock()

    client.add_log_to_batch(TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    client.add_log_to_batch(TelemetryData({}, 3000))
    assert rest_call.call_count == 1


def test_telemetry_close():
    """
    Test that remaining metrics are flushed on close
    """
    client, rest_call = get_client_and_mock()

    client.add_log_to_batch(TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    client.close()
    assert rest_call.call_count == 1
    assert client.is_closed()


def test_telemetry_close_empty():
    """
    Test that no calls are made on close if there are no metrics to flush
    """
    client, rest_call = get_client_and_mock()

    client.close()
    assert rest_call.call_count == 0
    assert client.is_closed()


def test_telemetry_send_batch():
    """
    Test that metrics are sent with the send_batch method
    """
    client, rest_call = get_client_and_mock()

    client.add_log_to_batch(TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    client.send_batch()
    assert rest_call.call_count == 1


def test_telemetry_send_batch_empty():
    """
    Test that send_batch does nothing when there are no metrics to send
    """
    client, rest_call = get_client_and_mock()

    client.send_batch()
    assert rest_call.call_count == 0


def test_telemetry_send_batch_clear():
    """
    Test that send_batch clears the first batch and will not send anything
    on a second call
    """
    client, rest_call = get_client_and_mock()

    client.add_log_to_batch(TelemetryData({}, 2000))
    assert rest_call.call_count == 0

    client.send_batch()
    assert rest_call.call_count == 1

    client.send_batch()
    assert rest_call.call_count == 1


def test_telemetry_auto_disable():
    """
    Test that the client will automatically disable itself if a request fails
    """
    client, rest_call = get_client_and_mock()
    rest_call.return_value = {u'success': False}

    client.add_log_to_batch(TelemetryData({}, 2000))
    assert client.is_enabled()

    client.send_batch()
    assert not client.is_enabled()


def test_telemetry_add_batch_disabled():
    """
    Test that the client will not add logs if disabled
    """
    client, _ = get_client_and_mock()

    client.disable()
    client.add_log_to_batch(TelemetryData({}, 2000))

    assert client.buffer_size() == 0


def test_telemetry_send_batch_disabled():
    """
    Test that the client will not send logs if disabled
    """
    client, rest_call = get_client_and_mock()

    client.add_log_to_batch(TelemetryData({}, 2000))
    assert client.buffer_size() == 1

    client.disable()

    client.send_batch()
    assert client.buffer_size() == 1
    assert rest_call.call_count == 0