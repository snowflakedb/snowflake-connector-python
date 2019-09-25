# encoding=utf-8
# !/usr/bin/env python
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import pytest

from snowflake.connector.telemetry_oob import TelemetryService
from snowflake.connector.errors import RevocationCheckError
from snowflake.connector.sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
from snowflake.connector.errorcode import ER_FAILED_TO_REQUEST

DEV_CONFIG = {
    'host': 'localhost',
    'port': 8080,
    'account': 'testAccount',
    'user': 'test',
    'password': 'ShouldNotShowUp',
    'protocol': 'http'
}
telemetry_data = {}
exception = RevocationCheckError("Test OCSP Revocation error")
event_type = "Test OCSP Exception"
stack_trace = [
    'Traceback (most recent call last):\n',
    '  File "<doctest...>", line 10, in <module>\n    lumberjack()\n',
    '  File "<doctest...>", line 4, in lumberjack\n    bright_side_of_death()\n',
    '  File "<doctest...>", line 7, in bright_side_of_death\n    return tuple()[0]\n',
    'IndexError: tuple index out of range\n'
]

event_name = "HttpRetryTimeout"
url = "http://localhost:8080/queries/v1/query-request?request_guid=a54a3d70-abf2-4576-bb6f-ddf23999491a"
method = "POST"


@pytest.fixture()
def telemetry_setup(request):
    """
    Sets up the telemetry service by enabling it and flushing any entries
    """
    telemetry = TelemetryService.get_instance()
    telemetry.update_context(DEV_CONFIG)
    telemetry.enable()
    telemetry.flush()


def test_telemetry_oob_simple_flush(telemetry_setup):
    """
    Tests capturing and sending a simple OCSP Exception message
    """
    telemetry = TelemetryService.get_instance()

    telemetry.log_ocsp_exception(event_type, telemetry_data, exception=exception, stack_trace=stack_trace)
    assert telemetry.size() == 1
    telemetry.flush()
    assert telemetry.size() == 0


def test_telemetry_oob_urgent(telemetry_setup):
    """
    Tests sending an urgent OCSP Exception message
    """
    telemetry = TelemetryService.get_instance()

    telemetry.log_ocsp_exception(event_type, telemetry_data, exception=exception, stack_trace=stack_trace, urgent=True)
    assert telemetry.size() == 0


def test_telemetry_oob_close(telemetry_setup):
    """
    Tests closing the Telemetry Service when there are still messages in the queue
    """
    telemetry = TelemetryService.get_instance()

    telemetry.log_ocsp_exception(event_type, telemetry_data, exception=exception, stack_trace=stack_trace)
    assert telemetry.size() == 1
    telemetry.close()
    assert telemetry.size() == 0


def test_telemetry_oob_close_empty(telemetry_setup):
    """
    Tests closing the Telemetry Service when the queue is empty
    """
    telemetry = TelemetryService.get_instance()

    assert telemetry.size() == 0
    telemetry.close()
    assert telemetry.size() == 0


def test_telemetry_oob_log_when_disabled(telemetry_setup):
    """
    Tests trying to log to the telemetry service when it is disabled
    """
    telemetry = TelemetryService.get_instance()

    assert telemetry.size() == 0
    telemetry.disable()
    telemetry.log_ocsp_exception(event_type, telemetry_data, exception=exception, stack_trace=stack_trace)
    assert telemetry.size() == 0
    telemetry.enable()


def test_telemetry_oob_http_log(telemetry_setup):
    """
    Tests sending a simple HTTP request telemetry event
    """
    telemetry = TelemetryService.get_instance()

    telemetry.log_http_request_error(event_name, url, method, SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED, ER_FAILED_TO_REQUEST,
                               exception=exception, stack_trace=stack_trace)
    assert telemetry.size() == 1
    telemetry.flush()
    assert telemetry.size() == 0


def test_telemetry_oob_http_log_urgent(telemetry_setup):
    """
    Tests sending an urgent HTTP request telemetry event
    """
    telemetry = TelemetryService.get_instance()

    assert telemetry.size() == 0
    telemetry.log_http_request_error(event_name, url, method, SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED, ER_FAILED_TO_REQUEST,
                               exception=exception, stack_trace=stack_trace, urgent=True)
    assert telemetry.size() == 0
