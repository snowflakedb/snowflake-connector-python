#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

import snowflake.connector.errorcode
import snowflake.connector.telemetry
from snowflake.connector.description import CLIENT_NAME, SNOWFLAKE_CONNECTOR_VERSION
from snowflake.connector.errorcode import ER_FAILED_TO_REQUEST
from snowflake.connector.errors import RevocationCheckError
from snowflake.connector.ocsp_snowflake import OCSPTelemetryData
from snowflake.connector.sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
from snowflake.connector.telemetry_oob import TelemetryService

DEV_CONFIG = {
    "host": "localhost",
    "port": 8080,
    "account": "testAccount",
    "user": "test",
    "password": "ShouldNotShowUp",
    "protocol": "http",
}
TEST_RACE_CONDITION_THREAD_COUNT = 2
TEST_RACE_CONDITION_DELAY_SECONDS = 1
telemetry_data = {}
exception = RevocationCheckError("Test OCSP Revocation error")
event_type = "Test OCSP Exception"
stack_trace = [
    "Traceback (most recent call last):\n",
    '  File "<doctest...>", line 10, in <module>\n    lumberjack()\n',
    '  File "<doctest...>", line 4, in lumberjack\n    bright_side_of_death()\n',
    '  File "<doctest...>", line 7, in bright_side_of_death\n    return tuple()[0]\n',
    "IndexError: tuple index out of range\n",
]

event_name = "HttpRetryTimeout"
url = "http://localhost:8080/queries/v1/query-request?request_guid=a54a3d70-abf2-4576-bb6f-ddf23999491a"
method = "POST"


@pytest.fixture()
def telemetry_setup(request):
    """Sets up the telemetry service by enabling it and flushing any entries."""
    telemetry = TelemetryService.get_instance()
    telemetry.update_context(DEV_CONFIG)
    telemetry.enable()
    telemetry.flush()


def test_telemetry_oob_simple_flush(telemetry_setup, caplog):
    """Tests capturing and sending a simple OCSP Exception message."""
    telemetry = TelemetryService.get_instance()
    telemetry.flush()  # clear the buffer first
    telemetry.log_ocsp_exception(
        event_type, telemetry_data, exception=exception, stack_trace=stack_trace
    )
    assert telemetry.size() == 1
    caplog.set_level(logging.DEBUG, "snowflake.connector.telemetry_oob")
    telemetry.flush()
    assert (
        "Failed to generate a JSON dump from the passed in telemetry OOB events"
        not in caplog.text
    )
    # since pytests can run test in parallel and TelemetryService is a singleton, other tests
    # might encounter error logged into the queue of the OOB Telemetry simultaneously
    # leading to assert telemetry.size() == 0 failure
    # here we check that the OCSP exception event in the test is flushed
    for event in list(telemetry.queue.queue):
        assert "OCSPException" not in event.name


@pytest.mark.flaky(reruns=3)
def test_telemetry_oob_urgent(telemetry_setup):
    """Tests sending an urgent OCSP Exception message."""
    telemetry = TelemetryService.get_instance()

    telemetry.log_ocsp_exception(
        event_type,
        telemetry_data,
        exception=exception,
        stack_trace=stack_trace,
        urgent=True,
    )
    assert telemetry.size() == 0


def test_telemetry_oob_close(telemetry_setup):
    """Tests closing the Telemetry Service when there are still messages in the queue."""
    telemetry = TelemetryService.get_instance()

    telemetry.log_ocsp_exception(
        event_type, telemetry_data, exception=exception, stack_trace=stack_trace
    )
    assert telemetry.size() == 1
    telemetry.close()
    assert telemetry.size() == 0


def test_telemetry_oob_close_empty(telemetry_setup):
    """Tests closing the Telemetry Service when the queue is empty."""
    telemetry = TelemetryService.get_instance()

    assert telemetry.size() == 0
    telemetry.close()
    assert telemetry.size() == 0


def test_telemetry_oob_log_when_disabled(telemetry_setup):
    """Tests trying to log to the telemetry service when it is disabled."""
    telemetry = TelemetryService.get_instance()

    assert telemetry.size() == 0
    telemetry.disable()
    telemetry.log_ocsp_exception(
        event_type, telemetry_data, exception=exception, stack_trace=stack_trace
    )
    assert telemetry.size() == 0
    telemetry.enable()


def test_telemetry_oob_http_log(telemetry_setup):
    """Tests sending a simple HTTP request telemetry event."""
    telemetry = TelemetryService.get_instance()

    telemetry.log_http_request_error(
        event_name,
        url,
        method,
        SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
        ER_FAILED_TO_REQUEST,
        exception=exception,
        stack_trace=stack_trace,
    )
    assert telemetry.size() == 1
    telemetry.flush()
    assert telemetry.size() == 0


def test_telemetry_oob_error_code_mapping():
    """Tests that all OCSP error codes have a corresponding Telemetry sub event type."""
    ec_dict = snowflake.connector.errorcode.__dict__
    for ec, ec_val in ec_dict.items():
        if not ec.startswith("__") and ec not in ("annotations",):
            if 254000 <= ec_val < 255000:
                assert ec_val in OCSPTelemetryData.ERROR_CODE_MAP


@pytest.mark.flaky(reruns=3)
def test_telemetry_oob_http_log_urgent(telemetry_setup):
    """Tests sending an urgent HTTP request telemetry event."""
    telemetry = TelemetryService.get_instance()

    assert telemetry.size() == 0
    telemetry.log_http_request_error(
        event_name,
        url,
        method,
        SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
        ER_FAILED_TO_REQUEST,
        exception=exception,
        stack_trace=stack_trace,
        urgent=True,
    )
    assert telemetry.size() == 0


def test_generate_telemetry_with_driver_info():
    assert snowflake.connector.telemetry.generate_telemetry_data_dict(
        is_oob_telemetry=True
    ) == {
        snowflake.connector.telemetry.TelemetryField.KEY_OOB_DRIVER.value: CLIENT_NAME,
        snowflake.connector.telemetry.TelemetryField.KEY_OOB_VERSION.value: SNOWFLAKE_CONNECTOR_VERSION,
    }

    assert snowflake.connector.telemetry.generate_telemetry_data_dict(
        from_dict={}, is_oob_telemetry=True
    ) == {
        snowflake.connector.telemetry.TelemetryField.KEY_OOB_DRIVER.value: CLIENT_NAME,
        snowflake.connector.telemetry.TelemetryField.KEY_OOB_VERSION.value: SNOWFLAKE_CONNECTOR_VERSION,
    }

    assert snowflake.connector.telemetry.generate_telemetry_data_dict(
        from_dict={"key": "value"}, is_oob_telemetry=True
    ) == {
        snowflake.connector.telemetry.TelemetryField.KEY_OOB_DRIVER.value: CLIENT_NAME,
        snowflake.connector.telemetry.TelemetryField.KEY_OOB_VERSION.value: SNOWFLAKE_CONNECTOR_VERSION,
        "key": "value",
    }

    assert snowflake.connector.telemetry.generate_telemetry_data_dict(
        from_dict={
            snowflake.connector.telemetry.TelemetryField.KEY_OOB_DRIVER.value: "CUSTOM_CLIENT_NAME",
            snowflake.connector.telemetry.TelemetryField.KEY_OOB_VERSION.value: "1.2.3",
            "key": "value",
        },
        is_oob_telemetry=True,
    ) == {
        snowflake.connector.telemetry.TelemetryField.KEY_OOB_DRIVER.value: "CUSTOM_CLIENT_NAME",
        snowflake.connector.telemetry.TelemetryField.KEY_OOB_VERSION.value: "1.2.3",
        "key": "value",
    }


class MockTelemetryService(TelemetryService):
    """Mocks a delay in the __init__ of TelemetryService to simulate a race condition"""

    def __init__(self, *args, **kwargs):
        # this delay all but guarantees enough time to catch multiple threads entering __init__
        time.sleep(TEST_RACE_CONDITION_DELAY_SECONDS)
        super().__init__(*args, **kwargs)


def test_get_instance_multithreaded():
    """Tests thread safety of multithreaded calls to TelemetryService.get_instance()"""
    TelemetryService._TelemetryService__instance = None
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(MockTelemetryService.get_instance)
            for _ in range(TEST_RACE_CONDITION_THREAD_COUNT)
        ]
        for future in futures:
            # will error if singleton constraint violated
            future.result()
