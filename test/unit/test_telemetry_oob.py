#!/usr/bin/env python
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from snowflake.connector.errors import RevocationCheckError
from snowflake.connector.telemetry_oob import TelemetryService

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


def test_telemetry_oob_disabled():
    telemetry = TelemetryService.get_instance()
    assert not telemetry.enabled
    telemetry.enable()
    assert not telemetry.enabled
    telemetry.disable()
    assert not telemetry.enabled
    telemetry.enable()
    telemetry.log_ocsp_exception(
        event_type, telemetry_data, exception=exception, stack_trace=stack_trace
    )
    assert telemetry.queue.empty()
    telemetry.log_general_exception(event_name, {})
    assert telemetry.queue.empty()
    telemetry.log_http_request_error(event_name, url, method, "error", "error")
    assert telemetry.queue.empty()


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
