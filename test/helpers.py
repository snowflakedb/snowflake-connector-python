#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Pattern, Sequence
from unittest.mock import Mock

import pytest

from snowflake.connector.compat import OK

if TYPE_CHECKING:
    import snowflake.connector.connection

try:
    from snowflake.connector.constants import QueryStatus
except ImportError:
    QueryStatus = None


def create_mock_response(status_code: int) -> Mock:
    """Create a Mock "Response" with a given status code. See `test_result_batch.py` for examples.
    Args:
        status_code: the status code of the response.
    Returns:
        A Mock object that can be used as a Mock Response in tests.
    """
    mock_resp = Mock()
    mock_resp.status_code = status_code
    mock_resp.raw = "success" if status_code == OK else "fail"
    return mock_resp


def verify_log_tuple(
    module: str,
    level: int,
    message: str | Pattern,
    log_tuples: Sequence[tuple[str, int, str]],
):
    """Convenience function to be able to search for regex patterns in log messages.

    Designed to search caplog.record_tuples.

    Notes:
        - module could be extended to take a pattern too
    """
    for _module, _level, _message in log_tuples:
        if _module == module and _level == level:
            if _message == message or (
                isinstance(message, Pattern) and message.search(_message)
            ):
                return True
    return False


def _wait_while_query_running(
    con: snowflake.connector.connection.SnowflakeConnection,
    sfqid: str,
    sleep_time: int,
    dont_cache: bool = False,
) -> None:
    """
    Checks if the provided still returns that it is still running, and if so,
    sleeps for the specified time in a while loop.
    """
    query_status = con._get_query_status if dont_cache else con.get_query_status
    while con.is_still_running(query_status(sfqid)):
        time.sleep(sleep_time)


def _wait_until_query_success(
    con: snowflake.connector.connection.SnowflakeConnection,
    sfqid: str,
    num_checks: int,
    sleep_per_check: int,
) -> None:
    for _ in range(num_checks):
        status = con.get_query_status(sfqid)
        if status == QueryStatus.SUCCESS:
            break
        time.sleep(sleep_per_check)
    else:
        pytest.fail(
            "We should have broke out of wait loop for query success."
            f"Query ID: {sfqid}"
            f"Final query status: {status}"
        )
