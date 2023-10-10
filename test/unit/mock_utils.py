#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import time
from unittest.mock import MagicMock

from snowflake.connector.constants import BackoffMode
from snowflake.connector.vendored.requests.exceptions import ConnectionError


def mock_connection(
    login_timeout=120,
    network_timeout=None,
    socket_timeout=None,
    backoff_mode=None,
    backoff_base=None,
    backoff_cap=None,
    backoff_factor=None,
    backoff_enable_jitter=None,
):
    connection = MagicMock()

    connection._login_timeout = login_timeout
    connection.login_timeout = login_timeout

    connection._network_timeout = network_timeout
    connection.network_timeout = network_timeout

    connection._socket_timeout = socket_timeout
    connection.socket_timeout = socket_timeout

    connection.backoff_mode = (
        BackoffMode[backoff_mode.upper()] if backoff_mode is not None else None
    )
    connection.backoff_base = backoff_base
    connection.backoff_cap = backoff_cap
    connection.backoff_factor = backoff_factor
    connection.backoff_enable_jitter = backoff_enable_jitter

    return connection


def mock_request_with_action(next_action, sleep=None):
    def mock_request(*args, **kwargs):
        if sleep is not None:
            time.sleep(sleep)
        if next_action == "RETRY":
            response = MagicMock()
            response.status_code = 503
            response.close = lambda: None
            return response
        elif next_action == "ERROR":
            raise ConnectionError()

    return mock_request
