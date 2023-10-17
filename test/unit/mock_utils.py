#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import time
from unittest.mock import MagicMock

try:
    from snowflake.connector.vendored.requests.exceptions import ConnectionError
except ImportError:
    from requests.exceptions import ConnectionError


def mock_connection(
    login_timeout=120,
    request_timeout=None,
    socket_timeout=None,
    backoff_policy=None,
):
    connection = MagicMock()

    connection._login_timeout = login_timeout
    connection.login_timeout = login_timeout

    connection._request_timeout = request_timeout
    connection.request_timeout = request_timeout

    connection._socket_timeout = socket_timeout
    connection.socket_timeout = socket_timeout

    connection._backoff_policy = backoff_policy
    connection.backoff_policy = backoff_policy

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