#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import time
from unittest.mock import MagicMock

try:
    from snowflake.connector.vendored.requests.exceptions import ConnectionError
except ImportError:
    from requests.exceptions import ConnectionError

try:
    from snowflake.connector.auth.by_plugin import DEFAULT_AUTH_CLASS_TIMEOUT
except ImportError:
    DEFAULT_AUTH_CLASS_TIMEOUT = 120


def zero_backoff():
    while True:
        yield 0


try:
    from snowflake.connector.connection import DEFAULT_BACKOFF_POLICY
except ImportError:
    DEFAULT_BACKOFF_POLICY = zero_backoff


def mock_connection(
    login_timeout=DEFAULT_AUTH_CLASS_TIMEOUT,
    network_timeout=None,
    socket_timeout=None,
    backoff_policy=DEFAULT_BACKOFF_POLICY,
    disable_saml_url_check=False,
):
    return MagicMock(
        _login_timeout=login_timeout,
        login_timeout=login_timeout,
        _network_timeout=network_timeout,
        network_timeout=network_timeout,
        _socket_timeout=socket_timeout,
        socket_timeout=socket_timeout,
        _backoff_policy=backoff_policy,
        backoff_policy=backoff_policy,
        _disable_saml_url_check=disable_saml_url_check,
    )


def mock_request_with_action(next_action, sleep=None):
    def mock_request(*args, **kwargs):
        if sleep is not None:
            time.sleep(sleep)
        if next_action == "RETRY":
            return MagicMock(
                status_code=503,
                close=lambda: None,
            )
        elif next_action == "ERROR":
            raise ConnectionError()

    return mock_request
