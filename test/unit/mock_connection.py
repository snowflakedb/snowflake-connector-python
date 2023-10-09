#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from unittest.mock import MagicMock


def mock_connection(
    login_timeout=120,
    network_timeout=None,
    socket_timeout=None,
):
    connection = MagicMock()

    connection._login_timeout = login_timeout
    connection.login_timeout = login_timeout

    connection._network_timeout = network_timeout
    connection.network_timeout = network_timeout

    connection._socket_timeout = socket_timeout
    connection.socket_timeout = socket_timeout

    connection.backoff_mode = None
    connection.backoff_base = None
    connection.backoff_factor = None
    connection.backoff_enable_jitter = None

    return connection
