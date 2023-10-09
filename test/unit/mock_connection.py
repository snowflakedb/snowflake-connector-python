#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from unittest.mock import MagicMock


def mock_connection():
    connection = MagicMock()
    connection._login_timeout = 120
    connection.login_timeout = 120
    connection._network_timeout = None
    connection.network_timeout = None
    connection._socket_timeout = None
    connection.socket_timeout = None
    connection.backoff_mode = None
    connection.backoff_base = None
    connection.backoff_factor = None
    connection.backoff_enable_jitter = None
    return connection
