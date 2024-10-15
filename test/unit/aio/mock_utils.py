#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import asyncio
from unittest.mock import AsyncMock, MagicMock

import aiohttp

from snowflake.connector.auth.by_plugin import DEFAULT_AUTH_CLASS_TIMEOUT
from snowflake.connector.connection import DEFAULT_BACKOFF_POLICY


def mock_async_request_with_action(next_action, sleep=None):
    async def mock_request(*args, **kwargs):
        if sleep is not None:
            await asyncio.sleep(sleep)
        if next_action == "RETRY":
            return MagicMock(
                status=503,
                close=lambda: None,
            )
        elif next_action == "ERROR":
            raise aiohttp.ClientConnectionError()

    return mock_request


def mock_connection(
    login_timeout=DEFAULT_AUTH_CLASS_TIMEOUT,
    network_timeout=None,
    socket_timeout=None,
    backoff_policy=DEFAULT_BACKOFF_POLICY,
    disable_saml_url_check=False,
):
    return AsyncMock(
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
