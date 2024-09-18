#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import asyncio
from unittest.mock import MagicMock

import aiohttp


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
