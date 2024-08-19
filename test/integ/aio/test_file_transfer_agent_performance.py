#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pytest

pytestmark = pytest.mark.asyncio


async def test_put_and_get_single_small_file(aio_connection):
    await aio_connection.connect()
    aio_connection.cursor()


async def test_put_and_get_multiple_small_file(aio_connection):
    await aio_connection.connect()
    aio_connection.cursor()
