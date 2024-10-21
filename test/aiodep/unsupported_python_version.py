#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import asyncio
import sys

import snowflake.connector.aio

assert (
    sys.version_info.major == 3 and sys.version_info.minor <= 9
), "This test is only for Python 3.9 and lower"


CONNECTION_PARAMETERS = {
    "account": "test",
    "user": "test",
    "password": "test",
    "schema": "test",
    "database": "test",
    "protocol": "test",
    "host": "test.snowflakecomputing.com",
    "warehouse": "test",
    "port": 443,
    "role": "test",
}

raise ValueError("Test CI")


async def main():
    try:
        async with snowflake.connector.aio.SnowflakeConnection(**CONNECTION_PARAMETERS):
            pass
    except Exception as exc:
        assert isinstance(
            exc, RuntimeError
        ) and "Async Snowflake Python Connector requires Python 3.10+" in str(
            exc
        ), "should raise RuntimeError"


asyncio.run(main())
