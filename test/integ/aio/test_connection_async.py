#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pytest

from snowflake.connector.aio import SnowflakeConnection

pytestmark = pytest.mark.asyncio


async def test_basic(db_parameters):
    """Basic Connection test without schema."""
    cnx = SnowflakeConnection(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        database=db_parameters["database"],
        protocol=db_parameters["protocol"],
        timezone="UTC",
    )
    await cnx.connect()
    cursor = cnx.cursor()
    await cursor.execute("select 1")
    assert await cursor.fetchone() == (1,)
    assert cnx, "invalid cnx"
    await cnx.close()
