#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from test.integ.test_converter_null import NUMERIC_VALUES

import snowflake.connector.aio
from snowflake.connector.converter import ZERO_EPOCH
from snowflake.connector.converter_null import SnowflakeNoConverterToPython


async def test_converter_no_converter_to_python(db_parameters):
    """Tests no converter.

    This should not translate the Snowflake internal data representation to the Python native types.
    """
    async with snowflake.connector.aio.SnowflakeConnection(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        database=db_parameters["database"],
        schema=db_parameters["schema"],
        protocol=db_parameters["protocol"],
        timezone="UTC",
        converter_class=SnowflakeNoConverterToPython,
    ) as con:
        await con.cursor().execute(
            """
    alter session set python_connector_query_result_format='JSON'
    """
        )

        ret = await (
            await con.cursor().execute(
                """
    select  current_timestamp(),
            1::NUMBER,
            2.0::FLOAT,
            'test1'
    """
            )
        ).fetchone()
        assert isinstance(ret[0], str)
        assert NUMERIC_VALUES.match(ret[0])
        assert isinstance(ret[1], str)
        assert NUMERIC_VALUES.match(ret[1])
        await con.cursor().execute(
            "create or replace table testtb(c1 timestamp_ntz(6))"
        )
        try:
            current_time = datetime.now(timezone.utc).replace(tzinfo=None)
            # binding value should have no impact
            await con.cursor().execute(
                "insert into testtb(c1) values(%s)", (current_time,)
            )
            ret = (
                await (await con.cursor().execute("select * from testtb")).fetchone()
            )[0]
            assert ZERO_EPOCH + timedelta(seconds=(float(ret))) == current_time
        finally:
            await con.cursor().execute("drop table if exists testtb")
