#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_binding_fetching_boolean(async_conn_cnx, db_parameters):
    try:
        async with async_conn_cnx() as cnx:
            await cnx.cursor().execute(
                """
create or replace table {name} (c1 boolean, c2 integer)
""".format(
                    name=db_parameters["name"]
                )
            )

        async with async_conn_cnx() as cnx:
            await cnx.cursor().execute(
                """
insert into {name} values(%s,%s), (%s,%s), (%s,%s)
""".format(
                    name=db_parameters["name"]
                ),
                (True, 1, False, 2, True, 3),
            )
            results = await (
                await cnx.cursor().execute(
                    """
select * from {name} order by 1""".format(
                        name=db_parameters["name"]
                    )
                )
            ).fetchall()
            assert not results[0][0]
            assert results[1][0]
            assert results[2][0]
            results = await (
                await cnx.cursor().execute(
                    """
select c1 from {name} where c2=2
""".format(
                        name=db_parameters["name"]
                    )
                )
            ).fetchall()
            assert not results[0][0]

            # SNOW-15905: boolean support
            results = await (
                await cnx.cursor().execute(
                    """
SELECT CASE WHEN (null LIKE trim(null)) THEN null  ELSE null END
"""
                )
            ).fetchall()
            assert not results[0][0]

    finally:
        async with async_conn_cnx() as cnx:
            await cnx.cursor().execute(
                """
drop table if exists {name}
""".format(
                    name=db_parameters["name"]
                )
            )


async def test_boolean_from_compiler(async_conn_cnx):
    async with async_conn_cnx() as cnx:
        ret = await (await cnx.cursor().execute("SELECT true")).fetchone()
        assert ret[0]

        ret = await (await cnx.cursor().execute("SELECT false")).fetchone()
        assert not ret[0]
