#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import snowflake.connector.aio


async def test_transaction(conn_cnx, db_parameters):
    """Tests transaction API."""
    async with conn_cnx() as cnx:
        await cnx.cursor().execute(
            "create table {name} (c1 int)".format(name=db_parameters["name"])
        )
        await cnx.cursor().execute(
            "insert into {name}(c1) "
            "values(1234),(3456)".format(name=db_parameters["name"])
        )
        c = cnx.cursor()
        await c.execute("select * from {name}".format(name=db_parameters["name"]))
        total = 0
        async for rec in c:
            total += rec[0]
        assert total == 4690, "total integer"

        #
        await cnx.cursor().execute("begin")
        await cnx.cursor().execute(
            "insert into {name}(c1) values(5678),(7890)".format(
                name=db_parameters["name"]
            )
        )
        c = cnx.cursor()
        await c.execute("select * from {name}".format(name=db_parameters["name"]))
        total = 0
        async for rec in c:
            total += rec[0]
        assert total == 18258, "total integer"
        await cnx.rollback()

        await c.execute("select * from {name}".format(name=db_parameters["name"]))
        total = 0
        async for rec in c:
            total += rec[0]
        assert total == 4690, "total integer"

        #
        await cnx.cursor().execute("begin")
        await cnx.cursor().execute(
            "insert into {name}(c1) values(2345),(6789)".format(
                name=db_parameters["name"]
            )
        )
        c = cnx.cursor()
        await c.execute("select * from {name}".format(name=db_parameters["name"]))
        total = 0
        async for rec in c:
            total += rec[0]
        assert total == 13824, "total integer"
        await cnx.commit()
        await cnx.rollback()
        c = cnx.cursor()
        await c.execute("select * from {name}".format(name=db_parameters["name"]))
        total = 0
        async for rec in c:
            total += rec[0]
        assert total == 13824, "total integer"


async def test_connection_context_manager(request, db_parameters):
    db_config = {
        "protocol": db_parameters["protocol"],
        "account": db_parameters["account"],
        "user": db_parameters["user"],
        "password": db_parameters["password"],
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "database": db_parameters["database"],
        "schema": db_parameters["schema"],
        "timezone": "UTC",
    }

    async def fin():
        async with snowflake.connector.aio.SnowflakeConnection(**db_config) as cnx:
            await cnx.cursor().execute(
                """
DROP TABLE IF EXISTS {name}
""".format(
                    name=db_parameters["name"]
                )
            )

    try:
        async with snowflake.connector.aio.SnowflakeConnection(**db_config) as cnx:
            await cnx.autocommit(False)
            await cnx.cursor().execute(
                """
CREATE OR REPLACE TABLE {name} (cc1 int)
""".format(
                    name=db_parameters["name"]
                )
            )
            await cnx.cursor().execute(
                """
INSERT INTO {name} VALUES(1),(2),(3)
""".format(
                    name=db_parameters["name"]
                )
            )
            ret = await (
                await cnx.cursor().execute(
                    """
SELECT SUM(cc1) FROM {name}
""".format(
                        name=db_parameters["name"]
                    )
                )
            ).fetchone()
            assert ret[0] == 6
            await cnx.commit()
            await cnx.cursor().execute(
                """
INSERT INTO {name} VALUES(4),(5),(6)
""".format(
                    name=db_parameters["name"]
                )
            )
            ret = await (
                await cnx.cursor().execute(
                    """
SELECT SUM(cc1) FROM {name}
""".format(
                        name=db_parameters["name"]
                    )
                )
            ).fetchone()
            assert ret[0] == 21
            await cnx.cursor().execute(
                """
SELECT WRONG SYNTAX QUERY
"""
            )
            raise Exception("Failed to cause the syntax error")
    except snowflake.connector.Error:
        # syntax error should be caught here
        # and the last change must have been rollbacked
        async with snowflake.connector.aio.SnowflakeConnection(**db_config) as cnx:
            ret = await (
                await cnx.cursor().execute(
                    """
SELECT SUM(cc1) FROM {name}
""".format(
                        name=db_parameters["name"]
                    )
                )
            ).fetchone()
            assert ret[0] == 6
    yield
    await fin()
