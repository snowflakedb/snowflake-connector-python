#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#


async def test_reuse_cursor(conn_cnx, db_parameters):
    """Ensures only the last executed command/query's result sets are returned."""
    async with conn_cnx() as cnx:
        c = cnx.cursor()
        await c.execute(
            "create or replace table {name}(c1 string)".format(
                name=db_parameters["name"]
            )
        )
        try:
            await c.execute(
                "insert into {name} values('123'),('456'),('678')".format(
                    name=db_parameters["name"]
                )
            )
            await c.execute("show tables")
            await c.execute("select current_date()")
            rec = await c.fetchone()
            assert len(rec) == 1, "number of records is wrong"
            await c.execute(
                "select * from {name} order by 1".format(name=db_parameters["name"])
            )
            recs = await c.fetchall()
            assert c.description[0][0] == "C1", "fisrt column name"
            assert len(recs) == 3, "number of records is wrong"
        finally:
            await c.execute(
                "drop table if exists {name}".format(name=db_parameters["name"])
            )
