#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from logging import getLogger


async def test_context_manager(conn_testaccount, db_parameters):
    """Tests context Manager support in Cursor."""
    logger = getLogger(__name__)

    async def tables(conn):
        async with conn.cursor() as cur:
            await cur.execute("show tables")
            name_to_idx = {elem[0]: idx for idx, elem in enumerate(cur.description)}
            async for row in cur:
                yield row[name_to_idx["name"]]

    try:
        await conn_testaccount.cursor().execute(
            "create or replace table {} (a int)".format(db_parameters["name"])
        )
        all_tables = [
            rec
            async for rec in tables(conn_testaccount)
            if rec == db_parameters["name"].upper()
        ]
        logger.info("tables: %s", all_tables)
        assert len(all_tables) == 1, "number of tables"
    finally:
        await conn_testaccount.cursor().execute(
            "drop table if exists {}".format(db_parameters["name"])
        )
