#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
from logging import getLogger

import pytest

import snowflake.connector.aio
from snowflake.connector.errors import ProgrammingError

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except Exception:
    CONNECTION_PARAMETERS_ADMIN = {}

logger = getLogger(__name__)


async def _concurrent_insert(meta):
    """Concurrent insert method."""
    cnx = snowflake.connector.aio.SnowflakeConnection(
        user=meta["user"],
        password=meta["password"],
        host=meta["host"],
        port=meta["port"],
        account=meta["account"],
        database=meta["database"],
        schema=meta["schema"],
        timezone="UTC",
        protocol="http",
    )
    await cnx.connect()
    try:
        await cnx.cursor().execute("use warehouse {}".format(meta["warehouse"]))
        table = meta["table"]
        sql = f"insert into {table} values(%(c1)s, %(c2)s)"
        logger.debug(sql)
        await cnx.cursor().execute(
            sql,
            {
                "c1": meta["idx"],
                "c2": "test string " + meta["idx"],
            },
        )
        meta["success"] = True
        logger.debug("Succeeded process #%s", meta["idx"])
    except Exception:
        logger.exception("failed to insert into a table [%s]", table)
        meta["success"] = False
    finally:
        await cnx.close()
    return meta


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="The user needs a privilege of create warehouse.",
)
async def test_concurrent_insert(conn_cnx, db_parameters):
    """Concurrent insert tests. Inserts block on the one that's running."""
    number_of_tasks = 22  # change this to increase the concurrency
    expected_success_runs = number_of_tasks - 1
    cnx_array = []

    try:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                """
create or replace warehouse {}
warehouse_type=standard
warehouse_size=small
""".format(
                    db_parameters["name_wh"]
                )
            )
            sql = """
create or replace table {name} (c1 integer, c2 string)
""".format(
                name=db_parameters["name"]
            )
            await cnx.cursor().execute(sql)
            for i in range(number_of_tasks):
                cnx_array.append(
                    {
                        "host": db_parameters["host"],
                        "port": db_parameters["port"],
                        "user": db_parameters["user"],
                        "password": db_parameters["password"],
                        "account": db_parameters["account"],
                        "database": db_parameters["database"],
                        "schema": db_parameters["schema"],
                        "table": db_parameters["name"],
                        "idx": str(i),
                        "warehouse": db_parameters["name_wh"],
                    }
                )
            tasks = [
                asyncio.create_task(_concurrent_insert(cnx_item))
                for cnx_item in cnx_array
            ]
            results = await asyncio.gather(*tasks)
            success = 0
            for record in results:
                success += 1 if record["success"] else 0

            # 21 threads or more
            assert success >= expected_success_runs, "Number of success run"

            c = cnx.cursor()
            sql = "select * from {name} order by 1".format(name=db_parameters["name"])
            await c.execute(sql)
            for rec in c:
                logger.debug(rec)
            await c.close()

    finally:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "drop table if exists {}".format(db_parameters["name"])
            )
            await cnx.cursor().execute(
                "drop warehouse if exists {}".format(db_parameters["name_wh"])
            )


async def _concurrent_insert_using_connection(meta):
    connection = meta["connection"]
    idx = meta["idx"]
    name = meta["name"]
    try:
        await connection.cursor().execute(
            f"INSERT INTO {name} VALUES(%s, %s)",
            (idx, f"test string{idx}"),
        )
    except ProgrammingError as e:
        if e.errno != 619:  # SQL Execution Canceled
            raise


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="The user needs a privilege of create warehouse.",
)
async def test_concurrent_insert_using_connection(conn_cnx, db_parameters):
    """Concurrent insert tests using the same connection."""
    try:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                """
create or replace warehouse {}
warehouse_type=standard
warehouse_size=small
""".format(
                    db_parameters["name_wh"]
                )
            )
            await cnx.cursor().execute(
                """
CREATE OR REPLACE TABLE {name} (c1 INTEGER, c2 STRING)
""".format(
                    name=db_parameters["name"]
                )
            )
            number_of_tasks = 5
            metas = []
            for i in range(number_of_tasks):
                metas.append(
                    {
                        "connection": cnx,
                        "idx": i,
                        "name": db_parameters["name"],
                    }
                )
            tasks = [
                asyncio.create_task(_concurrent_insert_using_connection(meta))
                for meta in metas
            ]
            await asyncio.gather(*tasks)
            cnt = 0
            async for _ in await cnx.cursor().execute(
                "SELECT * FROM {name} ORDER BY 1".format(name=db_parameters["name"])
            ):
                cnt += 1
            assert (
                cnt <= number_of_tasks
            ), "Number of records should be less than the number of threads"
            assert cnt > 0, "Number of records should be one or more number of threads"
    finally:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "drop table if exists {}".format(db_parameters["name"])
            )
            await cnx.cursor().execute(
                "drop warehouse if exists {}".format(db_parameters["name_wh"])
            )
