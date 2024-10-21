#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

from snowflake.connector.errors import ProgrammingError


async def test_binding_security(conn_cnx, db_parameters):
    """SQL Injection Tests."""
    try:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa INT, bb STRING)".format(name=db_parameters["name"])
            )
            await cnx.cursor().execute(
                "INSERT INTO {name} VALUES(%s, %s)".format(name=db_parameters["name"]),
                (1, "test1"),
            )
            await cnx.cursor().execute(
                "INSERT INTO {name} VALUES(%(aa)s, %(bb)s)".format(
                    name=db_parameters["name"]
                ),
                {"aa": 2, "bb": "test2"},
            )
            async for _rec in await cnx.cursor().execute(
                "SELECT * FROM {name} ORDER BY 1 DESC".format(
                    name=db_parameters["name"]
                )
            ):
                break
            assert _rec[0] == 2, "First column"
            assert _rec[1] == "test2", "Second column"
            async for _rec in await cnx.cursor().execute(
                "SELECT * FROM {name} WHERE aa=%s".format(name=db_parameters["name"]),
                (1,),
            ):
                break
            assert _rec[0] == 1, "First column"
            assert _rec[1] == "test1", "Second column"

            # SQL injection safe test
            # Good Example
            with pytest.raises(ProgrammingError):
                await cnx.cursor().execute(
                    "SELECT * FROM {name} WHERE aa=%s".format(
                        name=db_parameters["name"]
                    ),
                    ("1 or aa>0",),
                )

            with pytest.raises(ProgrammingError):
                await cnx.cursor().execute(
                    "SELECT * FROM {name} WHERE aa=%(aa)s".format(
                        name=db_parameters["name"]
                    ),
                    {"aa": "1 or aa>0"},
                )

            # Bad Example in application. DON'T DO THIS
            c = cnx.cursor()
            await c.execute(
                "SELECT * FROM {name} WHERE aa=%s".format(name=db_parameters["name"])
                % ("1 or aa>0",)
            )
            rec = await c.fetchall()
            assert len(rec) == 2, "not raising error unlike the previous one."
    finally:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "drop table if exists {name}".format(name=db_parameters["name"])
            )


async def test_binding_list(conn_cnx, db_parameters):
    """SQL binding list type for IN."""
    try:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa INT, bb STRING)".format(name=db_parameters["name"])
            )
            await cnx.cursor().execute(
                "INSERT INTO {name} VALUES(%s, %s)".format(name=db_parameters["name"]),
                (1, "test1"),
            )
            await cnx.cursor().execute(
                "INSERT INTO {name} VALUES(%(aa)s, %(bb)s)".format(
                    name=db_parameters["name"]
                ),
                {"aa": 2, "bb": "test2"},
            )
            await cnx.cursor().execute(
                "INSERT INTO {name} VALUES(3, 'test3')".format(
                    name=db_parameters["name"]
                )
            )
            async for _rec in await cnx.cursor().execute(
                """
SELECT * FROM {name} WHERE aa IN (%s) ORDER BY 1 DESC
""".format(
                    name=db_parameters["name"]
                ),
                ([1, 3],),
            ):
                break
            assert _rec[0] == 3, "First column"
            assert _rec[1] == "test3", "Second column"

            async for _rec in await cnx.cursor().execute(
                "SELECT * FROM {name} WHERE aa=%s".format(name=db_parameters["name"]),
                (1,),
            ):
                break
            assert _rec[0] == 1, "First column"
            assert _rec[1] == "test1", "Second column"

            await cnx.cursor().execute(
                """
SELECT * FROM {name} WHERE aa IN (%s) ORDER BY 1 DESC
""".format(
                    name=db_parameters["name"]
                ),
                ((1,),),
            )

    finally:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "drop table if exists {name}".format(name=db_parameters["name"])
            )


@pytest.mark.internal
async def test_unsupported_binding(negative_conn_cnx, db_parameters):
    """Unsupported data binding."""
    try:
        async with negative_conn_cnx() as cnx:
            await cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa INT, bb STRING)".format(name=db_parameters["name"])
            )
            await cnx.cursor().execute(
                "INSERT INTO {name} VALUES(%s, %s)".format(name=db_parameters["name"]),
                (1, "test1"),
            )

            sql = "select count(*) from {name} where aa=%s".format(
                name=db_parameters["name"]
            )

            async with cnx.cursor() as cur:
                rec = await (await cur.execute(sql, (1,))).fetchone()
                assert rec[0] is not None, "no value is returned"

            # dict
            with pytest.raises(ProgrammingError):
                await cnx.cursor().execute(sql, ({"value": 1},))
    finally:
        async with negative_conn_cnx() as cnx:
            await cnx.cursor().execute(
                "drop table if exists {name}".format(name=db_parameters["name"])
            )
