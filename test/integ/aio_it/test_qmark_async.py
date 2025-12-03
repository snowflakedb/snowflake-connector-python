#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

from snowflake.connector import errors


async def test_qmark_paramstyle(conn_cnx, db_parameters):
    """Tests that binding question marks is not supported by default."""
    try:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa STRING, bb STRING)".format(name=db_parameters["name"])
            )
            await cnx.cursor().execute(
                "INSERT INTO {name} VALUES('?', '?')".format(name=db_parameters["name"])
            )
            async for rec in await cnx.cursor().execute(
                "SELECT * FROM {name}".format(name=db_parameters["name"])
            ):
                assert rec[0] == "?", "First column value"
                with pytest.raises(errors.ProgrammingError):
                    await cnx.cursor().execute(
                        "INSERT INTO {name} VALUES(?,?)".format(
                            name=db_parameters["name"]
                        )
                    )
    finally:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(name=db_parameters["name"])
            )


async def test_numeric_paramstyle(conn_cnx, db_parameters):
    """Tests that binding numeric positional style is not supported."""
    try:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa STRING, bb STRING)".format(name=db_parameters["name"])
            )
            await cnx.cursor().execute(
                "INSERT INTO {name} VALUES(':1', ':2')".format(
                    name=db_parameters["name"]
                )
            )
            async for rec in await cnx.cursor().execute(
                "SELECT * FROM {name}".format(name=db_parameters["name"])
            ):
                assert rec[0] == ":1", "First column value"
                with pytest.raises(errors.ProgrammingError):
                    await cnx.cursor().execute(
                        "INSERT INTO {name} VALUES(:1,:2)".format(
                            name=db_parameters["name"]
                        )
                    )
    finally:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(name=db_parameters["name"])
            )


@pytest.mark.internal
async def test_qmark_paramstyle_enabled(negative_conn_cnx, db_parameters):
    """Enable qmark binding."""
    import snowflake.connector

    snowflake.connector.paramstyle = "qmark"
    try:
        async with negative_conn_cnx() as cnx:
            await cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa STRING, bb STRING)".format(name=db_parameters["name"])
            )
            await cnx.cursor().execute(
                "INSERT INTO {name} VALUES(?, ?)".format(name=db_parameters["name"]),
                ("test11", "test12"),
            )
            ret = await (
                await cnx.cursor().execute(
                    "select * from {name}".format(name=db_parameters["name"])
                )
            ).fetchone()
            assert ret[0] == "test11"
            assert ret[1] == "test12"
    finally:
        async with negative_conn_cnx() as cnx:
            await cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(name=db_parameters["name"])
            )
        snowflake.connector.paramstyle = "pyformat"

    # After changing back to pyformat, binding qmark should fail.
    try:
        async with negative_conn_cnx() as cnx:
            await cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa STRING, bb STRING)".format(name=db_parameters["name"])
            )
            with pytest.raises(TypeError):
                await cnx.cursor().execute(
                    "INSERT INTO {name} VALUES(?, ?)".format(
                        name=db_parameters["name"]
                    ),
                    ("test11", "test12"),
                )
    finally:
        async with negative_conn_cnx() as cnx:
            await cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(name=db_parameters["name"])
            )


async def test_binding_datetime_qmark(conn_cnx, db_parameters):
    """Ensures datetime can bound."""
    import datetime

    import snowflake.connector

    snowflake.connector.paramstyle = "qmark"
    try:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa TIMESTAMP_NTZ)".format(name=db_parameters["name"])
            )
            days = 2
            inserts = tuple((datetime.datetime(2018, 1, i + 1),) for i in range(days))
            await cnx.cursor().executemany(
                "INSERT INTO {name} VALUES(?)".format(name=db_parameters["name"]),
                inserts,
            )
            ret = await (
                await cnx.cursor().execute(
                    "SELECT * FROM {name} ORDER BY 1".format(name=db_parameters["name"])
                )
            ).fetchall()
            for i in range(days):
                assert ret[i][0] == inserts[i][0]
    finally:
        async with conn_cnx() as cnx:
            await cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(name=db_parameters["name"])
            )


async def test_binding_none(conn_cnx):
    import snowflake.connector

    original = snowflake.connector.paramstyle
    snowflake.connector.paramstyle = "qmark"

    async with conn_cnx() as con:
        try:
            table_name = "foo"
            await con.cursor().execute(f"CREATE TABLE {table_name}(bar text)")
            await con.cursor().execute(f"INSERT INTO {table_name} VALUES (?)", [None])
        finally:
            await con.cursor().execute(f"DROP TABLE {table_name}")
            snowflake.connector.paramstyle = original
