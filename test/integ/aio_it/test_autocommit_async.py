#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import snowflake.connector.aio


async def exe0(cnx, sql):
    return await cnx.cursor().execute(sql)


async def _run_autocommit_off(cnx, db_parameters):
    """Runs autocommit off test.

    Args:
        cnx: The database connection context.
        db_parameters: Database parameters.
    """

    async def exe(cnx, sql):
        return await cnx.cursor().execute(sql.format(name=db_parameters["name"]))

    await exe(
        cnx,
        """
INSERT INTO {name} VALUES(True), (False), (False)
""",
    )
    res = await (
        await exe0(
            cnx,
            """
SELECT CURRENT_TRANSACTION()
""",
        )
    ).fetchone()
    assert res[0] is not None
    res = await (
        await exe(
            cnx,
            """
SELECT COUNT(*) FROM {name} WHERE c1
""",
        )
    ).fetchone()
    assert res[0] == 1
    res = await (
        await exe(
            cnx,
            """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""",
        )
    ).fetchone()
    assert res[0] == 2
    await cnx.rollback()
    res = await (
        await exe0(
            cnx,
            """
SELECT CURRENT_TRANSACTION()
""",
        )
    ).fetchone()
    assert res[0] is None
    res = await (
        await exe(
            cnx,
            """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""",
        )
    ).fetchone()
    assert res[0] == 0
    await exe(
        cnx,
        """
INSERT INTO {name} VALUES(True), (False), (False)
""",
    )
    await cnx.commit()
    res = await (
        await exe(
            cnx,
            """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""",
        )
    ).fetchone()
    assert res[0] == 2
    await cnx.rollback()
    res = await (
        await exe(
            cnx,
            """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""",
        )
    ).fetchone()
    assert res[0] == 2


async def _run_autocommit_on(cnx, db_parameters):
    """Run autocommit on test.

    Args:
        cnx: The database connection context.
        db_parameters: Database parameters.
    """

    async def exe(cnx, sql):
        return await cnx.cursor().execute(sql.format(name=db_parameters["name"]))

    await exe(
        cnx,
        """
INSERT INTO {name} VALUES(True), (False), (False)
""",
    )
    await cnx.rollback()
    res = await (
        await exe(
            cnx,
            """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""",
        )
    ).fetchone()
    assert res[0] == 4


async def test_autocommit_attribute(conn_cnx, db_parameters):
    """Tests autocommit attribute.

    Args:
        conn_cnx: The database connection context.
        db_parameters: Database parameters.
    """

    async def exe(cnx, sql):
        return await cnx.cursor().execute(sql.format(name=db_parameters["name"]))

    async with conn_cnx() as cnx:
        await exe(
            cnx,
            """
CREATE TABLE {name} (c1 boolean)
""",
        )
        try:
            await cnx.autocommit(False)
            await _run_autocommit_off(cnx, db_parameters)
            await cnx.autocommit(True)
            await _run_autocommit_on(cnx, db_parameters)
        finally:
            await exe(
                cnx,
                """
DROP TABLE IF EXISTS {name}
        """,
            )


async def test_autocommit_parameters(db_parameters):
    """Tests autocommit parameter.

    Args:
        db_parameters: Database parameters.
    """

    async def exe(cnx, sql):
        return await cnx.cursor().execute(sql.format(name=db_parameters["name"]))

    async with snowflake.connector.aio.SnowflakeConnection(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        protocol=db_parameters["protocol"],
        schema=db_parameters["schema"],
        database=db_parameters["database"],
        autocommit=False,
    ) as cnx:
        await exe(
            cnx,
            """
CREATE TABLE {name} (c1 boolean)
""",
        )
        await _run_autocommit_off(cnx, db_parameters)

    async with snowflake.connector.aio.SnowflakeConnection(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        protocol=db_parameters["protocol"],
        schema=db_parameters["schema"],
        database=db_parameters["database"],
        autocommit=True,
    ) as cnx:
        await _run_autocommit_on(cnx, db_parameters)
        await exe(
            cnx,
            """
DROP TABLE IF EXISTS {name}
""",
        )
