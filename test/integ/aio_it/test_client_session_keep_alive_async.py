#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio

import pytest

import snowflake.connector.aio

try:
    from parameters import CONNECTION_PARAMETERS
except ImportError:
    CONNECTION_PARAMETERS = {}

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}


@pytest.fixture
async def token_validity_test_values(request):
    async with snowflake.connector.aio.SnowflakeConnection(
        **CONNECTION_PARAMETERS_ADMIN
    ) as cnx:
        print("[INFO] Setting token validity to test values")
        await cnx.cursor().execute(
            """
ALTER SYSTEM SET
    MASTER_TOKEN_VALIDITY=30,
    SESSION_TOKEN_VALIDITY=10
"""
        )

    async def fin():
        async with snowflake.connector.aio.SnowflakeConnection(
            **CONNECTION_PARAMETERS_ADMIN
        ) as cnx:
            print("[INFO] Reverting token validity")
            await cnx.cursor().execute(
                """
ALTER SYSTEM SET
    MASTER_TOKEN_VALIDITY=default,
    SESSION_TOKEN_VALIDITY=default
"""
            )

    request.addfinalizer(fin)
    return None


@pytest.mark.skipif(
    not (CONNECTION_PARAMETERS_ADMIN),
    reason="ADMIN connection parameters must be provided.",
)
async def test_client_session_keep_alive(token_validity_test_values):
    test_connection_parameters = CONNECTION_PARAMETERS.copy()
    print("[INFO] Connected")
    test_connection_parameters["client_session_keep_alive"] = True
    async with snowflake.connector.aio.SnowflakeConnection(
        **test_connection_parameters
    ) as con:
        print("[INFO] Running a query. Ensuring a connection is valid.")
        await con.cursor().execute("select 1")
        print("[INFO] Sleeping 15s")
        await asyncio.sleep(15)
        print(
            "[INFO] Running a query. Both master and session tokens must "
            "have been renewed by token request"
        )
        await con.cursor().execute("select 1")
        print("[INFO] Sleeping 40s")
        await asyncio.sleep(40)
        print(
            "[INFO] Running a query. Master token must have been renewed "
            "by the heartbeat"
        )
        await con.cursor().execute("select 1")
