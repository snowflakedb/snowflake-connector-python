#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from datetime import datetime

import pytest
import pytz

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
async def test_binding_security(conn_cnx):
    """Tests binding statement parameters."""
    expected_qa_mode_datetime = datetime(1967, 6, 23, 7, 0, 0, 123000, pytz.UTC)

    async with conn_cnx() as cnx:
        await cnx.cursor().execute("alter session set timezone='UTC'")
        async with cnx.cursor() as cur:
            await cur.execute("show databases like 'TESTDB'")
            rec = await cur.fetchone()
            assert rec[0] != expected_qa_mode_datetime

        async with cnx.cursor() as cur:
            await cur.execute(
                "show databases like 'TESTDB'",
                _statement_params={
                    "QA_MODE": True,
                },
            )
            rec = await cur.fetchone()
            assert rec[0] == expected_qa_mode_datetime

        async with cnx.cursor() as cur:
            await cur.execute("show databases like 'TESTDB'")
            rec = await cur.fetchone()
            assert rec[0] != expected_qa_mode_datetime
