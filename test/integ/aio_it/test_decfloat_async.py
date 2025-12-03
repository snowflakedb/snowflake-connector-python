#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import decimal
from decimal import Decimal

import numpy
import pytest

import snowflake.connector


@pytest.mark.skipolddriver
async def test_decfloat_bindings(conn_cnx):
    # set required decimal precision
    decimal.getcontext().prec = 38
    original_style = snowflake.connector.paramstyle
    snowflake.connector.paramstyle = "qmark"
    try:
        async with conn_cnx() as cnx:
            cur = cnx.cursor()
            await cur.execute("select ?", [("DECFLOAT", Decimal("-1234e4000"))])
            ret = await cur.fetchone()
            assert isinstance(ret[0], Decimal)
            assert ret[0] == Decimal("-1234e4000")

            await cur.execute("select ?", [("DECFLOAT", -1e3)])
            ret = await cur.fetchone()
            assert isinstance(ret[0], Decimal)
            assert ret[0] == Decimal("-1e3")

            # test 38 digits
            await cur.execute(
                "select ?",
                [("DECFLOAT", Decimal("12345678901234567890123456789012345678"))],
            )
            ret = await cur.fetchone()
            assert isinstance(ret[0], Decimal)
            assert ret[0] == Decimal("12345678901234567890123456789012345678")

            # test w/o explicit type specification
            await cur.execute("select ?", [-1e3])
            ret = await cur.fetchone()
            assert isinstance(ret[0], float)

            await cur.execute("select ?", [Decimal("-1e3")])
            ret = await cur.fetchone()
            assert isinstance(ret[0], int)
    finally:
        snowflake.connector.paramstyle = original_style


@pytest.mark.skipolddriver
async def test_decfloat_from_compiler(conn_cnx):
    # set required decimal precision
    decimal.getcontext().prec = 38
    # test both result formats
    for fmt in ["json", "arrow"]:
        async with conn_cnx(
            session_parameters={
                "PYTHON_CONNECTOR_QUERY_RESULT_FORMAT": fmt,
                "use_cached_result": "false",
            }
        ) as cnx:
            cur = cnx.cursor()
            # test endianess
            await cur.execute("SELECT 555::decfloat")
            ret = await cur.fetchone()
            assert isinstance(ret[0], Decimal)
            assert ret[0] == Decimal("555")

            # test with decimal separator
            await cur.execute("SELECT 123456789.12345678::decfloat")
            ret = await cur.fetchone()
            assert isinstance(ret[0], Decimal)
            assert ret[0] == Decimal("123456789.12345678")

            # test 38 digits
            await cur.execute(
                "SELECT '12345678901234567890123456789012345678'::decfloat"
            )
            ret = await cur.fetchone()
            assert isinstance(ret[0], Decimal)
            assert ret[0] == Decimal("12345678901234567890123456789012345678")

    async with conn_cnx(numpy=True) as cnx:
        cur = cnx.cursor()
        await cur.execute("SELECT 1.234::decfloat", None)
        ret = await cur.fetchone()
        assert isinstance(ret[0], numpy.float64)
        assert ret[0] == numpy.float64("1.234")
