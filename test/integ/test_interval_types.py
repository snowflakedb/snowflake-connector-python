#!/usr/bin/env python
from __future__ import annotations

from datetime import timedelta

import numpy
import pytest

pytestmark = pytest.mark.skipolddriver  # old test driver tests won't run this module


@pytest.mark.parametrize("use_numpy", [True, False])
@pytest.mark.parametrize("result_format", ["json", "arrow"])
def test_select_year_month_interval(conn_cnx, use_numpy, result_format):
    cases = ["0-0", "1-2", "-1-3", "999999999-11", "-999999999-11"]
    expected = [0, 14, -15, 11_999_999_999, -11_999_999_999]
    if use_numpy:
        expected = [numpy.timedelta64(e, "M") for e in expected]
    else:
        expected = ["+0-00", "+1-02", "-1-03", "+999999999-11", "-999999999-11"]

    table = "test_arrow_day_time_interval"
    values = "(" + "),(".join([f"'{c}'" for c in cases]) + ")"
    with conn_cnx(numpy=use_numpy) as conn:
        cursor = conn.cursor()
        cursor.execute(
            f"alter session set python_connector_query_result_format='{result_format}'"
        )

        cursor.execute("alter session set feature_interval_types=enabled")
        cursor.execute(f"create or replace table {table} (c1 interval year to month)")
        cursor.execute(f"insert into {table} values {values}")
        result = conn.cursor().execute(f"select * from {table}").fetchall()
        result = [r[0] for r in result]
        assert result == expected


@pytest.mark.skip(
    reason="SNOW-1878635: Add support for day-time interval in ArrowStreamWriter"
)
@pytest.mark.parametrize("use_numpy", [True, False])
@pytest.mark.parametrize("result_format", ["json", "arrow"])
def test_select_day_time_interval(conn_cnx, use_numpy, result_format):
    cases = [
        "0 0:0:0.0",
        "12 3:4:5.678",
        "-1 2:3:4.567",
        "99999 23:59:59.999999",
        "-99999 23:59:59.999999",
    ]
    expected = [
        timedelta(days=0),
        timedelta(days=12, hours=3, minutes=4, seconds=5.678),
        -timedelta(days=1, hours=2, minutes=3, seconds=4.567),
        timedelta(days=99999, hours=23, minutes=59, seconds=59.999999),
        -timedelta(days=99999, hours=23, minutes=59, seconds=59.999999),
    ]
    if use_numpy:
        expected = [numpy.timedelta64(e) for e in expected]

    table = "test_arrow_day_time_interval"
    values = "(" + "),(".join([f"'{c}'" for c in cases]) + ")"
    with conn_cnx(numpy=use_numpy) as conn:
        cursor = conn.cursor()
        cursor.execute(
            f"alter session set python_connector_query_result_format='{result_format}'"
        )

        cursor.execute("alter session set feature_interval_types=enabled")
        cursor.execute(
            f"create or replace table {table} (c1 interval day(5) to second)"
        )
        cursor.execute(f"insert into {table} values {values}")
        result = conn.cursor().execute(f"select * from {table}").fetchall()
        result = [r[0] for r in result]
        assert result == expected
