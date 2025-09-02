#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import decimal
import itertools
import random
import time
from datetime import datetime
from decimal import Decimal
from enum import Enum
from unittest import mock

import numpy
import pytest
import pytz
from numpy.testing import assert_equal

try:
    from snowflake.connector.constants import (
        PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT,
        IterUnit,
    )
except ImportError:
    # This is because of olddriver tests
    class IterUnit(Enum):
        ROW_UNIT = "row"
        TABLE_UNIT = "table"


try:
    from snowflake.connector.options import installed_pandas, pandas, pyarrow
except ImportError:
    installed_pandas = False
    pandas = None
    pyarrow = None

try:
    from snowflake.connector.nanoarrow_arrow_iterator import PyArrowIterator  # NOQA

    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True

SQL_ENABLE_ARROW = "alter session set python_connector_query_result_format='ARROW';"

EPSILON = 1e-8


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_num_one(conn_cnx):
    print("Test fetching one single dataframe")
    row_count = 50000
    col_count = 2
    random_seed = get_random_seed()
    sql_exec = (
        f"select seq4() as c1, uniform(1, 10, random({random_seed})) as c2 from "
        f"table(generator(rowcount=>{row_count})) order by c1, c2"
    )
    await fetch_pandas(conn_cnx, sql_exec, row_count, col_count, "one")


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_scaled_tinyint(conn_cnx):
    cases = ["NULL", 0.11, -0.11, "NULL", 1.27, -1.28, "NULL"]
    table = "test_arrow_tiny_int"
    column = "(a number(5,2))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(conn, sql_text, cases, 1, "one")
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_scaled_smallint(conn_cnx):
    cases = ["NULL", 0, 0.11, -0.11, "NULL", 32.767, -32.768, "NULL"]
    table = "test_arrow_small_int"
    column = "(a number(5,3))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(conn, sql_text, cases, 1, "one")
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_scaled_int(conn_cnx):
    cases = [
        "NULL",
        0,
        "NULL",
        0.123456789,
        -0.123456789,
        2.147483647,
        -2.147483648,
        "NULL",
    ]
    table = "test_arrow_int"
    column = "(a number(10,9))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(conn, sql_text, cases, 1, "one")
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is not installed.",
)
async def test_scaled_bigint(conn_cnx):
    cases = [
        "NULL",
        0,
        "NULL",
        "1.23456789E-10",
        "-1.23456789E-10",
        "2.147483647E-9",
        "-2.147483647E-9",
        "-1e-9",
        "1e-9",
        "1e-8",
        "-1e-8",
        "NULL",
    ]
    table = "test_arrow_big_int"
    column = "(a number(38,18))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(conn, sql_text, cases, 1, "one", epsilon=EPSILON)
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_decimal(conn_cnx):
    cases = [
        "NULL",
        0,
        "NULL",
        "10000000000000000000000000000000000000",
        "12345678901234567890123456789012345678",
        "99999999999999999999999999999999999999",
        "-1000000000000000000000000000000000000",
        "-2345678901234567890123456789012345678",
        "-9999999999999999999999999999999999999",
        "NULL",
    ]
    table = "test_arrow_decimal"
    column = "(a number(38,0))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(conn, sql_text, cases, 1, "one", data_type="decimal")
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is not installed.",
)
async def test_scaled_decimal(conn_cnx):
    cases = [
        "NULL",
        0,
        "NULL",
        "1.0000000000000000000000000000000000000",
        "1.2345678901234567890123456789012345678",
        "9.9999999999999999999999999999999999999",
        "-1.000000000000000000000000000000000000",
        "-2.345678901234567890123456789012345678",
        "-9.999999999999999999999999999999999999",
        "NULL",
    ]
    table = "test_arrow_decimal"
    column = "(a number(38,37))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(conn, sql_text, cases, 1, "one", data_type="decimal")
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is not installed.",
)
async def test_scaled_decimal_SNOW_133561(conn_cnx):
    cases = [
        "NULL",
        0,
        "NULL",
        "1.2345",
        "2.1001",
        "2.2001",
        "2.3001",
        "2.3456",
        "-9.999",
        "-1.000",
        "-3.4567",
        "3.4567",
        "4.5678",
        "5.6789",
        "-0.0012",
        "NULL",
    ]
    table = "test_scaled_decimal_SNOW_133561"
    column = "(a number(38,10))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(conn, sql_text, cases, 1, "one", data_type="float")
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_boolean(conn_cnx):
    cases = ["NULL", True, "NULL", False, True, True, "NULL", True, False, "NULL"]
    table = "test_arrow_boolean"
    column = "(a boolean)"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(conn, sql_text, cases, 1, "one")
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_double(conn_cnx):
    cases = [
        "NULL",
        # SNOW-31249
        "-86.6426540296895",
        "3.14159265359",
        # SNOW-76269
        "1.7976931348623157E308",
        "1.7E308",
        "1.7976931348623151E308",
        "-1.7976931348623151E308",
        "-1.7E308",
        "-1.7976931348623157E308",
        "NULL",
    ]
    table = "test_arrow_double"
    column = "(a double)"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(conn, sql_text, cases, 1, "one")
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_semi_struct(conn_cnx):
    sql_text = """
    select array_construct(10, 20, 30),
        array_construct(null, 'hello', 3::double, 4, 5),
        array_construct(),
        object_construct('a',1,'b','BBBB', 'c',null),
        object_construct('Key_One', parse_json('NULL'), 'Key_Two', null, 'Key_Three', 'null'),
        to_variant(3.2),
        parse_json('{ "a": null}'),
        100::variant;
    """
    res = [
        "[\n" + "  10,\n" + "  20,\n" + "  30\n" + "]",
        "[\n"
        + "  undefined,\n"
        + '  "hello",\n'
        + "  3.000000000000000e+00,\n"
        + "  4,\n"
        + "  5\n"
        + "]",
        "[]",
        "{\n" + '  "a": 1,\n' + '  "b": "BBBB"\n' + "}",
        "{\n" + '  "Key_One": null,\n' + '  "Key_Three": "null"\n' + "}",
        "3.2",
        "{\n" + '  "a": null\n' + "}",
        "100",
    ]
    async with conn_cnx() as cnx_table:
        # fetch dataframe with new arrow support
        cursor_table = cnx_table.cursor()
        await cursor_table.execute(SQL_ENABLE_ARROW)
        await cursor_table.execute(sql_text)
        df_new = await cursor_table.fetch_pandas_all()
        col_new = df_new.iloc[0]
        for j, c_new in enumerate(col_new):
            assert res[j] == c_new, (
                "{} column: original value is {}, new value is {}, "
                "values are not equal".format(j, res[j], c_new)
            )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_date(conn_cnx):
    cases = [
        "NULL",
        "2017-01-01",
        "2014-01-02",
        "2014-01-02",
        "1970-01-01",
        "1970-01-01",
        "NULL",
        "1969-12-31",
        "0200-02-27",
        "NULL",
        "0200-02-28",
        # "0200-02-29", # day is out of range
        # "0000-01-01", # year 0 is out of range
        "0001-12-31",
        "NULL",
    ]
    table = "test_arrow_date"
    column = "(a date)"
    values = ",".join(
        [f"({i}, {c})" if c == "NULL" else f"({i}, '{c}')" for i, c in enumerate(cases)]
    )
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(conn, sql_text, cases, 1, "one", data_type="date")
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
@pytest.mark.parametrize("scale", [i for i in range(10)])
async def test_time(conn_cnx, scale):
    cases = [
        "NULL",
        "00:00:51",
        "01:09:03.100000",
        "02:23:23.120000",
        "03:56:23.123000",
        "04:56:53.123400",
        "09:01:23.123450",
        "11:03:29.123456",
        # note: Python's max time precision is microsecond, rest of them will lose precision
        # "15:31:23.1234567",
        # "19:01:43.12345678",
        # "23:59:59.99999999",
        "NULL",
    ]
    table = "test_arrow_time"
    column = f"(a time({scale}))"
    values = ",".join(
        [f"({i}, {c})" if c == "NULL" else f"({i}, '{c}')" for i, c in enumerate(cases)]
    )
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(
            conn, sql_text, cases, 1, "one", data_type="time", scale=scale
        )
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
@pytest.mark.parametrize("scale", [i for i in range(10)])
async def test_timestampntz(conn_cnx, scale):
    cases = [
        "NULL",
        "1970-01-01 00:00:00",
        "1970-01-01 00:00:01",
        "1970-01-01 00:00:10",
        "2014-01-02 16:00:00",
        "2014-01-02 12:34:56",
        "2017-01-01 12:00:00.123456789",
        "2014-01-02 16:00:00.000000001",
        "NULL",
        "2014-01-02 12:34:57.1",
        "1969-12-31 23:59:59.000000001",
        "1970-01-01 00:00:00.123412423",
        "1970-01-01 00:00:01.000001",
        "1969-12-31 11:59:59.001",
        # "0001-12-31 11:59:59.11",
        # pandas._libs.tslibs.np_datetime.OutOfBoundsDatetime:
        # Out of bounds nanosecond timestamp: 1-12-31 11:59:59
        "NULL",
    ]
    table = "test_arrow_timestamp"
    column = f"(a timestampntz({scale}))"

    values = ",".join(
        [f"({i}, {c})" if c == "NULL" else f"({i}, '{c}')" for i, c in enumerate(cases)]
    )
    async with conn_cnx() as conn:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(
            conn, sql_text, cases, 1, "one", data_type="timestamp", scale=scale
        )
        await finish(conn, table)


@pytest.mark.parametrize(
    "timestamp_str",
    [
        "'1400-01-01 01:02:03.123456789'::timestamp as low_ts",
        "'9999-01-01 01:02:03.123456789789'::timestamp as high_ts",
    ],
)
async def test_timestampntz_raises_overflow(conn_cnx, timestamp_str):
    async with conn_cnx() as conn:
        r = await conn.cursor().execute(f"select {timestamp_str}")
        with pytest.raises(OverflowError, match="overflows int64 range."):
            await r.fetch_arrow_all()


async def test_timestampntz_down_scale(conn_cnx):
    async with conn_cnx() as conn:
        r = await conn.cursor().execute(
            "select '1400-01-01 01:02:03.123456'::timestamp as low_ts, '9999-01-01 01:02:03.123456'::timestamp as high_ts"
        )
        table = await r.fetch_arrow_all()
        lower_dt = table[0][0].as_py()  # type: datetime
        assert (
            lower_dt.year,
            lower_dt.month,
            lower_dt.day,
            lower_dt.hour,
            lower_dt.minute,
            lower_dt.second,
            lower_dt.microsecond,
        ) == (1400, 1, 1, 1, 2, 3, 123456)
        higher_dt = table[1][0].as_py()
        assert (
            higher_dt.year,
            higher_dt.month,
            higher_dt.day,
            higher_dt.hour,
            higher_dt.minute,
            higher_dt.second,
            higher_dt.microsecond,
        ) == (9999, 1, 1, 1, 2, 3, 123456)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
@pytest.mark.parametrize(
    "scale, timezone",
    itertools.product(
        [i for i in range(10)], ["UTC", "America/New_York", "Australia/Sydney"]
    ),
)
async def test_timestamptz(conn_cnx, scale, timezone):
    cases = [
        "NULL",
        "1971-01-01 00:00:00",
        "1971-01-11 00:00:01",
        "1971-01-01 00:00:10",
        "2014-01-02 16:00:00",
        "2014-01-02 12:34:56",
        "2017-01-01 12:00:00.123456789",
        "2014-01-02 16:00:00.000000001",
        "NULL",
        "2014-01-02 12:34:57.1",
        "1969-12-31 23:59:59.000000001",
        "1970-01-01 00:00:00.123412423",
        "1970-01-01 00:00:01.000001",
        "1969-12-31 11:59:59.001",
        # "0001-12-31 11:59:59.11",
        # pandas._libs.tslibs.np_datetime.OutOfBoundsDatetime:
        # Out of bounds nanosecond timestamp: 1-12-31 11:59:59
        "NULL",
    ]
    table = "test_arrow_timestamp"
    column = f"(a timestamptz({scale}))"
    values = ",".join(
        [f"({i}, {c})" if c == "NULL" else f"({i}, '{c}')" for i, c in enumerate(cases)]
    )
    async with conn_cnx() as conn:
        await init(conn, table, column, values, timezone=timezone)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(
            conn,
            sql_text,
            cases,
            1,
            "one",
            data_type="timestamptz",
            scale=scale,
            timezone=timezone,
        )
        await finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
@pytest.mark.parametrize(
    "scale, timezone",
    itertools.product(
        [i for i in range(10)], ["UTC", "America/New_York", "Australia/Sydney"]
    ),
)
async def test_timestampltz(conn_cnx, scale, timezone):
    cases = [
        "NULL",
        "1970-01-01 00:00:00",
        "1970-01-01 00:00:01",
        "1970-01-01 00:00:10",
        "2014-01-02 16:00:00",
        "2014-01-02 12:34:56",
        "2017-01-01 12:00:00.123456789",
        "2014-01-02 16:00:00.000000001",
        "NULL",
        "2014-01-02 12:34:57.1",
        "1969-12-31 23:59:59.000000001",
        "1970-01-01 00:00:00.123412423",
        "1970-01-01 00:00:01.000001",
        "1969-12-31 11:59:59.001",
        # "0001-12-31 11:59:59.11",
        # pandas._libs.tslibs.np_datetime.OutOfBoundsDatetime:
        # Out of bounds nanosecond timestamp: 1-12-31 11:59:59
        "NULL",
    ]
    table = "test_arrow_timestamp"
    column = f"(a timestampltz({scale}))"
    values = ",".join(
        [f"({i}, {c})" if c == "NULL" else f"({i}, '{c}')" for i, c in enumerate(cases)]
    )
    async with conn_cnx() as conn:
        await init(conn, table, column, values, timezone=timezone)
        sql_text = f"select a from {table} order by s"
        await validate_pandas(
            conn,
            sql_text,
            cases,
            1,
            "one",
            data_type="timestamp",
            scale=scale,
            timezone=timezone,
        )
        await finish(conn, table)


@pytest.mark.skipolddriver
@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_vector(conn_cnx, is_public_test):
    if is_public_test:
        pytest.xfail(
            reason="This feature hasn't been rolled out for public Snowflake deployments yet."
        )
    tests = [
        (
            "vector(int,3)",
            [
                "NULL",
                "[1,2,3]::vector(int,3)",
            ],
            ["NULL", numpy.array([1, 2, 3])],
        ),
        (
            "vector(float,3)",
            [
                "NULL",
                "[1.3,2.4,3.5]::vector(float,3)",
            ],
            ["NULL", numpy.array([1.3, 2.4, 3.5], dtype=numpy.float32)],
        ),
    ]
    for vector_type, cases, typed_cases in tests:
        table = "test_arrow_vector"
        column = f"(a {vector_type})"
        values = [f"{i}, {c}" for i, c in enumerate(cases)]
        async with conn_cnx() as conn:
            await init_with_insert_select(conn, table, column, values)
            # Test general fetches
            sql_text = f"select a from {table} order by s"
            await validate_pandas(
                conn, sql_text, typed_cases, 1, method="one", data_type=vector_type
            )

            # Test empty result sets
            cur = conn.cursor()
            await cur.execute(f"select a from {table} limit 0")
            df = await cur.fetch_pandas_all()
            assert len(df) == 0
            assert df.dtypes[0] == "object"

            await finish(conn, table)


async def validate_pandas(
    cnx_table,
    sql,
    cases,
    col_count,
    method="one",
    data_type="float",
    epsilon=None,
    scale=0,
    timezone=None,
):
    """Tests that parameters can be customized.

    Args:
        cnx_table: Connection object.
        sql: SQL command for execution.
        cases: Test cases.
        col_count: Number of columns in dataframe.
        method: If method is 'batch', we fetch dataframes in batch. If method is 'one', we fetch a single dataframe
            containing all data (Default value = 'one').
        data_type: Defines how to compare values (Default value = 'float').
        epsilon: For comparing double values (Default value = None).
        scale: For comparing time values with scale (Default value = 0).
        timezone: For comparing timestamp ltz (Default value = None).
    """

    row_count = len(cases)
    assert col_count != 0, "# of columns should be larger than 0"

    cursor_table = cnx_table.cursor()
    await cursor_table.execute(SQL_ENABLE_ARROW)
    await cursor_table.execute(sql)

    # build dataframe
    total_rows, total_batches = 0, 0
    start_time = time.time()

    if method == "one":
        df_new = await cursor_table.fetch_pandas_all()
        total_rows = df_new.shape[0]
    else:
        async for df_new in await cursor_table.fetch_pandas_batches():
            total_rows += df_new.shape[0]
            total_batches += 1
    end_time = time.time()

    print(f"new way (fetching {method}) took {end_time - start_time}s")
    if method == "batch":
        print(f"new way has # of batches : {total_batches}")
    await cursor_table.close()
    assert (
        total_rows == row_count
    ), f"there should be {row_count} rows, but {total_rows} rows"

    # verify the correctness
    # only do it when fetch one dataframe
    if method == "one":
        assert (row_count, col_count) == df_new.shape, (
            "the shape of old dataframe is {}, "
            "the shape of new dataframe is {}, "
            "shapes are not equal".format((row_count, col_count), df_new.shape)
        )

        for i in range(row_count):
            for j in range(col_count):
                c_new = df_new.iat[i, j]
                if type(cases[i]) is str and cases[i] == "NULL":
                    assert c_new is None or pandas.isnull(c_new), (
                        "{} row, {} column: original value is NULL, "
                        "new value is {}, values are not equal".format(i, j, c_new)
                    )
                else:
                    if data_type == "float":
                        c_case = float(cases[i])
                    elif data_type == "decimal":
                        c_case = Decimal(cases[i])
                    elif data_type == "date":
                        c_case = datetime.strptime(cases[i], "%Y-%m-%d").date()
                    elif data_type == "time":
                        time_str_len = 8 if scale == 0 else 9 + scale
                        c_case = cases[i].strip()[:time_str_len]
                        c_new = str(c_new).strip()[:time_str_len]
                        assert c_new == c_case, (
                            "{} row, {} column: original value is {}, "
                            "new value is {}, "
                            "values are not equal".format(i, j, cases[i], c_new)
                        )
                        break
                    elif data_type.startswith("timestamp"):
                        time_str_len = 19 if scale == 0 else 20 + scale
                        if timezone:
                            c_case = pandas.Timestamp(
                                cases[i][:time_str_len], tz=timezone
                            )
                            if data_type == "timestamptz":
                                c_case = c_case.tz_convert("UTC")
                        else:
                            c_case = pandas.Timestamp(cases[i][:time_str_len])
                        assert c_case == c_new, (
                            "{} row, {} column: original value is {}, new value is {}, "
                            "values are not equal".format(i, j, cases[i], c_new)
                        )
                        break
                    elif data_type.startswith("vector"):
                        assert numpy.array_equal(cases[i], c_new), (
                            "{} row, {} column: original value is {}, new value is {}, "
                            "values are not equal".format(i, j, cases[i], c_new)
                        )
                        continue
                    else:
                        c_case = cases[i]
                    if epsilon is None:
                        assert c_case == c_new, (
                            "{} row, {} column: original value is {}, new value is {}, "
                            "values are not equal".format(i, j, cases[i], c_new)
                        )
                    else:
                        assert abs(c_case - c_new) < epsilon, (
                            "{} row, {} column: original value is {}, "
                            "new value is {}, epsilon is {} \
                        values are not equal".format(
                                i, j, cases[i], c_new, epsilon
                            )
                        )


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_num_batch(conn_cnx):
    print("Test fetching dataframes in batch")
    row_count = 1000000
    col_count = 2
    random_seed = get_random_seed()
    sql_exec = (
        f"select seq4() as c1, uniform(1, 10, random({random_seed})) as c2 from "
        f"table(generator(rowcount=>{row_count})) order by c1, c2"
    )
    await fetch_pandas(conn_cnx, sql_exec, row_count, col_count, "batch")


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
@pytest.mark.parametrize(
    "result_format",
    ["pandas", "arrow"],
)
async def test_empty(conn_cnx, result_format):
    print("Test fetch empty dataframe")
    async with conn_cnx() as cnx:
        cursor = cnx.cursor()
        await cursor.execute(SQL_ENABLE_ARROW)
        await cursor.execute(
            "select seq4() as foo, seq4() as bar from table(generator(rowcount=>1)) limit 0"
        )
        fetch_all_fn = getattr(cursor, f"fetch_{result_format}_all")
        fetch_batches_fn = getattr(cursor, f"fetch_{result_format}_batches")
        result = await fetch_all_fn()
        if result_format == "pandas":
            assert len(list(result)) == 2
            assert list(result)[0] == "FOO"
            assert list(result)[1] == "BAR"
        else:
            assert result is None

        await cursor.execute(
            "select seq4() as foo from table(generator(rowcount=>1)) limit 0"
        )
        df_count = 0
        async for _ in await fetch_batches_fn():
            df_count += 1
        assert df_count == 0


def get_random_seed():
    random.seed(datetime.now().timestamp())
    return random.randint(0, 10000)


async def fetch_pandas(conn_cnx, sql, row_count, col_count, method="one"):
    """Tests that parameters can be customized.

    Args:
        conn_cnx: Connection object.
        sql: SQL command for execution.
        row_count: Number of total rows combining all dataframes.
        col_count: Number of columns in dataframe.
        method: If method is 'batch', we fetch dataframes in batch. If method is 'one', we fetch a single dataframe
            containing all data (Default value = 'one').
    """
    assert row_count != 0, "# of rows should be larger than 0"
    assert col_count != 0, "# of columns should be larger than 0"

    async with conn_cnx() as conn:
        # fetch dataframe by fetching row by row
        cursor_row = conn.cursor()
        await cursor_row.execute(SQL_ENABLE_ARROW)
        await cursor_row.execute(sql)

        # build dataframe
        # actually its exec time would be different from `pandas.read_sql()` via sqlalchemy as most people use
        # further perf test can be done separately
        start_time = time.time()
        rows = 0
        if method == "one":
            df_old = pandas.DataFrame(
                await cursor_row.fetchall(),
                columns=[f"c{i}" for i in range(col_count)],
            )
        else:
            print("use fetchmany")
            while True:
                dat = await cursor_row.fetchmany(10000)
                if not dat:
                    break
                else:
                    df_old = pandas.DataFrame(
                        dat, columns=[f"c{i}" for i in range(col_count)]
                    )
                    rows += df_old.shape[0]
        end_time = time.time()
        print(f"The original way took {end_time - start_time}s")
        await cursor_row.close()

        # fetch dataframe with new arrow support
        cursor_table = conn.cursor()
        await cursor_table.execute(SQL_ENABLE_ARROW)
        await cursor_table.execute(sql)

        # build dataframe
        total_rows, total_batches = 0, 0
        start_time = time.time()
        if method == "one":
            df_new = await cursor_table.fetch_pandas_all()
            total_rows = df_new.shape[0]
        else:
            async for df_new in await cursor_table.fetch_pandas_batches():
                total_rows += df_new.shape[0]
                total_batches += 1
        end_time = time.time()
        print(f"new way (fetching {method}) took {end_time - start_time}s")
        if method == "batch":
            print(f"new way has # of batches : {total_batches}")
        await cursor_table.close()
        assert total_rows == row_count, "there should be {} rows, but {} rows".format(
            row_count, total_rows
        )

        # verify the correctness
        # only do it when fetch one dataframe
        if method == "one":
            assert (
                df_old.shape == df_new.shape
            ), "the shape of old dataframe is {}, the shape of new dataframe is {}, \
                                     shapes are not equal".format(
                df_old.shape, df_new.shape
            )

            for i in range(row_count):
                col_old = df_old.iloc[i]
                col_new = df_new.iloc[i]
                for j, (c_old, c_new) in enumerate(zip(col_old, col_new)):
                    assert c_old == c_new, (
                        f"{i} row, {j} column: old value is {c_old}, new value "
                        f"is {c_new} values are not equal"
                    )
        else:
            assert (
                rows == total_rows
            ), f"the number of rows are not equal {rows} vs {total_rows}"


async def init(json_cnx, table, column, values, timezone=None):
    cursor_json = json_cnx.cursor()
    if timezone is not None:
        await cursor_json.execute(f"ALTER SESSION SET TIMEZONE = '{timezone}'")
    column_with_seq = column[0] + "s number, " + column[1:]
    await cursor_json.execute(f"create or replace table {table} {column_with_seq}")
    await cursor_json.execute(f"insert into {table} values {values}")


async def init_with_insert_select(json_cnx, table, column, rows, timezone=None):
    cursor_json = json_cnx.cursor()
    if timezone is not None:
        await cursor_json.execute(f"ALTER SESSION SET TIMEZONE = '{timezone}'")
    column_with_seq = column[0] + "s number, " + column[1:]
    await cursor_json.execute(f"create or replace table {table} {column_with_seq}")
    for row in rows:
        await cursor_json.execute(f"insert into {table} select {row}")


async def finish(json_cnx, table):
    cursor_json = json_cnx.cursor()
    await cursor_json.execute(f"drop table if exists {table};")


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
async def test_arrow_fetch_result_scan(conn_cnx):
    async with conn_cnx() as cnx:
        cur = cnx.cursor()
        await cur.execute("alter session set query_result_format='ARROW_FORCE'")
        await cur.execute(
            "alter session set python_connector_query_result_format='ARROW_FORCE'"
        )
        res = await (await cur.execute("select 1, 2, 3")).fetch_pandas_all()
        assert tuple(res) == ("1", "2", "3")
        result_scan_res = await (
            await cur.execute(f"select * from table(result_scan('{cur.sfqid}'));")
        ).fetch_pandas_all()
        assert tuple(result_scan_res) == ("1", "2", "3")


@pytest.mark.parametrize("query_format", ("JSON", "ARROW"))
@pytest.mark.parametrize("resultscan_format", ("JSON", "ARROW"))
async def test_query_resultscan_combos(conn_cnx, query_format, resultscan_format):
    if query_format == "JSON" and resultscan_format == "ARROW":
        pytest.xfail("fix not yet released to test deployment")
    async with conn_cnx() as cnx:
        sfqid = None
        results = None
        scanned_results = None
        async with cnx.cursor() as query_cur:
            await query_cur.execute(
                "alter session set python_connector_query_result_format='{}'".format(
                    query_format
                )
            )
            await query_cur.execute(
                "select seq8(), randstr(1000,random()) from table(generator(rowcount=>100))"
            )
            sfqid = query_cur.sfqid
            assert query_cur._query_result_format.upper() == query_format
            if query_format == "JSON":
                results = await query_cur.fetchall()
            else:
                results = await query_cur.fetch_pandas_all()
        async with cnx.cursor() as resultscan_cur:
            await resultscan_cur.execute(
                "alter session set python_connector_query_result_format='{}'".format(
                    resultscan_format
                )
            )
            await resultscan_cur.execute(f"select * from table(result_scan('{sfqid}'))")
            if resultscan_format == "JSON":
                scanned_results = await resultscan_cur.fetchall()
            else:
                scanned_results = await resultscan_cur.fetch_pandas_all()
            assert resultscan_cur._query_result_format.upper() == resultscan_format
        if isinstance(results, pandas.DataFrame):
            results = [tuple(e) for e in results.values.tolist()]
        if isinstance(scanned_results, pandas.DataFrame):
            scanned_results = [tuple(e) for e in scanned_results.values.tolist()]
        assert results == scanned_results


@pytest.mark.parametrize(
    "use_decimal,expected",
    [
        (False, numpy.float64),
        pytest.param(True, decimal.Decimal, marks=pytest.mark.skipolddriver),
    ],
)
async def test_number_fetchall_retrieve_type(conn_cnx, use_decimal, expected):
    async with conn_cnx(arrow_number_to_decimal=use_decimal) as con:
        async with con.cursor() as cur:
            await cur.execute("SELECT 12345600.87654301::NUMBER(18, 8) a")
            result_df = await cur.fetch_pandas_all()
            a_column = result_df["A"]
            assert isinstance(a_column.values[0], expected), type(a_column.values[0])


@pytest.mark.parametrize(
    "use_decimal,expected",
    [
        (
            False,
            numpy.float64,
        ),
        pytest.param(True, decimal.Decimal, marks=pytest.mark.skipolddriver),
    ],
)
async def test_number_fetchbatches_retrieve_type(
    conn_cnx, use_decimal: bool, expected: type
):
    async with conn_cnx(arrow_number_to_decimal=use_decimal) as con:
        async with con.cursor() as cur:
            await cur.execute("SELECT 12345600.87654301::NUMBER(18, 8) a")
            async for batch in await cur.fetch_pandas_batches():
                a_column = batch["A"]
                assert isinstance(a_column.values[0], expected), type(
                    a_column.values[0]
                )


async def test_execute_async_and_fetch_pandas_batches(conn_cnx):
    """Test get pandas in an asynchronous way"""

    async with conn_cnx() as cnx:
        async with cnx.cursor() as cur:
            await cur.execute("select 1/2")
            res_sync = await cur.fetch_pandas_batches()

            result = await cur.execute_async("select 1/2")
            await cur.get_results_from_sfqid(result["queryId"])
            res_async = await cur.fetch_pandas_batches()

            assert res_sync is not None
            assert res_async is not None
            while True:
                try:
                    r_sync = await res_sync.__anext__()
                    r_async = await res_async.__anext__()
                    assert r_sync.values == r_async.values
                except StopAsyncIteration:
                    break


async def test_execute_async_and_fetch_arrow_batches(conn_cnx):
    """Test fetching result of an asynchronous query as batches of arrow tables"""

    async with conn_cnx() as cnx:
        async with cnx.cursor() as cur:
            await cur.execute("select 1/2")
            res_sync = await cur.fetch_arrow_batches()

            result = await cur.execute_async("select 1/2")
            await cur.get_results_from_sfqid(result["queryId"])
            res_async = await cur.fetch_arrow_batches()

            assert res_sync is not None
            assert res_async is not None
            while True:
                try:
                    r_sync = await res_sync.__anext__()
                    r_async = await res_async.__anext__()
                    assert r_sync == r_async
                except StopAsyncIteration:
                    break


async def test_simple_async_pandas(conn_cnx):
    """Simple test to that shows the most simple usage of fire and forget.

    This test also makes sure that wait_until_ready function's sleeping is tested and
    that some fields are copied over correctly from the original query.
    """
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute_async(
                "select count(*) from table(generator(timeLimit => 5))"
            )
            await cur.get_results_from_sfqid(cur.sfqid)
            assert len(await cur.fetch_pandas_all()) == 1
            assert cur.rowcount
            assert cur.description


async def test_simple_async_arrow(conn_cnx):
    """Simple test for async fetch_arrow_all"""
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute_async(
                "select count(*) from table(generator(timeLimit => 5))"
            )
            await cur.get_results_from_sfqid(cur.sfqid)
            assert len(await cur.fetch_arrow_all()) == 1
            assert cur.rowcount
            assert cur.description


@pytest.mark.parametrize(
    "use_decimal,expected",
    [
        (
            True,
            decimal.Decimal,
        ),
        pytest.param(False, numpy.float64, marks=pytest.mark.xfail),
    ],
)
async def test_number_iter_retrieve_type(conn_cnx, use_decimal: bool, expected: type):
    async with conn_cnx(arrow_number_to_decimal=use_decimal) as con:
        async with con.cursor() as cur:
            await cur.execute("SELECT 12345600.87654301::NUMBER(18, 8) a")
            async for row in cur:
                assert isinstance(row[0], expected), type(row[0])


async def test_resultbatches_pandas_functionality(conn_cnx):
    """Fetch ArrowResultBatches as pandas dataframes and check its result."""
    rowcount = 100000
    expected_df = pandas.DataFrame(data={"A": range(rowcount)})
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute(
                f"select seq4() a from table(generator(rowcount => {rowcount}));"
            )
            assert cur._result_set.total_row_index() == rowcount
            result_batches = await cur.get_result_batches()
            assert (await cur.fetch_pandas_all()).index[-1] == rowcount - 1
            assert len(result_batches) > 1

    iterables = []
    for b in result_batches:
        iterables.append(
            list(await b.create_iter(iter_unit=IterUnit.TABLE_UNIT, structure="arrow"))
        )
    tables = itertools.chain.from_iterable(iterables)
    final_df = pyarrow.concat_tables(tables).to_pandas()
    assert numpy.array_equal(expected_df, final_df)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing. or no new telemetry defined - skipolddrive",
)
@pytest.mark.parametrize(
    "fetch_method, expected_telemetry_type",
    [
        ("one", "client_fetch_pandas_all"),  # TelemetryField.PANDAS_FETCH_ALL
        ("batch", "client_fetch_pandas_batches"),  # TelemetryField.PANDAS_FETCH_BATCHES
    ],
)
async def test_pandas_telemetry(
    conn_cnx, capture_sf_telemetry_async, fetch_method, expected_telemetry_type
):
    cases = ["NULL", 0.11, -0.11, "NULL", 1.27, -1.28, "NULL"]
    table = "test_telemetry"
    column = "(a number(5,2))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    async with conn_cnx() as conn, capture_sf_telemetry_async.patch_connection(
        conn, False
    ) as telemetry_test:
        await init(conn, table, column, values)
        sql_text = f"select a from {table} order by s"

        await validate_pandas(
            conn,
            sql_text,
            cases,
            1,
            fetch_method,
        )

        occurence = 0
        for t in telemetry_test.records:
            if t.message["type"] == expected_telemetry_type:
                occurence += 1
        assert occurence == 1

        await finish(conn, table)


@pytest.mark.parametrize("result_format", ["pandas", "arrow"])
async def test_batch_to_pandas_arrow(conn_cnx, result_format):
    rowcount = 10
    async with conn_cnx() as cnx:
        async with cnx.cursor() as cur:
            await cur.execute(SQL_ENABLE_ARROW)
            await cur.execute(
                f"select seq4() as foo, seq4() as bar from table(generator(rowcount=>{rowcount})) order by foo asc"
            )
            batches = await cur.get_result_batches()
            assert len(batches) == 1
            batch = batches[0]

            # check that size, columns, and FOO column data is correct
            if result_format == "pandas":
                df = await batch.to_pandas()
                assert type(df) is pandas.DataFrame
                assert df.shape == (10, 2)
                assert all(df.columns == ["FOO", "BAR"])
                assert list(df.FOO) == list(range(rowcount))
            elif result_format == "arrow":
                arrow_table = await batch.to_arrow()
                assert type(arrow_table) is pyarrow.Table
                assert arrow_table.shape == (10, 2)
                assert arrow_table.column_names == ["FOO", "BAR"]
                assert arrow_table.to_pydict()["FOO"] == list(range(rowcount))


@pytest.mark.internal
@pytest.mark.parametrize("enable_structured_types", [True, False])
async def test_to_arrow_datatypes(enable_structured_types, conn_cnx):
    expected_types = (
        pyarrow.int64(),
        pyarrow.float64(),
        pyarrow.string(),
        pyarrow.date64(),
        pyarrow.timestamp("ns"),
        pyarrow.string(),
        pyarrow.timestamp("ns"),
        pyarrow.timestamp("ns"),
        pyarrow.timestamp("ns"),
        pyarrow.binary(),
        pyarrow.time64("ns"),
        pyarrow.bool_(),
        pyarrow.string(),
        pyarrow.string(),
        pyarrow.list_(pyarrow.float64(), 5),
    )

    query = """
    select
    1 :: INTEGER as FIXED_type,
    2.0 :: FLOAT as REAL_type,
    'test' :: TEXT as TEXT_type,
    '2024-02-28' :: DATE as DATE_type,
    '2020-03-12 01:02:03.123456789' :: TIMESTAMP as TIMESTAMP_type,
    '{"foo": "bar"}' :: VARIANT as VARIANT_type,
    '2020-03-12 01:02:03.123456789' :: TIMESTAMP_LTZ as TIMESTAMP_LTZ_type,
    '2020-03-12 01:02:03.123456789' :: TIMESTAMP_TZ as TIMESTAMP_TZ_type,
    '2020-03-12 01:02:03.123456789' :: TIMESTAMP_NTZ as TIMESTAMP_NTZ_type,
    '0xAAAA' :: BINARY as BINARY_type,
    '01:02:03.123456789' :: TIME as TIME_type,
    true :: BOOLEAN as BOOLEAN_type,
    TO_GEOGRAPHY('LINESTRING(13.4814 52.5015, -121.8212 36.8252)') as GEOGRAPHY_type,
    TO_GEOMETRY('LINESTRING(13.4814 52.5015, -121.8212 36.8252)') as GEOMETRY_type,
    [1,2,3,4,5] :: vector(float, 5) as VECTOR_type,
    object_construct('k1', 1, 'k2', 2, 'k3', 3, 'k4', 4, 'k5', 5) :: map(varchar, int) as MAP_type,
    object_construct('city', 'san jose', 'population', 0.05) :: object(city varchar, population float) as OBJECT_type,
    [1.0, 3.1, 4.5] :: array(float) as ARRAY_type
    WHERE 1=0
    """

    structured_params = {
        "ENABLE_STRUCTURED_TYPES_IN_CLIENT_RESPONSE",
        "IGNORE_CLIENT_VESRION_IN_STRUCTURED_TYPES_RESPONSE",
        "FORCE_ENABLE_STRUCTURED_TYPES_NATIVE_ARROW_FORMAT",
    }

    async with conn_cnx() as cnx:
        async with cnx.cursor() as cur:
            await cur.execute(SQL_ENABLE_ARROW)
            try:
                if enable_structured_types:
                    for param in structured_params:
                        await cur.execute(f"alter session set {param}=true")
                    expected_types += (
                        pyarrow.map_(pyarrow.string(), pyarrow.int64()),
                        pyarrow.struct(
                            {"city": pyarrow.string(), "population": pyarrow.float64()}
                        ),
                        pyarrow.list_(pyarrow.float64()),
                    )
                else:
                    expected_types += (
                        pyarrow.string(),
                        pyarrow.string(),
                        pyarrow.string(),
                    )
                # Ensure an empty batch to use default typing
                # Otherwise arrow will resize types to save space
                await cur.execute(query)
                batches = cur.get_result_batches()
                assert len(batches) == 1
                batch = batches[0]
                arrow_table = batch.to_arrow()
                for actual, expected in zip(arrow_table.schema, expected_types):
                    assert (
                        actual.type == expected
                    ), f"Expected {actual.name} :: {actual.type} column to be of type {expected}"
            finally:
                if enable_structured_types:
                    for param in structured_params:
                        await cur.execute(f"alter session unset {param}")


async def test_simple_arrow_fetch(conn_cnx):
    rowcount = 250_000
    async with conn_cnx() as cnx:
        async with cnx.cursor() as cur:
            await cur.execute(SQL_ENABLE_ARROW)
            await cur.execute(
                f"select seq4() as foo from table(generator(rowcount=>{rowcount})) order by foo asc"
            )
            arrow_table = await cur.fetch_arrow_all()
            assert arrow_table.shape == (rowcount, 1)
            assert arrow_table.to_pydict()["FOO"] == list(range(rowcount))

            await cur.execute(
                f"select seq4() as foo from table(generator(rowcount=>{rowcount})) order by foo asc"
            )
            assert (
                len(await cur.get_result_batches()) > 1
            )  # non-trivial number of batches

            # the start and end points of each batch
            lo, hi = 0, 0
            async for table in await cur.fetch_arrow_batches():
                assert type(table) is pyarrow.Table  # sanity type check

                # check that data is correct
                length = len(table)
                hi += length
                assert table.to_pydict()["FOO"] == list(range(lo, hi))
                lo += length

            assert lo == rowcount


async def test_arrow_zero_rows(conn_cnx):
    async with conn_cnx() as cnx:
        async with cnx.cursor() as cur:
            await cur.execute(SQL_ENABLE_ARROW)
            await cur.execute("select 1::NUMBER(38,0) limit 0")
            table = await cur.fetch_arrow_all(force_return_table=True)
            # Snowflake will return an integer dtype with maximum bit-length if
            # no rows are returned
            assert table.schema[0].type == pyarrow.int64()
            await cur.execute("select 1::NUMBER(38,0) limit 0")
            # test default behavior
            assert await cur.fetch_arrow_all(force_return_table=False) is None


@pytest.mark.parametrize("fetch_fn_name", ["to_arrow", "to_pandas", "create_iter"])
@pytest.mark.parametrize("pass_connection", [True, False])
async def test_sessions_used(conn_cnx, fetch_fn_name, pass_connection):
    rowcount = 250_000
    async with conn_cnx() as cnx:
        async with cnx.cursor() as cur:
            await cur.execute(SQL_ENABLE_ARROW)
            await cur.execute(
                f"select seq1() from table(generator(rowcount=>{rowcount}))"
            )
            batches = await cur.get_result_batches()
            assert len(batches) > 1
            batch = batches[-1]

            connection = cnx if pass_connection else None
            fetch_fn = getattr(batch, fetch_fn_name)

            # check that sessions are used when connection is supplied
            with mock.patch(
                "snowflake.connector.aio._network.SnowflakeRestful._use_requests_session",
                side_effect=cnx._rest._use_requests_session,
            ) as get_session_mock:
                await fetch_fn(connection=connection)
                assert get_session_mock.call_count == (1 if pass_connection else 0)


def assert_dtype_equal(a, b):
    """Pandas method of asserting the same numpy dtype of variables by computing hash."""
    assert_equal(a, b)
    assert_equal(
        hash(a), hash(b), "two equivalent types do not hash to the same value !"
    )


def assert_pandas_batch_types(
    batch: pandas.DataFrame, expected_types: list[type]
) -> None:
    assert batch.dtypes is not None

    pandas_dtypes = batch.dtypes
    # pd.string is represented as an np.object
    # np.dtype string is not the same as pd.string (python)
    for pandas_dtype, expected_type in zip(pandas_dtypes, expected_types):
        assert_dtype_equal(pandas_dtype.type, numpy.dtype(expected_type).type)


async def test_pandas_dtypes(conn_cnx):
    async with conn_cnx(
        session_parameters={
            PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: "arrow_force"
        }
    ) as cnx:
        async with cnx.cursor() as cur:
            await cur.execute(
                "select 1::integer, 2.3::double, 'foo'::string, current_timestamp()::timestamp where 1=0"
            )
            expected_types = [numpy.int64, float, object, numpy.datetime64]
            assert_pandas_batch_types(await cur.fetch_pandas_all(), expected_types)

            batches = await cur.get_result_batches()
            assert await batches[0].to_arrow() is not True
            assert_pandas_batch_types(await batches[0].to_pandas(), expected_types)


async def test_timestamp_tz(conn_cnx):
    async with conn_cnx(
        session_parameters={
            PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: "arrow_force"
        }
    ) as cnx:
        async with cnx.cursor() as cur:
            await cur.execute("select '1990-01-04 10:00:00 +1100'::timestamp_tz as d")
            res = await cur.fetchall()
            assert res[0][0].tzinfo is not None
            res_pd = await cur.fetch_pandas_all()
            assert res_pd.D.dt.tz is pytz.UTC
            res_pa = await cur.fetch_arrow_all()
            assert res_pa.field("D").type.tz == "UTC"


async def test_arrow_number_to_decimal(conn_cnx):
    async with conn_cnx(
        session_parameters={
            PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: "arrow_force"
        },
        arrow_number_to_decimal=True,
    ) as cnx:
        async with cnx.cursor() as cur:
            await cur.execute("select -3.20 as num")
            df = await cur.fetch_pandas_all()
            val = df.NUM[0]
            assert val == Decimal("-3.20")
            assert isinstance(val, decimal.Decimal)


@pytest.mark.parametrize(
    "timestamp_type",
    [
        "TIMESTAMP_TZ",
        "TIMESTAMP_NTZ",
        "TIMESTAMP_LTZ",
    ],
)
async def test_time_interval_microsecond(conn_cnx, timestamp_type):
    async with conn_cnx(
        session_parameters={
            PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: "arrow_force"
        }
    ) as cnx:
        async with cnx.cursor() as cur:
            res = await (
                await cur.execute(
                    f"SELECT TO_{timestamp_type}('2010-06-25 12:15:30.747000')+INTERVAL '8999999999999998 MICROSECONDS'"
                )
            ).fetchone()
            assert res[0].microsecond == 746998
            res = await (
                await cur.execute(
                    f"SELECT TO_{timestamp_type}('2010-06-25 12:15:30.747000')+INTERVAL '8999999999999999 MICROSECONDS'"
                )
            ).fetchone()
            assert res[0].microsecond == 746999


async def test_fetch_with_pandas_nullable_types(conn_cnx):
    # use several float values to test nullable types. Nullable types can preserve both nan and null in float
    sql_text = """
    select 1.0::float, 'NaN'::float, Null::float;
    """
    # https://arrow.apache.org/docs/python/pandas.html#nullable-types
    dtype_mapping = {
        pyarrow.int8(): pandas.Int8Dtype(),
        pyarrow.int16(): pandas.Int16Dtype(),
        pyarrow.int32(): pandas.Int32Dtype(),
        pyarrow.int64(): pandas.Int64Dtype(),
        pyarrow.uint8(): pandas.UInt8Dtype(),
        pyarrow.uint16(): pandas.UInt16Dtype(),
        pyarrow.uint32(): pandas.UInt32Dtype(),
        pyarrow.uint64(): pandas.UInt64Dtype(),
        pyarrow.bool_(): pandas.BooleanDtype(),
        pyarrow.float32(): pandas.Float32Dtype(),
        pyarrow.float64(): pandas.Float64Dtype(),
        pyarrow.string(): pandas.StringDtype(),
    }

    expected_dtypes = pandas.Series(
        [pandas.Float64Dtype(), pandas.Float64Dtype(), pandas.Float64Dtype()],
        index=["1.0::FLOAT", "'NAN'::FLOAT", "NULL::FLOAT"],
    )
    expected_df_to_string = """   1.0::FLOAT  'NAN'::FLOAT  NULL::FLOAT
0         1.0           NaN         <NA>"""
    async with conn_cnx() as cnx_table:
        # fetch dataframe with new arrow support
        cursor_table = cnx_table.cursor()
        await cursor_table.execute(SQL_ENABLE_ARROW)
        await cursor_table.execute(sql_text)
        # test fetch_pandas_batches
        async for df in await cursor_table.fetch_pandas_batches(
            types_mapper=dtype_mapping.get
        ):
            pandas._testing.assert_series_equal(df.dtypes, expected_dtypes)
            print(df)
            assert df.to_string() == expected_df_to_string
        # test fetch_pandas_all
        df = await cursor_table.fetch_pandas_all(types_mapper=dtype_mapping.get)
        pandas._testing.assert_series_equal(df.dtypes, expected_dtypes)
        assert df.to_string() == expected_df_to_string
