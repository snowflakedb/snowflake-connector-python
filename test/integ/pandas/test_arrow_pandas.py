#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
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

try:
    from snowflake.connector.constants import IterUnit
except ImportError:
    # This is because of olddriver tests
    class IterUnit(Enum):
        ROW_UNIT = "row"
        TABLE_UNIT = "table"


try:
    from snowflake.connector.options import installed_pandas, pandas, pyarrow  # NOQA
except ImportError:
    installed_pandas = False
    pandas = None
    pyarrow = None

try:
    from snowflake.connector.arrow_iterator import PyArrowIterator  # NOQA

    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True

SQL_ENABLE_ARROW = "alter session set python_connector_query_result_format='ARROW';"

EPSILON = 1e-8


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
def test_num_one(conn_cnx):
    print("Test fetching one single dataframe")
    row_count = 50000
    col_count = 2
    random_seed = get_random_seed()
    sql_exec = "select seq4() as c1, uniform(1, 10, random({})) as c2 from ".format(
        random_seed
    ) + "table(generator(rowcount=>{})) order by c1, c2".format(row_count)
    fetch_pandas(conn_cnx, sql_exec, row_count, col_count, "one")


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
def test_scaled_tinyint(conn_cnx):
    cases = ["NULL", 0.11, -0.11, "NULL", 1.27, -1.28, "NULL"]
    table = "test_arrow_tiny_int"
    column = "(a number(5,2))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one")
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
def test_scaled_smallint(conn_cnx):
    cases = ["NULL", 0, 0.11, -0.11, "NULL", 32.767, -32.768, "NULL"]
    table = "test_arrow_small_int"
    column = "(a number(5,3))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one")
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
def test_scaled_int(conn_cnx):
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
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one")
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is not installed.",
)
def test_scaled_bigint(conn_cnx):
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
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one", epsilon=EPSILON)
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
def test_decimal(conn_cnx):
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
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one", data_type="decimal")
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is not installed.",
)
def test_scaled_decimal(conn_cnx):
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
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one", data_type="decimal")
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is not installed.",
)
def test_scaled_decimal_SNOW_133561(conn_cnx):
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
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one", data_type="float")
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
def test_boolean(conn_cnx):
    cases = ["NULL", True, "NULL", False, True, True, "NULL", True, False, "NULL"]
    table = "test_arrow_boolean"
    column = "(a boolean)"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one")
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
def test_double(conn_cnx):
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
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one")
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
def test_semi_struct(conn_cnx):
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
    with conn_cnx() as cnx_table:
        # fetch dataframe with new arrow support
        cursor_table = cnx_table.cursor()
        cursor_table.execute(SQL_ENABLE_ARROW)
        cursor_table.execute(sql_text)
        df_new = cursor_table.fetch_pandas_all()
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
def test_date(conn_cnx):
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
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one", data_type="date")
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
@pytest.mark.parametrize("scale", [i for i in range(10)])
def test_time(conn_cnx, scale):
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
    column = "(a time({}))".format(scale)
    values = ",".join(
        [f"({i}, {c})" if c == "NULL" else f"({i}, '{c}')" for i, c in enumerate(cases)]
    )
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(conn, sql_text, cases, 1, "one", data_type="time", scale=scale)
        finish(conn, table)


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
@pytest.mark.parametrize("scale", [i for i in range(10)])
def test_timestampntz(conn_cnx, scale):
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
    column = "(a timestampntz({}))".format(scale)

    values = ",".join(
        [f"({i}, {c})" if c == "NULL" else f"({i}, '{c}')" for i, c in enumerate(cases)]
    )
    with conn_cnx() as conn:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(
            conn, sql_text, cases, 1, "one", data_type="timestamp", scale=scale
        )
        finish(conn, table)


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
def test_timestamptz(conn_cnx, scale, timezone):
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
    column = "(a timestamptz({}))".format(scale)
    values = ",".join(
        [f"({i}, {c})" if c == "NULL" else f"({i}, '{c}')" for i, c in enumerate(cases)]
    )
    with conn_cnx() as conn:
        init(conn, table, column, values, timezone=timezone)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(
            conn,
            sql_text,
            cases,
            1,
            "one",
            data_type="timestamptz",
            scale=scale,
            timezone=timezone,
        )
        finish(conn, table)


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
def test_timestampltz(conn_cnx, scale, timezone):
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
    column = "(a timestampltz({}))".format(scale)
    values = ",".join(
        [f"({i}, {c})" if c == "NULL" else f"({i}, '{c}')" for i, c in enumerate(cases)]
    )
    with conn_cnx() as conn:
        init(conn, table, column, values, timezone=timezone)
        sql_text = "select a from {} order by s".format(table)
        validate_pandas(
            conn,
            sql_text,
            cases,
            1,
            "one",
            data_type="timestamp",
            scale=scale,
            timezone=timezone,
        )
        finish(conn, table)


def validate_pandas(
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
    cursor_table.execute(SQL_ENABLE_ARROW)
    cursor_table.execute(sql)

    # build dataframe
    total_rows, total_batches = 0, 0
    start_time = time.time()

    if method == "one":
        df_new = cursor_table.fetch_pandas_all()
        total_rows = df_new.shape[0]
    else:
        for df_new in cursor_table.fetch_pandas_batches():
            total_rows += df_new.shape[0]
            total_batches += 1
    end_time = time.time()

    print(f"new way (fetching {method}) took {end_time - start_time}s")
    if method == "batch":
        print(f"new way has # of batches : {total_batches}")
    cursor_table.close()
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
                if cases[i] == "NULL":
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
                                c_case = c_case.tz_localize(None)
                        else:
                            c_case = pandas.Timestamp(cases[i][:time_str_len])
                        assert c_case == c_new, (
                            "{} row, {} column: original value is {}, new value is {}, "
                            "values are not equal".format(i, j, cases[i], c_new)
                        )
                        break
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
def test_num_batch(conn_cnx):
    print("Test fetching dataframes in batch")
    row_count = 1000000
    col_count = 2
    random_seed = get_random_seed()
    sql_exec = (
        f"select seq4() as c1, uniform(1, 10, random({random_seed})) as c2 from "
        f"table(generator(rowcount=>{row_count})) order by c1, c2"
    )
    fetch_pandas(conn_cnx, sql_exec, row_count, col_count, "batch")


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
@pytest.mark.parametrize(
    "result_format",
    ["pandas", "arrow"],
)
def test_empty(conn_cnx, result_format):
    print("Test fetch empty dataframe")
    with conn_cnx() as cnx:
        cursor = cnx.cursor()
        cursor.execute(SQL_ENABLE_ARROW)
        cursor.execute(
            "select seq4() as foo, seq4() as bar from table(generator(rowcount=>1)) limit 0"
        )
        fetch_all_fn = getattr(cursor, f"fetch_{result_format}_all")
        fetch_batches_fn = getattr(cursor, f"fetch_{result_format}_batches")
        result = fetch_all_fn()
        if result_format == "pandas":
            assert len(list(result)) == 2
            assert list(result)[0] == "FOO"
            assert list(result)[1] == "BAR"
        else:
            assert result is None

        cursor.execute(
            "select seq4() as foo from table(generator(rowcount=>1)) limit 0"
        )
        df_count = 0
        for _ in fetch_batches_fn():
            df_count += 1
        assert df_count == 0


def get_random_seed():
    random.seed(datetime.now())
    return random.randint(0, 10000)


def fetch_pandas(conn_cnx, sql, row_count, col_count, method="one"):
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

    with conn_cnx() as conn:
        # fetch dataframe by fetching row by row
        cursor_row = conn.cursor()
        cursor_row.execute(SQL_ENABLE_ARROW)
        cursor_row.execute(sql)

        # build dataframe
        # actually its exec time would be different from `pandas.read_sql()` via sqlalchemy as most people use
        # further perf test can be done separately
        start_time = time.time()
        rows = 0
        if method == "one":
            df_old = pandas.DataFrame(
                cursor_row.fetchall(),
                columns=["c{}".format(i) for i in range(col_count)],
            )
        else:
            print("use fetchmany")
            while True:
                dat = cursor_row.fetchmany(10000)
                if not dat:
                    break
                else:
                    df_old = pandas.DataFrame(
                        dat, columns=["c{}".format(i) for i in range(col_count)]
                    )
                    rows += df_old.shape[0]
        end_time = time.time()
        print("The original way took {}s".format(end_time - start_time))
        cursor_row.close()

        # fetch dataframe with new arrow support
        cursor_table = conn.cursor()
        cursor_table.execute(SQL_ENABLE_ARROW)
        cursor_table.execute(sql)

        # build dataframe
        total_rows, total_batches = 0, 0
        start_time = time.time()
        if method == "one":
            df_new = cursor_table.fetch_pandas_all()
            total_rows = df_new.shape[0]
        else:
            for df_new in cursor_table.fetch_pandas_batches():
                total_rows += df_new.shape[0]
                total_batches += 1
        end_time = time.time()
        print("new way (fetching {}) took {}s".format(method, end_time - start_time))
        if method == "batch":
            print("new way has # of batches : {}".format(total_batches))
        cursor_table.close()
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
            ), "the number of rows are not equal {} vs {}".format(rows, total_rows)


def init(json_cnx, table, column, values, timezone=None):
    cursor_json = json_cnx.cursor()
    if timezone is not None:
        cursor_json.execute("ALTER SESSION SET TIMEZONE = '{}'".format(timezone))
    column_with_seq = column[0] + "s number, " + column[1:]
    cursor_json.execute("create or replace table {} {}".format(table, column_with_seq))
    cursor_json.execute("insert into {} values {}".format(table, values))


def finish(json_cnx, table):
    cursor_json = json_cnx.cursor()
    cursor_json.execute("drop table if exists {};".format(table))


@pytest.mark.skipif(
    not installed_pandas or no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built, or pandas is missing.",
)
def test_arrow_fetch_result_scan(conn_cnx):
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        cur.execute("alter session set query_result_format='ARROW_FORCE'")
        cur.execute(
            "alter session set python_connector_query_result_format='ARROW_FORCE'"
        )
        res = cur.execute("select 1, 2, 3").fetch_pandas_all()
        assert tuple(res) == ("1", "2", "3")
        result_scan_res = cur.execute(
            "select * from table(result_scan('{}'));".format(cur.sfqid)
        ).fetch_pandas_all()
        assert tuple(result_scan_res) == ("1", "2", "3")


@pytest.mark.parametrize("query_format", ("JSON", "ARROW"))
@pytest.mark.parametrize("resultscan_format", ("JSON", "ARROW"))
def test_query_resultscan_combos(conn_cnx, query_format, resultscan_format):
    if query_format == "JSON" and resultscan_format == "ARROW":
        pytest.xfail("fix not yet released to test deployment")
    with conn_cnx() as cnx:
        sfqid = None
        results = None
        scanned_results = None
        with cnx.cursor() as query_cur:
            query_cur.execute(
                "alter session set python_connector_query_result_format='{}'".format(
                    query_format
                )
            )
            query_cur.execute(
                "select seq8(), randstr(1000,random()) from table(generator(rowcount=>100))"
            )
            sfqid = query_cur.sfqid
            assert query_cur._query_result_format.upper() == query_format
            if query_format == "JSON":
                results = query_cur.fetchall()
            else:
                results = query_cur.fetch_pandas_all()
        with cnx.cursor() as resultscan_cur:
            resultscan_cur.execute(
                "alter session set python_connector_query_result_format='{}'".format(
                    resultscan_format
                )
            )
            resultscan_cur.execute(
                "select * from table(result_scan('{}'))".format(sfqid)
            )
            if resultscan_format == "JSON":
                scanned_results = resultscan_cur.fetchall()
            else:
                scanned_results = resultscan_cur.fetch_pandas_all()
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
def test_number_fetchall_retrieve_type(conn_cnx, use_decimal, expected):
    with conn_cnx(arrow_number_to_decimal=use_decimal) as con:
        with con.cursor() as cur:
            cur.execute("SELECT 12345600.87654301::NUMBER(18, 8) a")
            result_df = cur.fetch_pandas_all()
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
def test_number_fetchbatches_retrieve_type(conn_cnx, use_decimal: bool, expected: type):
    with conn_cnx(arrow_number_to_decimal=use_decimal) as con:
        with con.cursor() as cur:
            cur.execute("SELECT 12345600.87654301::NUMBER(18, 8) a")
            for batch in cur.fetch_pandas_batches():
                a_column = batch["A"]
                assert isinstance(a_column.values[0], expected), type(
                    a_column.values[0]
                )


def test_simple_async_arrow(conn_cnx):
    """Simple test to that shows the most simple usage of fire and forget.

    This test also makes sure that wait_until_ready function's sleeping is tested and
    that some fields are copied over correctly from the original query.
    """
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async("select count(*) from table(generator(timeLimit => 5))")
            cur.get_results_from_sfqid(cur.sfqid)
            assert len(cur.fetch_pandas_all()) == 1
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
def test_number_iter_retrieve_type(conn_cnx, use_decimal: bool, expected: type):
    with conn_cnx(arrow_number_to_decimal=use_decimal) as con:
        with con.cursor() as cur:
            cur.execute("SELECT 12345600.87654301::NUMBER(18, 8) a")
            for row in cur:
                assert isinstance(row[0], expected), type(row[0])


def test_resultbatches_pandas_functionality(conn_cnx):
    """Fetch ArrowResultBatches as pandas dataframes and check its result."""
    rowcount = 100000
    expected_df = pandas.DataFrame(data={"A": range(rowcount)})
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute(
                f"select seq4() a from table(generator(rowcount => {rowcount}));"
            )
            assert cur._result_set.total_row_index() == rowcount
            result_batches = cur.get_result_batches()
            assert len(result_batches) > 1
    tables = itertools.chain.from_iterable(
        list(b.create_iter(iter_unit=IterUnit.TABLE_UNIT, structure="arrow"))
        for b in result_batches
    )
    final_df = pyarrow.concat_tables(tables).to_pandas()
    assert numpy.array_equal(expected_df, final_df)


@pytest.mark.skipolddriver
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
def test_pandas_telemetry(
    conn_cnx, capture_sf_telemetry, fetch_method, expected_telemetry_type
):
    cases = ["NULL", 0.11, -0.11, "NULL", 1.27, -1.28, "NULL"]
    table = "test_telemetry"
    column = "(a number(5,2))"
    values = ",".join([f"({i}, {c})" for i, c in enumerate(cases)])
    with conn_cnx() as conn, capture_sf_telemetry.patch_connection(
        conn, False
    ) as telemetry_test:
        init(conn, table, column, values)
        sql_text = "select a from {} order by s".format(table)

        validate_pandas(
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

        finish(conn, table)


@pytest.mark.parametrize("result_format", ["pandas", "arrow"])
def test_batch_to_pandas_arrow(conn_cnx, result_format):
    rowcount = 10
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            cur.execute(SQL_ENABLE_ARROW)
            cur.execute(
                f"select seq4() as foo, seq4() as bar from table(generator(rowcount=>{rowcount})) order by foo asc"
            )
            batches = cur.get_result_batches()
            assert len(batches) == 1
            batch = batches[0]

            # check that size, columns, and FOO column data is correct
            if result_format == "pandas":
                df = batch.to_pandas()
                assert type(df) == pandas.DataFrame
                assert df.shape == (10, 2)
                assert all(df.columns == ["FOO", "BAR"])
                assert list(df.FOO) == list(range(rowcount))
            elif result_format == "arrow":
                arrow_table = batch.to_arrow()
                assert type(arrow_table) == pyarrow.Table
                assert arrow_table.shape == (10, 2)
                assert arrow_table.column_names == ["FOO", "BAR"]
                assert arrow_table.to_pydict()["FOO"] == list(range(rowcount))


def test_simple_arrow_fetch(conn_cnx):
    rowcount = 250_000
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            cur.execute(SQL_ENABLE_ARROW)
            cur.execute(
                f"select seq4() as foo from table(generator(rowcount=>{rowcount})) order by foo asc"
            )
            arrow_table = cur.fetch_arrow_all()
            assert arrow_table.shape == (rowcount, 1)
            assert arrow_table.to_pydict()["FOO"] == list(range(rowcount))

            cur.execute(
                f"select seq4() as foo from table(generator(rowcount=>{rowcount})) order by foo asc"
            )
            assert len(cur.get_result_batches()) > 1  # non-trivial number of batches

            # the start and end points of each batch
            lo, hi = 0, 0
            for table in cur.fetch_arrow_batches():
                assert type(table) == pyarrow.Table  # sanity type check

                # check that data is correct
                length = len(table)
                hi += length
                assert table.to_pydict()["FOO"] == list(range(lo, hi))
                lo += length

            assert lo == rowcount


@pytest.mark.parametrize("fetch_fn_name", ["to_arrow", "to_pandas", "create_iter"])
@pytest.mark.parametrize("pass_connection", [True, False])
@pytest.mark.parametrize("use_sessions", [True, False])
def test_sessions_used(conn_cnx, fetch_fn_name, pass_connection, use_sessions):
    rowcount = 250_000
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            cur.execute(SQL_ENABLE_ARROW)
            cur.execute(f"select seq1() from table(generator(rowcount=>{rowcount}))")
            batches = cur.get_result_batches()
            assert len(batches) > 1
            batch = batches[-1]
            batch.use_sessions = use_sessions

            connection = cnx if pass_connection else None
            fetch_fn = getattr(batch, fetch_fn_name)

            # check that sessions are used when connection is supplied
            with mock.patch(
                "snowflake.connector.network.SnowflakeRestful._use_requests_session",
                side_effect=cnx._rest._use_requests_session,
            ) as get_session_mock:
                fetch_fn(connection=connection)
                assert get_session_mock.call_count == (
                    1 if pass_connection and use_sessions else 0
                )
