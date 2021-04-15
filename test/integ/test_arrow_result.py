#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import itertools
import random
from datetime import datetime

import numpy
import pytest

import snowflake.connector

pytestmark = pytest.mark.skipolddriver  # old test driver tests won't run this module

try:
    from snowflake.connector.arrow_iterator import PyArrowIterator  # NOQA

    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True


def test_select_tinyint(conn_cnx):
    cases = [0, 1, -1, 127, -128]
    table = "test_arrow_tiny_int"
    column = "(a int)"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_scaled_tinyint(conn_cnx):
    cases = [0.0, 0.11, -0.11, 1.27, -1.28]
    table = "test_arrow_tiny_int"
    column = "(a number(5,3))"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_smallint(conn_cnx):
    cases = [0, 1, -1, 127, -128, 128, -129, 32767, -32768]
    table = "test_arrow_small_int"
    column = "(a int)"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_scaled_smallint(conn_cnx):
    cases = ["0", "2.0", "-2.0", "32.767", "-32.768"]
    table = "test_arrow_small_int"
    column = "(a number(5,3))"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_int(conn_cnx):
    cases = [
        0,
        1,
        -1,
        127,
        -128,
        128,
        -129,
        32767,
        -32768,
        32768,
        -32769,
        2147483647,
        -2147483648,
    ]
    table = "test_arrow_int"
    column = "(a int)"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_scaled_int(conn_cnx):
    cases = ["0", "0.123456789", "-0.123456789", "0.2147483647", "-0.2147483647"]
    table = "test_arrow_int"
    column = "(a number(10,9))"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_bigint(conn_cnx):
    cases = [
        0,
        1,
        -1,
        127,
        -128,
        128,
        -129,
        32767,
        -32768,
        32768,
        -32769,
        2147483647,
        -2147483648,
        2147483648,
        -2147483649,
        9223372036854775807,
        -9223372036854775808,
    ]
    table = "test_arrow_bigint"
    column = "(a int)"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_scaled_bigint(conn_cnx):
    cases = [
        "0",
        "0.000000000000000001",
        "-0.000000000000000001",
        "0.000000000000000127",
        "-0.000000000000000128",
        "0.000000000000000128",
        "-0.000000000000000129",
        "0.000000000000032767",
        "-0.000000000000032768",
        "0.000000000000032768",
        "-0.000000000000032769",
        "0.000000002147483647",
        "-0.000000002147483648",
        "0.000000002147483648",
        "-0.000000002147483649",
        "9.223372036854775807",
        "-9.223372036854775808",
    ]
    table = "test_arrow_bigint"
    column = "(a number(38,18))"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_decimal(conn_cnx):
    cases = [
        "10000000000000000000000000000000000000",
        "12345678901234567890123456789012345678",
        "99999999999999999999999999999999999999",
    ]
    table = "test_arrow_decimal"
    column = "(a number(38,0))"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_scaled_decimal(conn_cnx):
    cases = [
        "0",
        "0.000000000000000001",
        "-0.000000000000000001",
        "0.000000000000000127",
        "-0.000000000000000128",
        "0.000000000000000128",
        "-0.000000000000000129",
        "0.000000000000032767",
        "-0.000000000000032768",
        "0.000000000000032768",
        "-0.000000000000032769",
        "0.000000002147483647",
        "-0.000000002147483648",
        "0.000000002147483648",
        "-0.000000002147483649",
        "9.223372036854775807",
        "-9.223372036854775808",
    ]
    table = "test_arrow_decimal"
    column = "(a number(38,37))"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_large_scaled_decimal(conn_cnx):
    cases = [
        "1.0000000000000000000000000000000000000",
        "1.2345678901234567890123456789012345678",
        "9.9999999999999999999999999999999999999",
    ]
    table = "test_arrow_decimal"
    column = "(a number(38,37))"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_scaled_decimal_SNOW_133561(conn_cnx):
    cases = [
        "0",
        "1.2345",
        "2.3456",
        "-9.999",
        "-1.000",
        "-3.4567",
        "3.4567",
        "4.5678",
        "5.6789",
        "NULL",
    ]
    table = "test_scaled_decimal_SNOW_133561"
    column = "(a number(38,10))"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_boolean(conn_cnx):
    cases = ["true", "false", "true"]
    table = "test_arrow_boolean"
    column = "(a boolean)"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("boolean", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext, reason="arrow_iterator extension is not built."
)
def test_select_double_precision(conn_cnx):
    cases = [
        # SNOW-31249
        "-86.6426540296895",
        "3.14159265359",
        # SNOW-76269
        "1.7976931348623157e+308",
        "1.7e+308",
        "1.7976931348623151e+308",
        "-1.7976931348623151e+308",
        "-1.7e+308",
        "-1.7976931348623157e+308",
    ]
    table = "test_arrow_double"
    column = "(a double)"
    values = (
        "(" + "),(".join(["{}, {}".format(i, c) for i, c in enumerate(cases)]) + ")"
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases)
    col_count = 1
    iterate_over_test_chunk(
        "float", conn_cnx, sql_text, row_count, col_count, expected=cases
    )
    finish(conn_cnx, table)


def test_select_semi_structure(conn_cnx):
    sql_text = """select array_construct(10, 20, 30),
        array_construct(null, 'hello', 3::double, 4, 5),
        array_construct(),
        object_construct('a',1,'b','BBBB', 'c',null),
        object_construct('Key_One', parse_json('NULL'), 'Key_Two', null, 'Key_Three', 'null'),
        to_variant(3.2),
        parse_json('{ "a": null}'),
        100::variant;
    """
    row_count = 1
    col_count = 8
    iterate_over_test_chunk("struct", conn_cnx, sql_text, row_count, col_count)


def test_select_time(conn_cnx):
    for scale in range(10):
        select_time_with_scale(conn_cnx, scale)


def select_time_with_scale(conn_cnx, scale):
    cases = [
        "00:01:23",
        "00:01:23.1",
        "00:01:23.12",
        "00:01:23.123",
        "00:01:23.1234",
        "00:01:23.12345",
        "00:01:23.123456",
        "00:01:23.1234567",
        "00:01:23.12345678",
        "00:01:23.123456789",
    ]
    table = "test_arrow_time"
    column = "(a time({}))".format(scale)
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, '{}'".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("time", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_date(conn_cnx):
    cases = [
        "2016-07-23",
        "1970-01-01",
        "1969-12-31",
        "0001-01-01",
        "9999-12-31",
    ]
    table = "test_arrow_time"
    column = "(a date)"
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, '{}'".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk("date", conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


@pytest.mark.parametrize(
    "scale, type",
    itertools.product(
        [i for i in range(10)], ["timestampntz", "timestampltz", "timestamptz"]
    ),
)
def test_select_timestamp_with_scale(conn_cnx, scale, type):
    cases = [
        "2017-01-01 12:00:00",
        "2014-01-02 16:00:00",
        "2014-01-02 12:34:56",
        "2017-01-01 12:00:00.123456789",
        "2014-01-02 16:00:00.000000001",
        "2014-01-02 12:34:56.1",
        "1969-12-31 23:59:59.000000001",
        "1970-01-01 00:00:00.123412423",
        "1970-01-01 00:00:01.000001",
        "1969-12-31 11:59:59.001",
        "0001-12-31 11:59:59.11",
    ]
    table = "test_arrow_timestamp"
    column = "(a {}({}))".format(type, scale)
    values = (
        "(-1, NULL), ("
        + "),(".join(["{}, '{}'".format(i, c) for i, c in enumerate(cases)])
        + "), ({}, NULL)".format(len(cases))
    )
    init(conn_cnx, table, column, values)
    sql_text = "select a from {} order by s".format(table)
    row_count = len(cases) + 2
    col_count = 1
    iterate_over_test_chunk(type, conn_cnx, sql_text, row_count, col_count)
    finish(conn_cnx, table)


def test_select_with_string(conn_cnx):
    col_count = 2
    row_count = 50000
    random_seed = get_random_seed()
    length = random.randint(1, 10)
    sql_text = (
        "select seq4() as c1, randstr({}, random({})) as c2 from ".format(
            length, random_seed
        )
        + "table(generator(rowcount=>50000)) order by c1"
    )
    iterate_over_test_chunk("string", conn_cnx, sql_text, row_count, col_count)


def test_select_with_bool(conn_cnx):
    col_count = 2
    row_count = 50000
    random_seed = get_random_seed()
    sql_text = (
        "select seq4() as c1, as_boolean(uniform(0, 1, random({}))) as c2 from ".format(
            random_seed
        )
        + "table(generator(rowcount=>{})) order by c1".format(row_count)
    )
    iterate_over_test_chunk("bool", conn_cnx, sql_text, row_count, col_count)


def test_select_with_float(conn_cnx):
    col_count = 2
    row_count = 50000
    random_seed = get_random_seed()
    pow_val = random.randint(0, 10)
    val_len = random.randint(0, 16)
    # if we assign val_len a larger value like 20, then the precision difference between c++ and python will become
    # very obvious so if we meet some error in this test in the future, please check that whether it is caused by
    # different precision between python and c++
    val_range = random.randint(0, 10 ** val_len)

    sql_text = "select seq4() as c1, as_double(uniform({}, {}, random({})))/{} as c2 from ".format(
        -val_range, val_range, random_seed, 10 ** pow_val
    ) + "table(generator(rowcount=>{})) order by c1".format(
        row_count
    )
    iterate_over_test_chunk(
        "float", conn_cnx, sql_text, row_count, col_count, eps=10 ** (-pow_val + 1)
    )


def test_select_with_empty_resultset(conn_cnx):
    with conn_cnx() as cnx:
        cursor = cnx.cursor()
        cursor.execute("alter session set query_result_format='ARROW_FORCE'")
        cursor.execute(
            "alter session set python_connector_query_result_format='ARROW_FORCE'"
        )
        cursor.execute("select seq4() from table(generator(rowcount=>100)) limit 0")

        assert cursor.fetchone() is None


def test_select_with_large_resultset(conn_cnx):
    col_count = 5
    row_count = 1000000
    random_seed = get_random_seed()

    sql_text = (
        "select seq4() as c1, "
        "uniform(-10000, 10000, random({})) as c2, "
        "randstr(5, random({})) as c3, "
        "randstr(10, random({})) as c4, "
        "uniform(-100000, 100000, random({})) as c5 "
        "from table(generator(rowcount=>{}))".format(
            random_seed, random_seed, random_seed, random_seed, row_count
        )
    )

    iterate_over_test_chunk("large_resultset", conn_cnx, sql_text, row_count, col_count)


def test_dict_cursor(conn_cnx):
    with conn_cnx() as cnx:
        with cnx.cursor(snowflake.connector.DictCursor) as c:
            c.execute("alter session set python_connector_query_result_format='ARROW'")

            # first test small result generated by GS
            ret = c.execute("select 1 as foo, 2 as bar").fetchone()
            assert ret["FOO"] == 1
            assert ret["BAR"] == 2

            # test larger result set
            row_index = 1
            for row in c.execute(
                "select row_number() over (order by val asc) as foo, "
                "row_number() over (order by val asc) as bar "
                "from (select seq4() as val from table(generator(rowcount=>10000)));"
            ):
                assert row["FOO"] == row_index
                assert row["BAR"] == row_index
                row_index += 1


def test_fetch_as_numpy_val(conn_cnx):
    with conn_cnx(numpy=True) as cnx:
        cursor = cnx.cursor()
        cursor.execute("alter session set python_connector_query_result_format='ARROW'")

        val = cursor.execute(
            """
select 1.23456::double, 1.3456::number(10, 4), 1234567::number(10, 0)
"""
        ).fetchone()
        assert isinstance(val[0], numpy.float64)
        assert val[0] == numpy.float64("1.23456")
        assert isinstance(val[1], numpy.float64)
        assert val[1] == numpy.float64("1.3456")
        assert isinstance(val[2], numpy.int64)
        assert val[2] == numpy.float64("1234567")

        val = cursor.execute(
            """
select '2019-08-10'::date, '2019-01-02 12:34:56.1234'::timestamp_ntz(4),
'2019-01-02 12:34:56.123456789'::timestamp_ntz(9), '2019-01-02 12:34:56.123456789'::timestamp_ntz(8)
"""
        ).fetchone()
        assert isinstance(val[0], numpy.datetime64)
        assert val[0] == numpy.datetime64("2019-08-10")
        assert isinstance(val[1], numpy.datetime64)
        assert val[1] == numpy.datetime64("2019-01-02 12:34:56.1234")
        assert isinstance(val[2], numpy.datetime64)
        assert val[2] == numpy.datetime64("2019-01-02 12:34:56.123456789")
        assert isinstance(val[3], numpy.datetime64)
        assert val[3] == numpy.datetime64("2019-01-02 12:34:56.12345678")


def get_random_seed():
    random.seed(datetime.now())
    return random.randint(0, 10000)


def iterate_over_test_chunk(
    test_name, conn_cnx, sql_text, row_count, col_count, eps=None, expected=None
):
    with conn_cnx() as json_cnx:
        with conn_cnx() as arrow_cnx:
            if expected is None:
                cursor_json = json_cnx.cursor()
                cursor_json.execute("alter session set query_result_format='JSON'")
                cursor_json.execute(
                    "alter session set python_connector_query_result_format='JSON'"
                )
                cursor_json.execute(sql_text)

            cursor_arrow = arrow_cnx.cursor()
            cursor_arrow.execute("alter session set use_cached_result=false")
            cursor_arrow.execute("alter session set query_result_format='ARROW_FORCE'")
            cursor_arrow.execute(
                "alter session set python_connector_query_result_format='ARROW_FORCE'"
            )
            cursor_arrow.execute(sql_text)
            assert cursor_arrow._query_result_format == "arrow"

            if expected is None:
                for _ in range(0, row_count):
                    json_res = cursor_json.fetchone()
                    arrow_res = cursor_arrow.fetchone()
                    for j in range(0, col_count):
                        if test_name == "float" and eps is not None:
                            assert abs(json_res[j] - arrow_res[j]) <= eps
                        else:
                            assert json_res[j] == arrow_res[j]
            else:
                # only support single column for now
                for i in range(0, row_count):
                    arrow_res = cursor_arrow.fetchone()
                    assert str(arrow_res[0]) == expected[i]


def init(conn_cnx, table, column, values):
    with conn_cnx() as json_cnx:
        cursor_json = json_cnx.cursor()
        column_with_seq = column[0] + "s number, " + column[1:]
        cursor_json.execute(
            "create or replace table {} {}".format(table, column_with_seq)
        )
        cursor_json.execute("insert into {} values {}".format(table, values))


def finish(conn_cnx, table):
    with conn_cnx() as json_cnx:
        cursor_json = json_cnx.cursor()
        cursor_json.execute("drop table IF EXISTS {};".format(table))
