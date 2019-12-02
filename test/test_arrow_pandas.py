#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import pytest
import time
import pandas as pd
import random
from datetime import datetime
from decimal import Decimal
import itertools

try:
    import pyarrow
except ImportError as e:
    pass

try:
    from snowflake.connector.arrow_iterator import PyArrowIterator
    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True

SQL_ENABLE_ARROW = "alter session set python_connector_query_result_format='ARROW';"

EPSILON = 1e-8


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_num_one(conn_cnx):
    print('Test fetching one single dataframe')
    row_count = 50000
    col_count = 2
    random_seed = get_random_seed()
    sql_exec = ("select seq4() as c1, uniform(1, 10, random({})) as c2 from ".format(random_seed) +
                "table(generator(rowcount=>{})) order by c1, c2".format(row_count))
    fetch_pandas(conn_cnx, sql_exec, row_count, col_count, 'one')


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_scaled_tinyint(conn_cnx):
    cases = ["NULL", 0.11, -0.11, "NULL", 1.27, -1.28, "NULL"]
    table = "test_arrow_tiny_int"
    column = "(a number(5,2))"
    values = "(" + "),(".join([str(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one')
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_scaled_smallint(conn_cnx):
    cases = ["NULL", 0, 0.11, -0.11, "NULL", 32.767, -32.768, "NULL"]
    table = "test_arrow_small_int"
    column = "(a number(5,3))"
    values = "(" + "),(".join([str(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one')
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_scaled_int(conn_cnx):
    cases = ["NULL", 0, "NULL", 0.123456789, -0.123456789, 2.147483647, -2.147483648, "NULL"]
    table = "test_arrow_int"
    column = "(a number(10,9))"
    values = "(" + "),(".join([str(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one')
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_scaled_bigint(conn_cnx):
    cases = ["NULL", 0, "NULL",
             "1.23456789E-10", "-1.23456789E-10",
             "2.147483647E-9", "-2.147483647E-9",
             "-1e-9", "1e-9",
             "1e-8", "-1e-8",
             "NULL"]
    table = "test_arrow_big_int"
    column = "(a number(38,18))"
    values = "(" + "),(".join([str(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one', epsilon=EPSILON)
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_decimal(conn_cnx):
    cases = ["NULL", 0, "NULL",
             "10000000000000000000000000000000000000",
             "12345678901234567890123456789012345678",
             "99999999999999999999999999999999999999",
             "-1000000000000000000000000000000000000",
             "-2345678901234567890123456789012345678",
             "-9999999999999999999999999999999999999",
             "NULL"]
    table = "test_arrow_decimal"
    column = "(a number(38,0))"
    values = "(" + "),(".join([str(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one', data_type='decimal')
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_scaled_decimal(conn_cnx):
    cases = ["NULL", 0, "NULL",
             "1.0000000000000000000000000000000000000",
             "1.2345678901234567890123456789012345678",
             "9.9999999999999999999999999999999999999",
             "-1.000000000000000000000000000000000000",
             "-2.345678901234567890123456789012345678",
             "-9.999999999999999999999999999999999999",
             "NULL"]
    table = "test_arrow_decimal"
    column = "(a number(38,37))"
    values = "(" + "),(".join([str(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one', data_type='decimal')
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_boolean(conn_cnx):
    cases = ["NULL", True, "NULL", False, True, True, "NULL", True, False, "NULL"]
    table = "test_arrow_boolean"
    column = "(a boolean)"
    values = "(" + "),(".join([str(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one')
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_double(conn_cnx):
    cases = ["NULL",
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
             "NULL"]
    table = "test_arrow_double"
    column = "(a double)"
    values = "(" + "),(".join([str(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one')
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
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
        "[\n" +
        "  10,\n" +
        "  20,\n" +
        "  30\n" +
        "]",
        "[\n" +
        "  undefined,\n" +
        "  \"hello\",\n" +
        "  3.000000000000000e+00,\n" +
        "  4,\n" +
        "  5\n" +
        "]",
        "[]",
        "{\n" +
        "  \"a\": 1,\n" +
        "  \"b\": \"BBBB\"\n" +
        "}",
        "{\n" +
        "  \"Key_One\": null,\n" +
        "  \"Key_Three\": \"null\"\n" +
        "}",
        "3.2",
        "{\n" +
        "  \"a\": null\n" +
        "}",
        "100"
    ]
    with conn_cnx() as cnx_table:
        # fetch dataframe with new arrow support
        cursor_table = cnx_table.cursor()
        cursor_table.execute(SQL_ENABLE_ARROW)
        cursor_table.execute(sql_text)
        df_new = cursor_table.fetch_pandas_all()
        col_new = df_new.iloc[0]
        for j, c_new in enumerate(col_new):
            assert res[j] == c_new, '{} column: original value is {}, new value is {}, ' \
                                    'values are not equal'.format(j, res[j], c_new)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_date(conn_cnx):
    cases = ["NULL",
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
             "NULL"]
    table = "test_arrow_date"
    column = "(a date)"
    values = "(" + "),(".join([str(i) if i == "NULL" else "'{}'".format(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one', data_type='date')
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
@pytest.mark.parametrize("scale",
                         [i for i in range(10)])
def test_time(conn_cnx, scale):
    cases = ["NULL",
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
             "NULL"]
    table = "test_arrow_time"
    column = "(a time({}))".format(scale)
    values = "(" + "),(".join([str(i) if i == "NULL" else "'{}'".format(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one', data_type='time', scale=scale)
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
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
        "NULL"
    ]
    table = "test_arrow_timestamp"
    column = "(a timestampntz({}))".format(scale)
    values = "(" + "),(".join([str(i) if i == "NULL" else "'{}'".format(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one', data_type='timestamp', scale=scale)
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
@pytest.mark.parametrize("scale, timezone",
                         itertools.product(
                             [i for i in range(10)],
                             [
                               "UTC",
                               "America/New_York",
                               "Australia/Sydney"
                              ]))
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
        "NULL"
    ]
    table = "test_arrow_timestamp"
    column = "(a timestamptz({}))".format(scale)
    values = "(" + "),(".join([str(i) if i == "NULL" else "'{}'".format(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values, timezone=timezone)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one', data_type='timestamptz', scale=scale, timezone=timezone)
    finish(conn_cnx, table)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
@pytest.mark.parametrize("scale, timezone",
                         itertools.product(
                             [i for i in range(10)],
                             ["UTC",
                              "America/New_York",
                              "Australia/Sydney"
                              ]))
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
        "NULL"
    ]
    table = "test_arrow_timestamp"
    column = "(a timestampltz({}))".format(scale)
    values = "(" + "),(".join([str(i) if i == "NULL" else "'{}'".format(i) for i in cases]) + ")"
    init(conn_cnx, table, column, values, timezone=timezone)
    sql_text = "select * from {}".format(table)
    validate_pandas(conn_cnx, sql_text, cases, 1, 'one', data_type='timestamp', scale=scale, timezone=timezone)
    finish(conn_cnx, table)


def validate_pandas(conn_cnx, sql, cases, col_count, method='one', data_type='float', epsilon=None, scale=0, timezone=None):
    """
        test parameters can be customized
        @param conn_cnx: connection
        @param sql: SQL command for execution
        @param cases: test cases
        @param col_count: # of columns in dataframe
        @param method:
            1. If method is 'batch', we fetch dataframes in batch.
            2. If method is 'one', we fetch a single dataframe containing all data
        @param data_type: defines how to compare values
        @param epsilon: for compare double values
        @param scale: for compare time values with scale
        @param timezone: for timestamp ltz
    """

    row_count = len(cases)
    assert col_count != 0, '# of columns should be larger than 0'
    with conn_cnx() as cnx_table:
        # fetch dataframe with new arrow support
        cursor_table = cnx_table.cursor()
        cursor_table.execute(SQL_ENABLE_ARROW)
        cursor_table.execute(sql)

        # build dataframe
        total_rows, total_batches = 0, 0
        start_time = time.time()
        if method == 'one':
            df_new = cursor_table.fetch_pandas_all()
            total_rows = df_new.shape[0]
        else:
            for df_new in cursor_table.fetch_pandas_batches():
                total_rows += df_new.shape[0]
                total_batches += 1
        end_time = time.time()
        print('new way (fetching {}) took {}s'.format(method, end_time - start_time))
        if method == 'batch':
            print('new way has # of batches : {}'.format(total_batches))
        cursor_table.close()
        assert total_rows == row_count, 'there should be {} rows, but {} rows'.format(row_count, total_rows)

        # verify the correctness
        # only do it when fetch one dataframe
        if method == 'one':
            assert (row_count, col_count) == df_new.shape, 'the shape of old dataframe is {}, ' \
                                                           'the shape of new dataframe is {}, ' \
                                                           'shapes are not equal'.format((row_count, col_count),
                                                                                         df_new.shape)

            for i in range(row_count):
                for j in range(col_count):
                    c_new = df_new.iat[i, j]
                    if cases[i] == "NULL":
                        assert c_new is None or pd.isnull(c_new), '{} row, {} column: original value is NULL, ' \
                                                                  'new value is {}, values are not equal'.format(
                            i, j, c_new)
                    else:
                        if data_type == 'float':
                            c_case = float(cases[i])
                        elif data_type == 'decimal':
                            c_case = Decimal(cases[i])
                        elif data_type == 'date':
                            c_case = datetime.strptime(cases[i], '%Y-%m-%d').date()
                        elif data_type == 'time':
                            time_str_len = 8 if scale == 0 else 9 + scale
                            c_case = cases[i].strip()[:time_str_len]
                            c_new = str(c_new).strip()[:time_str_len]
                            assert c_case == c_new, '{} row, {} column: original value is {}, ' \
                                                    'new value is {}, ' \
                                                    'values are not equal'.format(i, j, cases[i],
                                                                                  c_new)
                            break
                        elif data_type.startswith('timestamp'):
                            time_str_len = 19 if scale == 0 else 20 + scale
                            if timezone:
                                c_case = pd.Timestamp(cases[i][:time_str_len], tz=timezone)
                                if data_type == 'timestamptz':
                                    c_case = c_case.tz_convert('UTC')
                                    c_case = c_case.tz_localize(None)
                            else:
                                c_case = pd.Timestamp(cases[i][:time_str_len])
                            assert c_case == c_new, '{} row, {} column: original value is {}, new value is {}, ' \
                                                    'values are not equal'.format(i, j, cases[i], c_new)
                            break
                        else:
                            c_case = cases[i]
                        if epsilon is None:
                            assert c_case == c_new, '{} row, {} column: original value is {}, new value is {}, ' \
                                                    'values are not equal'.format(i, j, cases[j], c_new)
                        else:
                            assert abs(c_case - c_new) < epsilon, '{} row, {} column: original value is {}, ' \
                                                                  'new value is {}, epsilon is {} \
                            values are not equal'.format(i, j, cases[j], c_new, epsilon)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_num_batch(conn_cnx):
    print('Test fetching dataframes in batch')
    row_count = 1000000
    col_count = 2
    random_seed = get_random_seed()
    sql_exec = ("select seq4() as c1, uniform(1, 10, random({})) as c2 from ".format(random_seed) +
                "table(generator(rowcount=>{})) order by c1, c2".format(row_count))
    fetch_pandas(conn_cnx, sql_exec, row_count, col_count, 'batch')


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_empty(conn_cnx):
    print('Test fetch empty dataframe')
    with conn_cnx() as cnx:
        cursor = cnx.cursor()
        cursor.execute(SQL_ENABLE_ARROW)
        cursor.execute("select seq4() from table(generator(rowcount=>1)) limit 0")
        assert cursor.fetch_pandas_all() is None, 'the result is not none'


def get_random_seed():
    random.seed(datetime.now())
    return random.randint(0, 10000)


def fetch_pandas(conn_cnx, sql, row_count, col_count, method='one'):
    """
        test parameters can be customized
        @param conn_cnx: connection
        @param sql: SQL command for execution
        @param row_count: # of total rows combining all dataframes
        @param col_count: # of columns in dataframe
        @param method:
            1. If method is 'batch', we fetch dataframes in batch.
            2. If method is 'one', we fetch a single dataframe containing all data
    """

    assert row_count != 0, '# of rows should be larger than 0'
    assert col_count != 0, '# of columns should be larger than 0'

    with conn_cnx() as cnx_row:
        with conn_cnx() as cnx_table:
            # fetch dataframe by fetching row by row
            cursor_row = cnx_row.cursor()
            cursor_row.execute(SQL_ENABLE_ARROW)
            cursor_row.execute(sql)

            # build dataframe
            # actually its exec time would be different from `pd.read_sql()` via sqlalchemy as most people use
            # further perf test can be done separately
            start_time = time.time()
            rows = 0
            if method == 'one':
                df_old = pd.DataFrame(cursor_row.fetchall(), columns=['c{}'.format(i) for i in range(col_count)])
            else:
                print("use fetchmany")
                while True:
                    dat = cursor_row.fetchmany(10000)
                    if not dat:
                        break
                    else:
                        df_old = pd.DataFrame(dat, columns=['c{}'.format(i) for i in range(col_count)])
                        rows += df_old.shape[0]
            end_time = time.time()
            print('The original way took {}s'.format(end_time - start_time))
            cursor_row.close()

            # fetch dataframe with new arrow support
            cursor_table = cnx_table.cursor()
            cursor_table.execute(SQL_ENABLE_ARROW)
            cursor_table.execute(sql)

            # build dataframe
            total_rows, total_batches = 0, 0
            start_time = time.time()
            if method == 'one':
                df_new = cursor_table.fetch_pandas_all()
                total_rows = df_new.shape[0]
            else:
                for df_new in cursor_table.fetch_pandas_batches():
                    total_rows += df_new.shape[0]
                    total_batches += 1
            end_time = time.time()
            print('new way (fetching {}) took {}s'.format(method, end_time - start_time))
            if method == 'batch':
                print('new way has # of batches : {}'.format(total_batches))
            cursor_table.close()
            assert total_rows == row_count, 'there should be {} rows, but {} rows'.format(row_count, total_rows)

            # verify the correctness
            # only do it when fetch one dataframe
            if method == 'one':
                assert df_old.shape == df_new.shape, 'the shape of old dataframe is {}, the shape of new dataframe is {}, \
                                     shapes are not equal'.format(df_old.shape, df_new.shape)

                for i in range(row_count):
                    col_old = df_old.iloc[i]
                    col_new = df_new.iloc[i]
                    for j, (c_old, c_new) in enumerate(zip(col_old, col_new)):
                        assert c_old == c_new, '{} row, {} column: old value is {}, new value is {}, \
                                              values are not equal'.format(i, j, c_old, c_new)
            else:
                assert rows == total_rows, 'the number of rows are not equal {} vs {}'.format(rows, total_rows)


def init(conn_cnx, table, column, values, timezone=None):
    with conn_cnx() as json_cnx:
        cursor_json = json_cnx.cursor()
        if timezone is not None:
            cursor_json.execute("ALTER SESSION SET TIMEZONE = '{}'".format(timezone))
        cursor_json.execute("create or replace table {} {}".format(table, column))
        cursor_json.execute("insert into {} values {}".format(table, values))


def finish(conn_cnx, table):
    with conn_cnx() as json_cnx:
        cursor_json = json_cnx.cursor()
        cursor_json.execute("drop table if exists {};".format(table))
