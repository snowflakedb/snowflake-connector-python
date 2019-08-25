#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import random
import pytest
from datetime import datetime
try:
    from snowflake.connector.arrow_iterator import PyArrowChunkIterator
    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_select_with_num(conn_cnx): 
    col_count = 2
    row_count = 50000
    random_seed = get_random_seed()
    sql_text = ("select seq4() as c1, uniform(1, 10, random({})) as c2 from ".format(random_seed) +
                "table(generator(rowcount=>{})) order by c1".format(row_count))
    iterate_over_test_chunk("num", conn_cnx, sql_text, row_count, col_count)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_select_with_string(conn_cnx):
    col_count = 2
    row_count = 50000
    random_seed = get_random_seed()
    length = random.randint(1, 10)
    sql_text = ("select seq4() as c1, randstr({}, random({})) as c2 from ".format(length, random_seed) +
                "table(generator(rowcount=>50000)) order by c1")
    iterate_over_test_chunk("string", conn_cnx, sql_text, row_count, col_count)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_select_with_bool(conn_cnx):
    col_count = 2
    row_count = 50000
    random_seed = get_random_seed()
    sql_text = ("select seq4() as c1, as_boolean(uniform(0, 1, random({}))) as c2 from ".format(random_seed) +
                "table(generator(rowcount=>{})) order by c1".format(row_count))
    iterate_over_test_chunk("bool", conn_cnx, sql_text, row_count, col_count)


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_select_with_float(conn_cnx):
    col_count = 2
    row_count = 50000
    random_seed = get_random_seed()
    pow_val = random.randint(0, 10)
    val_len = random.randint(0, 16)
    # if we assign val_len a larger value like 20, then the precision difference between c++ and python will become
    # very obvious so if we meet some error in this test in the future, please check that whether it is caused by
    # different precision between python and c++
    val_range = random.randint(0, 10**val_len)
    
    sql_text = ("select seq4() as c1, as_double(uniform({}, {}, random({})))/{} as c2 from ".format(-val_range, val_range, random_seed, 10**pow_val) +
                "table(generator(rowcount=>{})) order by c1".format(row_count))
    iterate_over_test_chunk("float", conn_cnx, sql_text, row_count, col_count, eps=10**(-pow_val+1))


@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_select_with_empty_resultset(conn_cnx):
    with conn_cnx() as cnx:
        cursor = cnx.cursor()
        cursor.execute("alter session set query_result_format='ARROW_FORCE'")
        cursor.execute("select seq4() from table(generator(rowcount=>100)) limit 0")

        assert cursor.fetchone() is None


def get_random_seed():
    random.seed(datetime.now())
    return random.randint(0, 10000)


def iterate_over_test_chunk(test_name, conn_cnx, sql_text, row_count, col_count, eps=None): 
    with conn_cnx() as json_cnx:
        with conn_cnx() as arrow_cnx:
            cursor_json = json_cnx.cursor()
            cursor_json.execute("alter session set query_result_format='JSON'")
            cursor_json.execute(sql_text)

            cursor_arrow = arrow_cnx.cursor()
            cursor_arrow.execute("alter session set query_result_format='ARROW_FORCE'")
            cursor_arrow.execute(sql_text)

            for i in range(0, row_count):
                json_res = cursor_json.fetchone()
                arrow_res = cursor_arrow.fetchone()
                for j in range(0, col_count):
                    if test_name == "float" and eps is not None:
                        assert abs(json_res[j] - arrow_res[j]) <= eps
                    else:
                        assert json_res[j] == arrow_res[j]
