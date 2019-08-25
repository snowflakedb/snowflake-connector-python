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

try:
    import pyarrow
except ImportError as e:
    pass

try:
    from snowflake.connector.arrow_iterator import PyArrowIterator
    no_arrow_iterator_ext = False
except ImportError:
    no_arrow_iterator_ext = True

sql_arrow = "alter session set query_result_format='ARROW_FORCE';"

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
    fetch_pandas(conn_cnx, sql_exec,row_count, col_count, 'one')

@pytest.mark.skipif(
    no_arrow_iterator_ext,
    reason="arrow_iterator extension is not built.")
def test_num_batch(conn_cnx):
    print('Test fetching dataframes in batch')
    row_count = 50000
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
        cursor.execute(sql_arrow)
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
            cursor_row.execute(sql_arrow)
            cursor_row.execute(sql)

            # build dataframe
            # actually its exec time would be different from `pd.read_sql()` via sqlalchemy as most people use
            # further perf test can be done separately
            start_time = time.time()
            df_old = pd.DataFrame(cursor_row.fetchall(), columns=['c{}'.format(i) for i in range(col_count)])
            end_time = time.time()
            print('The original way took {}s'.format(end_time - start_time))
            cursor_row.close()

            # fetch dataframe with new arrow support
            cursor_table = cnx_table.cursor()
            cursor_table.execute(sql_arrow)
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
            if method == 'one' :
                assert df_old.shape == df_new.shape, 'the shape of old dataframe is {}, the shape of new dataframe is {}, \
                                     shapes are not equal'.format(df_old.shape, df_new.shape)

                for i in range(row_count):
                    col_old = df_old.iloc[i]
                    col_new = df_new.iloc[i]
                    for j, (c_old, c_new) in enumerate(zip(col_old, col_new)):
                        assert c_old == c_new, '{} row, {} column: old value is {}, new value is {}, \
                                              values are not equal'.format(i, j, c_old, c_new)