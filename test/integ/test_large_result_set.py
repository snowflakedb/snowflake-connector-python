#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import pytest
from mock import Mock

from snowflake.connector.telemetry import TelemetryField

from ..integ_helpers import drop_table
from ..randomize import random_string

pytestmark = pytest.mark.parallel

NUMBER_OF_ROWS = 50000

PREFETCH_THREADS = [8, 3, 1]


@pytest.fixture()
def ingest_data(request, conn_cnx, db_parameters):
    table_name = random_string(10, prefix="ingest_data_")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"""
    create table {table_name} (
        c0 int,
        c1 int,
        c2 int,
        c3 int,
        c4 int,
        c5 int,
        c6 int,
        c7 int,
        c8 int,
        c9 int)
    """)
        request.addfinalizer(drop_table(conn_cnx, table_name))
        cnx.cursor().execute(f"""
    insert into {table_name}
    select  random(100),
            random(100),
            random(100),
            random(100),
            random(100),
            random(100),
            random(100),
            random(100),
            random(100),
            random(100)
    from table(generator(rowCount=>{NUMBER_OF_ROWS}))
    """)
        first_val = cnx.cursor().execute(
            f"select c0 from {table_name} order by 1 limit 1").fetchone()[0]
        last_val = cnx.cursor().execute(
            f"select c9 from {table_name} order by 1 desc limit 1").fetchone()[0]

    return first_val, last_val, table_name


@pytest.mark.aws
@pytest.mark.parametrize('num_threads', PREFETCH_THREADS)
def test_query_large_result_set_n_threads(
        conn_cnx, ingest_data, num_threads):
    table_name = ingest_data[2]
    sql = f"select * from {table_name} order by 1"
    with conn_cnx(client_prefetch_threads=num_threads) as cnx:
        assert cnx.client_prefetch_threads == num_threads
        results = []
        for rec in cnx.cursor().execute(sql):
            results.append(rec)
        num_rows = len(results)
        assert NUMBER_OF_ROWS == num_rows
        assert results[0][0] == ingest_data[0]
        assert results[num_rows - 1][8] == ingest_data[1]


@pytest.mark.aws
def test_query_large_result_set(conn_cnx, ingest_data):
    """[s3] Gets Large Result set."""
    table_name = ingest_data[2]
    sql = f"select * from {table_name} order by 1"
    with conn_cnx() as cnx:
        telemetry_data = []
        add_log_mock = Mock()
        add_log_mock.side_effect = lambda datum: telemetry_data.append(
            datum)
        cnx._telemetry.add_log_to_batch = add_log_mock

        result2 = []
        for rec in cnx.cursor().execute(sql):
            result2.append(rec)

        num_rows = len(result2)
        assert result2[0][0] == ingest_data[0]
        assert result2[num_rows - 1][8] == ingest_data[1]

        result999 = []
        for rec in cnx.cursor().execute(sql):
            result999.append(rec)

        num_rows = len(result999)
        assert result999[0][0] == ingest_data[0]
        assert result999[num_rows - 1][8] == ingest_data[1]

        assert len(result2) == len(result999), (
            "result length is different: result2, and result999")
        for i, (x, y) in enumerate(zip(result2, result999)):
            assert x == y, "element {}".format(i)

        # verify that the expected telemetry metrics were logged
        expected = [TelemetryField.TIME_CONSUME_FIRST_RESULT,
                    TelemetryField.TIME_CONSUME_LAST_RESULT,
                    TelemetryField.TIME_PARSING_CHUNKS,
                    TelemetryField.TIME_DOWNLOADING_CHUNKS]
        for field in expected:
            assert sum([1 if x.message['type'] == field else 0 for x in
                        telemetry_data]) == 2, \
                "Expected three telemetry logs (one per query) " \
                "for log type {}".format(field)
