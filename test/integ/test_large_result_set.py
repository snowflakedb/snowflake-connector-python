#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import pytest
from mock import Mock

from snowflake.connector.telemetry import TelemetryField

NUMBER_OF_ROWS = 50000

PREFETCH_THREADS = [8, 3, 1]


@pytest.fixture()
def ingest_data(request, conn_cnx, db_parameters):
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        cnx.cursor().execute(
            """
    create or replace table {name} (
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
    """.format(
                name=db_parameters["name"]
            )
        )
        cnx.cursor().execute(
            """
    insert into {name}
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
    from table(generator(rowCount=>{number_of_rows}))
    """.format(
                name=db_parameters["name"], number_of_rows=NUMBER_OF_ROWS
            )
        )
        first_val = (
            cnx.cursor()
            .execute(
                "select c0 from {name} order by 1 limit 1".format(
                    name=db_parameters["name"]
                )
            )
            .fetchone()[0]
        )
        last_val = (
            cnx.cursor()
            .execute(
                "select c9 from {name} order by 1 desc limit 1".format(
                    name=db_parameters["name"]
                )
            )
            .fetchone()[0]
        )

    def fin():
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            cnx.cursor().execute(
                "drop table if exists {name}".format(name=db_parameters["name"])
            )

    request.addfinalizer(fin)
    return first_val, last_val


@pytest.mark.aws
@pytest.mark.parametrize("num_threads", PREFETCH_THREADS)
def test_query_large_result_set_n_threads(
    conn_cnx, db_parameters, ingest_data, num_threads
):
    sql = "select * from {name} order by 1".format(name=db_parameters["name"])
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
        client_prefetch_threads=num_threads,
    ) as cnx:
        assert cnx.client_prefetch_threads == num_threads
        results = []
        for rec in cnx.cursor().execute(sql):
            results.append(rec)
        num_rows = len(results)
        assert NUMBER_OF_ROWS == num_rows
        assert results[0][0] == ingest_data[0]
        assert results[num_rows - 1][8] == ingest_data[1]


@pytest.mark.aws
def test_query_large_result_set(conn_cnx, db_parameters, ingest_data):
    """[s3] Gets Large Result set."""
    sql = "select * from {name} order by 1".format(name=db_parameters["name"])
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        telemetry_data = []
        add_log_mock = Mock()
        add_log_mock.side_effect = lambda datum: telemetry_data.append(datum)
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

        assert len(result2) == len(
            result999
        ), "result length is different: result2, and result999"
        for i, (x, y) in enumerate(zip(result2, result999)):
            assert x == y, "element {}".format(i)

        # verify that the expected telemetry metrics were logged
        expected = [
            TelemetryField.TIME_CONSUME_FIRST_RESULT,
            TelemetryField.TIME_CONSUME_LAST_RESULT,
            TelemetryField.TIME_PARSING_CHUNKS,
            TelemetryField.TIME_DOWNLOADING_CHUNKS,
        ]
        for field in expected:
            assert (
                sum([1 if x.message["type"] == field else 0 for x in telemetry_data])
                == 2
            ), (
                "Expected three telemetry logs (one per query) "
                "for log type {}".format(field)
            )
