#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2016 Snowflake Computing Inc. All right reserved.
#


def test_query_large_result_set(conn_cnx, db_parameters):
    """
    [s3] Get Large Result set
    """
    number_of_rows = 50000
    with conn_cnx(
            user=db_parameters['s3_user'],
            account=db_parameters['s3_account'],
            password=db_parameters['s3_password']) as cnx:
        cnx.cursor().execute("""
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
""".format(name=db_parameters['name']))
        cnx.cursor().execute("""
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
""".format(name=db_parameters['name'], number_of_rows=number_of_rows))

    try:
        sql = "select * from {name} order by 1 limit {number_of_rows}".format(
            name=db_parameters['name'],
            number_of_rows=number_of_rows)
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            # set the small first chunk max size to force using the large
            # result set
            result_first_chunk_max_size = 10
            rows_per_rowset = 8
            cnx.cursor().execute(
                "alter session set result_offline_chunks_disabled=false")
            cnx.cursor().execute(
                "alter session set RESULT_FIRST_CHUNK_MAX_SIZE = "
                "  {result_first_chunk_max_size}".format(
                    result_first_chunk_max_size=result_first_chunk_max_size))
            cnx.cursor().execute(
                "alter session set ROWS_PER_ROWSET={rows_per_rowset}".format(
                    rows_per_rowset=rows_per_rowset))
            cnx.cursor().execute(
                "alter session set CLIENT_RESULT_PREFETCH_THREADS=2"
            )
            # large result set fetch in the default mode
            result1 = []
            for rec in cnx.cursor().execute(sql):
                result1.append(rec)

            # large result set fetch in ijson mode
            result2 = []
            for rec in cnx.cursor().execute(sql, _use_ijson=True):
                result2.append(rec)

            # reset to the default
            cnx.cursor().execute(
                "alter session set RESULT_OFFLINE_CHUNKS_DISABLED=default")
            cnx.cursor().execute(
                "alter session set RESULT_FIRST_CHUNK_MAX_SIZE=default")
            cnx.cursor().execute("alter session set ROWS_PER_ROWSET=default")
            cnx.cursor().execute(
                "alter session set CLIENT_RESULT_PREFETCH_THREADS=default")

            result999 = []
            for rec in cnx.cursor().execute(sql):
                result999.append(rec)

            assert len(result1) == len(result999), (
                "result length is different: result1, and result999")
            for i, (x, y) in enumerate(zip(result1, result999)):
                assert x == y, "element {0}".format(i)

            assert len(result2) == len(result999), (
                "result length is different: result2, and result999")
            for i, (x, y) in enumerate(zip(result2, result999)):
                assert x == y, "element {0}".format(i)

    finally:
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            cnx.cursor().execute("drop table if exists {name}".format(
                name=db_parameters['name']))
