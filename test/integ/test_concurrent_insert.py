#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from concurrent.futures.thread import ThreadPoolExecutor
from logging import getLogger

import pytest

import snowflake.connector
from snowflake.connector.errors import ProgrammingError

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except Exception:
    CONNECTION_PARAMETERS_ADMIN = {}

logger = getLogger(__name__)


def _concurrent_insert(meta):
    """Concurrent insert method."""
    cnx = snowflake.connector.connect(
        user=meta["user"],
        password=meta["password"],
        host=meta["host"],
        port=meta["port"],
        account=meta["account"],
        database=meta["database"],
        schema=meta["schema"],
        timezone="UTC",
        protocol="http",
    )
    try:
        cnx.cursor().execute("use warehouse {}".format(meta["warehouse"]))
        table = meta["table"]
        sql = "insert into {name} values(%(c1)s, %(c2)s)".format(name=table)
        logger.debug(sql)
        cnx.cursor().execute(
            sql,
            {
                "c1": meta["idx"],
                "c2": "test string " + meta["idx"],
            },
        )
        meta["success"] = True
        logger.debug("Succeeded process #%s", meta["idx"])
    except Exception:
        logger.exception("failed to insert into a table [%s]", table)
        meta["success"] = False
    finally:
        cnx.close()
    return meta


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="The user needs a privilege of create warehouse.",
)
def test_concurrent_insert(conn_cnx, db_parameters):
    """Concurrent insert tests. Inserts block on the one that's running."""
    number_of_threads = 22  # change this to increase the concurrency
    expected_success_runs = number_of_threads - 1
    cnx_array = []

    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
create or replace warehouse {}
warehouse_type=standard
warehouse_size=small
""".format(
                    db_parameters["name_wh"]
                )
            )
            sql = """
create or replace table {name} (c1 integer, c2 string)
""".format(
                name=db_parameters["name"]
            )
            cnx.cursor().execute(sql)
            for i in range(number_of_threads):
                cnx_array.append(
                    {
                        "host": db_parameters["host"],
                        "port": db_parameters["port"],
                        "user": db_parameters["user"],
                        "password": db_parameters["password"],
                        "account": db_parameters["account"],
                        "database": db_parameters["database"],
                        "schema": db_parameters["schema"],
                        "table": db_parameters["name"],
                        "idx": str(i),
                        "warehouse": db_parameters["name_wh"],
                    }
                )

            pool = ThreadPoolExecutor(number_of_threads)
            results = list(pool.map(_concurrent_insert, cnx_array))
            pool.shutdown()
            success = 0
            for record in results:
                success += 1 if record["success"] else 0

            # 21 threads or more
            assert success >= expected_success_runs, "Number of success run"

            c = cnx.cursor()
            sql = "select * from {name} order by 1".format(name=db_parameters["name"])
            c.execute(sql)
            for rec in c:
                logger.debug(rec)
            c.close()

    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "drop table if exists {}".format(db_parameters["name"])
            )
            cnx.cursor().execute(
                "drop warehouse if exists {}".format(db_parameters["name_wh"])
            )


def _concurrent_insert_using_connection(meta):
    connection = meta["connection"]
    idx = meta["idx"]
    name = meta["name"]
    try:
        connection.cursor().execute(
            "INSERT INTO {name} VALUES(%s, %s)".format(name=name),
            (idx, "test string{}".format(idx)),
        )
    except ProgrammingError as e:
        if e.errno != 619:  # SQL Execution Canceled
            raise


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="The user needs a privilege of create warehouse.",
)
def test_concurrent_insert_using_connection(conn_cnx, db_parameters):
    """Concurrent insert tests using the same connection."""
    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
create or replace warehouse {}
warehouse_type=standard
warehouse_size=small
""".format(
                    db_parameters["name_wh"]
                )
            )
            cnx.cursor().execute(
                """
CREATE OR REPLACE TABLE {name} (c1 INTEGER, c2 STRING)
""".format(
                    name=db_parameters["name"]
                )
            )
            number_of_threads = 5
            metas = []
            for i in range(number_of_threads):
                metas.append(
                    {
                        "connection": cnx,
                        "idx": i,
                        "name": db_parameters["name"],
                    }
                )
            pool = ThreadPoolExecutor(number_of_threads)
            pool.map(_concurrent_insert_using_connection, metas)
            pool.shutdown()
            cnt = 0
            for _ in cnx.cursor().execute(
                "SELECT * FROM {name} ORDER BY 1".format(name=db_parameters["name"])
            ):
                cnt += 1
            assert (
                cnt <= number_of_threads
            ), "Number of records should be less than the number of threads"
            assert cnt > 0, "Number of records should be one or more number of threads"
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "drop table if exists {}".format(db_parameters["name"])
            )
            cnx.cursor().execute(
                "drop warehouse if exists {}".format(db_parameters["name_wh"])
            )
