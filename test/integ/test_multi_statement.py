#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import time

import pytest

from snowflake.connector import ProgrammingError, errors

try:  # pragma: no cover
    from snowflake.connector.constants import QueryStatus
except ImportError:
    QueryStatus = None

from ..randomize import random_string


@pytest.mark.skipolddriver
def test_multi_statement_wrong_count(conn_cnx):
    """Tries to send the wrong number of statements."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            with pytest.raises(
                errors.ProgrammingError,
                match="Actual statement count 2 did not match the desired statement count 1.",
            ):
                cur.execute("select 1; select 2")

            with pytest.raises(
                errors.ProgrammingError,
                match="Actual statement count 2 did not match the desired statement count 1.",
            ):
                cur.execute("alter session set MULTI_STATEMENT_COUNT=2; select 1;")

            cur.execute("alter session set MULTI_STATEMENT_COUNT=5")
            with pytest.raises(
                errors.ProgrammingError,
                match="Actual statement count 1 did not match the desired statement count 5.",
            ):
                cur.execute("select 1;")

            with pytest.raises(
                errors.ProgrammingError,
                match="Actual statement count 3 did not match the desired statement count 5.",
            ):
                cur.execute("select 1; select 2; select 3;")


@pytest.mark.skipolddriver
def test_multi_statement_basic(conn_cnx):
    """Selects fixed integer data using statement level parameters."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute("select 1; select 2; select 'a';", _num_statements=3)
            assert cur.fetchall()[0][0] == 1
            assert cur.nextset() == cur
            assert cur.fetchall()[0][0] == 2
            assert cur.nextset() == cur
            assert cur.fetchall()[0][0] == "a"
            assert cur.nextset() is None
            assert not cur.fetchall()


def _check_results(cursor, results):
    assert cursor.sfqid, "Snowflake query id is None"
    assert cursor.rowcount == 3, "the number of records"
    assert results[0] == 65432, "the first result was wrong"
    assert results[1] == 98765, "the second result was wrong"
    assert results[2] == 123456, "the third result was wrong"


@pytest.mark.skipolddriver
def test_insert_select_multi(conn_cnx, db_parameters):
    """Naive use of multi-statement to check multiple SQL functions."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute("alter session set MULTI_STATEMENT_COUNT = 0;")
            table_name = random_string(5, "test_multi_table_").upper()
            cur.execute(
                "use schema {db}.{schema};\n"
                "create table {name} (aa int);\n"
                "insert into {name}(aa) values(123456),(98765),(65432);\n"
                "select aa from {name} order by aa;\n"
                "drop table {name};".format(
                    db=db_parameters["database"],
                    schema=db_parameters["schema"]
                    if "schema" in db_parameters
                    else "PUBLIC",
                    name=table_name,
                )
            )

            assert cur.fetchall()[0][0] == "Statement executed successfully."
            assert cur.nextset()
            assert cur.fetchall()[0][0] == f"Table {table_name} successfully created."
            assert cur.nextset()
            assert cur.fetchall()[0][0] == 3
            assert cur.nextset()
            results = [rec[0] for rec in cur]
            _check_results(cur, results)
            assert cur.nextset()
            assert cur.fetchall()[0][0] == f"{table_name} successfully dropped."


@pytest.mark.skipolddriver
def test_binding_multi(conn_cnx):
    """Tests using pyformat and qmark style bindings with multi-statement"""
    test_string = "select {s}; select {s}, {s}; select {s}, {s}, {s};"
    for style in ("pyformat", "qmark"):
        with conn_cnx(paramstyle=style) as con:
            with con.cursor() as cur:
                sql = test_string.format(s="%s" if style == "pyformat" else "?")
                cur.execute(sql, (10, 20, 30, "a", "b", "c"), _num_statements=3)
                assert cur.fetchall()[0] == (10,)
                assert cur.nextset()
                assert cur.fetchall()[0] == (20, 30)
                assert cur.nextset()
                assert cur.fetchall()[0] == ("a", "b", "c")
                assert cur.nextset() is None
                assert not cur.fetchall()


@pytest.mark.skipolddriver
def test_async_exec_multi(conn_cnx):
    """Tests whether async execution query works within a multi-statement"""
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async(
                "select 1; select 2; select count(*) from table(generator(timeLimit => 5)); select 'b';",
                _num_statements=4,
            )
            q_id = cur.sfqid
            status = con.get_query_status(q_id)
            assert con.is_still_running(status)
    time.sleep(5)
    with conn_cnx() as con:
        with con.cursor() as cur:
            for _ in range(25):
                status = con.get_query_status(q_id)
                if status == QueryStatus.SUCCESS:
                    break
                time.sleep(1)
            else:
                pytest.fail(
                    f"We should have broke out of this loop, final query status: {status}"
                )

            status = con.get_query_status_throw_if_error(q_id)
            assert status == QueryStatus.SUCCESS

            cur.get_results_from_sfqid(q_id)
            assert cur.fetchall() == [(1,)]
            assert cur.nextset() == cur
            assert cur.fetchall() == [(2,)]
            assert cur.nextset() == cur
            assert cur.fetchall()[0][0] > 0
            assert cur.nextset() == cur
            assert cur.fetchall() == [("b",)]
            assert cur.nextset() is None
            assert not cur.fetchall()


@pytest.mark.skipolddriver
def test_async_error_multi(conn_cnx):
    """
    Runs a query that will fail to execute and then tests that if we tried to get results for the query
    then that would raise an exception. It also tests QueryStatus related functionality too.
    """
    with conn_cnx() as con:
        with con.cursor() as cur:
            sql = "select 1; select * from nonexistentTable"
            cur.execute_async(sql)
            q_id = cur.sfqid
            with pytest.raises(ProgrammingError) as sync_error:
                cur.execute(sql)
            while con.is_still_running(con.get_query_status(q_id)):
                time.sleep(1)
            status = con.get_query_status(q_id)
            assert status == QueryStatus.FAILED_WITH_ERROR
            assert con.is_an_error(status)
            with pytest.raises(ProgrammingError) as e1:
                con.get_query_status_throw_if_error(q_id)
            assert sync_error.value.errno != -1
            with pytest.raises(ProgrammingError) as e2:
                cur.get_results_from_sfqid(q_id)
            assert e1.value.errno == e2.value.errno == sync_error.value.errno


@pytest.mark.skipolddriver
def test_mix_sync_async_multi(conn_cnx):
    """Tests sending multiple multi-statement async queries at the same time."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            # Setup
            cur.execute("alter session set MULTI_STATEMENT_COUNT = 0")
            cur.execute("alter session set CLIENT_TIMESTAMP_TYPE_MAPPING=TIMESTAMP_TZ")
            try:
                cur.execute(
                    "create or replace table smallTable (colA string, colB int);"
                    "create or replace table uselessTable (colA string, colB int);"
                )
                for table in ["smallTable", "uselessTable"]:
                    cur.execute(
                        "insert into {t} values('row1', 1);"
                        "insert into {t} values('row2', 2);"
                        "insert into {t} values('row3', 3);".format(t=table)
                    )
                cur.execute_async("select 1; select 'a'; select * from smallTable;")
                sf_qid1 = cur.sfqid
                cur.execute_async("select 2; select 'b'; select * from uselessTable")
                sf_qid2 = cur.sfqid
                # Wait until the 2 queries finish
                while con.is_still_running(con.get_query_status(sf_qid1)):
                    time.sleep(1)
                while con.is_still_running(con.get_query_status(sf_qid2)):
                    time.sleep(1)
                cur.execute("drop table uselessTable")
                assert cur.fetchall() == [("USELESSTABLE successfully dropped.",)]
                cur.get_results_from_sfqid(sf_qid1)
                assert cur.fetchall() == [(1,)]
                assert cur.nextset() == cur
                assert cur.fetchall() == [("a",)]
                assert cur.nextset() == cur
                assert cur.fetchall() == [("row1", 1), ("row2", 2), ("row3", 3)]
                assert cur.nextset() is None
                assert not cur.fetchall()
                cur.get_results_from_sfqid(sf_qid2)
                assert cur.fetchall() == [(2,)]
                assert cur.nextset() == cur
                assert cur.fetchall() == [("b",)]
                assert cur.nextset() == cur
                assert cur.fetchall() == [("row1", 1), ("row2", 2), ("row3", 3)]
                assert cur.nextset() is None
                assert not cur.fetchall()
            finally:
                for table in ["smallTable", "uselessTable"]:
                    cur.execute(f"drop table if exists {table}")


@pytest.mark.skipolddriver
def test_done_caching_multi(conn_cnx):
    """Tests whether get status caching is working as expected."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute("alter session set MULTI_STATEMENT_COUNT=0;")
            cur.execute_async(
                "select 1; select 'a'; select count(*) from table(generator(timeLimit => 5));"
            )
            qid1 = cur.sfqid
            cur.execute_async(
                "select 2; select 'b'; select count(*) from table(generator(timeLimit => 10));"
            )
            qid2 = cur.sfqid
            assert len(con._async_sfqids) == 2
            time.sleep(5)
            while con.is_still_running(con.get_query_status(qid1)):
                time.sleep(1)
            assert con.get_query_status(qid1) == QueryStatus.SUCCESS
            assert len(con._async_sfqids) == 1
            assert len(con._done_async_sfqids) == 1
            time.sleep(5)
            while con.is_still_running(con.get_query_status(qid2)):
                time.sleep(1)
            assert con.get_query_status(qid2) == QueryStatus.SUCCESS
            assert len(con._async_sfqids) == 0
            assert len(con._done_async_sfqids) == 2
            assert con._all_async_queries_finished()
