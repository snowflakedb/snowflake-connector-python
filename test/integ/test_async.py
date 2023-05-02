#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import time

import pytest

from snowflake.connector import ProgrammingError

# Mark all tests in this file to time out after 2 minutes to prevent hanging forever
pytestmark = [pytest.mark.timeout(120), pytest.mark.skipolddriver]

try:  # pragma: no cover
    from snowflake.connector.constants import QueryStatus
except ImportError:
    QueryStatus = None


def test_simple_async(conn_cnx):
    """Simple test to that shows the most simple usage of fire and forget.

    This test also makes sure that wait_until_ready function's sleeping is tested and
    that some fields are copied over correctly from the original query.
    """
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async("select count(*) from table(generator(timeLimit => 5))")
            cur.get_results_from_sfqid(cur.sfqid)
            assert len(cur.fetchall()) == 1
            assert cur.rowcount
            assert cur.description


def test_async_result_iteration(conn_cnx):
    """Test yielding results of an async query.

    Ensures that wait_until_ready is also called in __iter__() via _prefetch_hook().
    """

    def result_generator(query):
        with conn_cnx() as con:
            with con.cursor() as cur:
                cur.execute_async(query)
                cur.get_results_from_sfqid(cur.sfqid)
                yield from cur

    gen = result_generator("select count(*) from table(generator(timeLimit => 5))")
    assert next(gen)
    with pytest.raises(StopIteration):
        next(gen)


def test_async_exec(conn_cnx):
    """Tests whether simple async query execution works.

    Runs a query that takes a few seconds to finish and then totally closes connection
    to Snowflake. Then waits enough time for that query to finish, opens a new connection
    and fetches results. It also tests QueryStatus related functionality too.

    This test tends to hang longer than expected when the testing warehouse is overloaded.
    Manually looking at query history reveals that when a full GH actions + Jenkins test load hits one warehouse
    it can be queued for 15 seconds, so for now we wait 5 seconds before checking and then we give it another 25
    seconds to finish.
    """
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async("select count(*) from table(generator(timeLimit => 5))")
            q_id = cur.sfqid
            status = con.get_query_status(q_id)
            assert con.is_still_running(status)
    time.sleep(5)
    with conn_cnx() as con:
        with con.cursor() as cur:
            for _ in range(25):
                # Check upto 15 times once a second to see if it's done
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
            assert len(cur.fetchall()) == 1


def test_async_error(conn_cnx):
    """Tests whether simple async query error retrieval works.

    Runs a query that will fail to execute and then tests that if we tried to get results for the query
    then that would raise an exception. It also tests QueryStatus related functionality too.
    """
    with conn_cnx() as con:
        with con.cursor() as cur:
            sql = "select * from nonexistentTable"
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


def test_mix_sync_async(conn_cnx):
    with conn_cnx() as con:
        with con.cursor() as cur:
            # Setup
            cur.execute("alter session set CLIENT_TIMESTAMP_TYPE_MAPPING=TIMESTAMP_TZ")
            try:
                for table in ["smallTable", "uselessTable"]:
                    cur.execute(
                        "create or replace table {} (colA string, colB int)".format(
                            table
                        )
                    )
                    cur.execute(
                        "insert into {} values ('row1', 1), ('row2', 2), ('row3', 3)".format(
                            table
                        )
                    )
                cur.execute_async("select * from smallTable")
                sf_qid1 = cur.sfqid
                cur.execute_async("select * from uselessTable")
                sf_qid2 = cur.sfqid
                # Wait until the 2 queries finish
                while con.is_still_running(con.get_query_status(sf_qid1)):
                    time.sleep(1)
                while con.is_still_running(con.get_query_status(sf_qid2)):
                    time.sleep(1)
                cur.execute("drop table uselessTable")
                assert cur.fetchall() == [("USELESSTABLE successfully dropped.",)]
                cur.get_results_from_sfqid(sf_qid1)
                assert cur.fetchall() == [("row1", 1), ("row2", 2), ("row3", 3)]
                cur.get_results_from_sfqid(sf_qid2)
                assert cur.fetchall() == [("row1", 1), ("row2", 2), ("row3", 3)]
            finally:
                for table in ["smallTable", "uselessTable"]:
                    cur.execute(f"drop table if exists {table}")


def test_async_qmark(conn_cnx):
    """Tests that qmark parameter binding works with async queries."""
    import snowflake.connector

    orig_format = snowflake.connector.paramstyle
    snowflake.connector.paramstyle = "qmark"
    try:
        with conn_cnx() as con:
            with con.cursor() as cur:
                try:
                    cur.execute(
                        "create or replace table qmark_test (aa STRING, bb STRING)"
                    )
                    cur.execute(
                        "insert into qmark_test VALUES(?, ?)", ("test11", "test12")
                    )
                    cur.execute_async("select * from qmark_test")
                    async_qid = cur.sfqid
                    with conn_cnx() as con2:
                        with con2.cursor() as cur2:
                            cur2.get_results_from_sfqid(async_qid)
                            assert cur2.fetchall() == [("test11", "test12")]
                finally:
                    cur.execute("drop table if exists qmark_test")
    finally:
        snowflake.connector.paramstyle = orig_format


def test_done_caching(conn_cnx):
    """Tests whether get status caching is working as expected."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async("select count(*) from table(generator(timeLimit => 5))")
            qid1 = cur.sfqid
            cur.execute_async("select count(*) from table(generator(timeLimit => 10))")
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


def test_invalid_uuid_get_status(conn_cnx):
    with conn_cnx() as con:
        with con.cursor() as cur:
            with pytest.raises(
                ValueError, match=r"Invalid UUID: 'doesnt exist, dont even look'"
            ):
                cur.get_results_from_sfqid("doesnt exist, dont even look")


def test_unknown_sfqid(conn_cnx):
    """Tests the exception that there is no Exception thrown when we attempt to get a status of a not existing query."""
    with conn_cnx() as con:
        assert (
            con.get_query_status("12345678-1234-4123-A123-123456789012")
            == QueryStatus.NO_DATA
        )


def test_unknown_sfqid_results(conn_cnx):
    """Tests that there is no Exception thrown when we attempt to get a status of a not existing query."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.get_results_from_sfqid("12345678-1234-4123-A123-123456789012")


def test_not_fetching(conn_cnx):
    """Tests whether executing a new query actually cleans up after an async result retrieving.

    If someone tries to retrieve results then the first fetch would have to block. We should not block
    if we executed a new query.
    """
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async("select 1")
            sf_qid = cur.sfqid
            cur.get_results_from_sfqid(sf_qid)
            cur.execute("select 2")
            assert cur._inner_cursor is None
            assert cur._prefetch_hook is None


def test_close_connection_with_running_async_queries(conn_cnx):
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async("select count(*) from table(generator(timeLimit => 10))")
            cur.execute_async("select count(*) from table(generator(timeLimit => 1))")
        assert not con._all_async_queries_finished()
    assert len(con._done_async_sfqids) < 2 and con.rest is None


def test_close_connection_with_completed_async_queries(conn_cnx):
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async("select 1")
            qid1 = cur.sfqid
            cur.execute_async("select 2")
            qid2 = cur.sfqid
        while con.is_still_running(
            con._get_query_status(qid1)[0]
        ):  # use _get_query_status to avoid caching
            time.sleep(1)
        while con.is_still_running(con._get_query_status(qid2)[0]):
            time.sleep(1)
        assert con._all_async_queries_finished()
    assert len(con._done_async_sfqids) == 2 and con.rest is None
