#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#
import time

import pytest

from snowflake.connector import ProgrammingError
from snowflake.connector.constants import QueryStatus
from snowflake.connector.errors import InterfaceError

# Mark all tests in this file to time out after 2 minutes to prevent hanging forever
pytestmark = pytest.mark.timeout(120)


def test_async_exec(conn_cnx):
    """Tests whether simple async query execution works.

    Runs a query that takes a few seconds to finish and then totally closes connection
    to Snowflake. Then waits enough time for that query to finish, opens a new connection
    and fetches results. It also tests QueryStatus related functionality too.
    """
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute('select count(*) from table(generator(timeLimit => 5))', exec_async=True)
            q_id = cur.sfqid
            status = con.get_query_status(q_id)
            assert status == QueryStatus.RUNNING
            assert con.is_still_running(status)
    time.sleep(10)
    with conn_cnx() as con:
        with con.cursor() as cur:
            status = con.get_query_status(q_id)
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
            cur.execute('select * from nonexistentTable', exec_async=True)
            q_id = cur.sfqid
            while con.is_still_running(con.get_query_status(q_id)):
                time.sleep(1)
            status = con.get_query_status(q_id)
            assert status == QueryStatus.FAILED_WITH_ERROR
            assert con.is_an_error(status)
            with pytest.raises(ProgrammingError):
                con.get_query_status_throw_if_error(q_id)
            with pytest.raises(ProgrammingError):
                cur.get_results_from_sfqid(q_id)


def test_mix_sync_async(conn_cnx):
    with conn_cnx() as con:
        with con.cursor() as cur:
            # Setup
            cur.execute('alter session set CLIENT_TIMESTAMP_TYPE_MAPPING=TIMESTAMP_TZ')
            try:
                for table in ['smallTable', 'uselessTable']:
                    cur.execute('create or replace table {} (colA string, colB int)'.format(table))
                    cur.execute('insert into {} values (\'row1\', 1), (\'row2\', 2), (\'row3\', 3)'.format(table))
                cur.execute('select * from smallTable', exec_async=True)
                sf_qid1 = cur.sfqid
                cur.execute('select * from uselessTable', exec_async=True)
                sf_qid2 = cur.sfqid
                # Wait until the 2 queries finish
                while con.is_still_running(con.get_query_status(sf_qid1)):
                    time.sleep(1)
                while con.is_still_running(con.get_query_status(sf_qid2)):
                    time.sleep(1)
                cur.execute('drop table uselessTable')
                assert cur.fetchall() == [('USELESSTABLE successfully dropped.',)]
                cur.get_results_from_sfqid(sf_qid1)
                assert cur.fetchall() == [('row1', 1), ('row2', 2), ('row3', 3)]
                cur.get_results_from_sfqid(sf_qid2)
                assert cur.fetchall() == [('row1', 1), ('row2', 2), ('row3', 3)]
            finally:
                for table in ['smallTable', 'uselessTable']:
                    cur.execute('drop table if exists {}'.format(table))


def test_async_qmark(conn_cnx):
    """Tests that qmark parameter binding works with async queries."""
    import snowflake.connector
    orig_format = snowflake.connector.paramstyle
    snowflake.connector.paramstyle = 'qmark'
    try:
        with conn_cnx() as con:
            with con.cursor() as cur:
                try:
                    cur.execute("create or replace table qmark_test (aa STRING, bb STRING)")
                    cur.execute("insert into qmark_test VALUES(?, ?)", ('test11', 'test12'))
                    cur.execute("select * from qmark_test", exec_async=True)
                    async_qid = cur.sfqid
                    with conn_cnx() as con2:
                        with con2.cursor() as cur2:
                            cur2.get_results_from_sfqid(async_qid)
                            assert cur2.fetchall() == [('test11', 'test12')]
                finally:
                    cur.execute('drop table if exists qmark_test')
    finally:
        snowflake.connector.paramstyle = orig_format


def test_done_caching(conn_cnx):
    """Tests whether get status caching is working as expected."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute('select count(*) from table(generator(timeLimit => 5))', exec_async=True)
            qid1 = cur.sfqid
            cur.execute('select count(*) from table(generator(timeLimit => 10))', exec_async=True)
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
            assert con.safe_to_close()


def test_invalid_sfqid(conn_cnx):
    """Tests the exception that is thrown when we attempt to get a status of a not existing query."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            with pytest.raises(InterfaceError) as thrown_ex:
                cur.get_results_from_sfqid('doesnt exist, dont even look')
            assert '404 Not Found:' in str(thrown_ex)


def test_not_fetching(conn_cnx):
    """Tests whether executing a new query actually cleans up after an async result retrieving.

    If someone tries to retrieve results then the first fetch would have to block. We should not block
    if we executed a new query.
    """
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute('select 1', exec_async=True)
            sf_qid = cur.sfqid
            cur.get_results_from_sfqid(sf_qid)
            cur.execute('select 2')
            assert cur._inner_cursor is None
            assert cur._prefetch_hook is None
