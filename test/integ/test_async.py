#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import time

import pytest

from snowflake.connector import ProgrammingError

from ..integ_helpers import drop_table
from ..randomize import random_string

# Mark all tests in this file to time out after 2 minutes to prevent hanging forever
pytestmark = [pytest.mark.timeout(120), pytest.mark.skipolddriver, pytest.mark.sequential]

try:  # pragma: no cover
    from snowflake.connector.constants import QueryStatus
except ImportError:
    QueryStatus = None


def test_simple_async(conn_cnx):
    """Simple test that shows the most simple usage of fire and forget.

    This test also makes sure that wait_until_ready function's sleeping is tested.
    """
    with conn_cnx() as con, con.cursor() as cur:
        cur.execute_async('select count(*) from table(generator(timeLimit => 5))')
        cur.get_results_from_sfqid(cur.sfqid)
        assert len(cur.fetchall()) == 1


def test_async_exec(conn_cnx):
    """Tests whether simple async query execution works.

    Runs a query that takes a few seconds to finish and then totally closes connection
    to Snowflake. Then waits enough time for that query to finish, opens a new connection
    and fetches results. It also tests QueryStatus related functionality too.
    """
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async('select count(*) from table(generator(timeLimit => 5))')
            q_id = cur.sfqid
            status = con.get_query_status(q_id)
            assert con.is_still_running(status)
    time.sleep(10)
    with conn_cnx() as con:
        with con.cursor() as cur:
            status = con.get_query_status(q_id)
            assert status == QueryStatus.SUCCESS
            status = con.get_query_status_throw_if_error(q_id)
            assert status == QueryStatus.SUCCESS
            cur.get_results_from_sfqid(q_id)
            assert len(cur.fetchall()) == 1


def test_async_error(conn_cnx):
    """Tests whether simple async query error retrieval works.

    Runs a query that will fail to execute and then tests that if we tried to get results for the query
    then that would raise an exception. It also tests QueryStatus related functionality too.
    """
    with conn_cnx() as con, con.cursor() as cur:
        cur.execute_async('select * from nonexistentTable')
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


def test_mix_sync_async(conn_cnx, request):
    with conn_cnx() as con, con.cursor() as cur:
        cur.execute('alter session set CLIENT_TIMESTAMP_TYPE_MAPPING=TIMESTAMP_TZ')

        small_table = random_string(3, prefix="test_mix_sync_async")
        useless_table = random_string(3, prefix="test_mix_sync_async")

        for table in [small_table, useless_table]:
            cur.execute(f'create table {table} (colA string, colB int)')
            request.addfinalizer(drop_table(conn_cnx, table))
            cur.execute(f'insert into {table} values (\'row1\', 1), (\'row2\', 2), (\'row3\', 3)')

        cur.execute_async(f'select * from {small_table}')
        sf_qid1 = cur.sfqid
        cur.execute_async(f'select * from {useless_table}')
        sf_qid2 = cur.sfqid
        # Wait until the 2 queries finish
        while con.is_still_running(con.get_query_status(sf_qid1)):
            time.sleep(1)
        while con.is_still_running(con.get_query_status(sf_qid2)):
            time.sleep(1)
        cur.execute(f'drop table {useless_table}')
        assert cur.fetchall()[0] == (f'{useless_table.upper()} successfully dropped.',)
        cur.get_results_from_sfqid(sf_qid1)
        assert cur.fetchall() == [('row1', 1), ('row2', 2), ('row3', 3)]
        cur.get_results_from_sfqid(sf_qid2)
        assert cur.fetchall() == [('row1', 1), ('row2', 2), ('row3', 3)]


def test_async_qmark(conn_cnx, request):
    """Tests that qmark parameter binding works with async queries."""
    table_name = random_string(3, prefix="test_async_qmark")
    with conn_cnx(paramstyle='qmark') as con, con.cursor() as cur:
        cur.execute(f"create table {table_name} (aa STRING, bb STRING)")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        cur.execute(f"insert into {table_name} VALUES(?, ?)", ('test11', 'test12'))
        cur.execute_async(f"select * from {table_name}")
        async_qid = cur.sfqid
        with conn_cnx(paramstyle='qmark') as con2:
            with con2.cursor() as cur2:
                cur2.get_results_from_sfqid(async_qid)
                assert cur2.fetchall() == [('test11', 'test12')]


def test_done_caching(conn_cnx):
    """Tests whether get status caching is working as expected."""
    with conn_cnx() as con, con.cursor() as cur:
        cur.execute_async('select count(*) from table(generator(timeLimit => 5))')
        qid1 = cur.sfqid
        cur.execute_async('select count(*) from table(generator(timeLimit => 10))')
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
    """"""
    with conn_cnx() as con, con.cursor() as cur:
        with pytest.raises(ValueError, match=r"Invalid UUID: 'doesnt exist, dont even look'"):
            cur.get_results_from_sfqid('doesnt exist, dont even look')


def test_unknown_sfqid(conn_cnx):
    """Tests the exception that there is no Exception thrown when we attempt to get a status of a not existing query."""
    with conn_cnx() as con:
        assert con.get_query_status('12345678-1234-4123-A123-123456789012') == QueryStatus.NO_DATA


def test_unknown_sfqid_results(conn_cnx):
    """Tests that there is no Exception thrown when we attempt to get a status of a not existing query."""
    with conn_cnx() as con, con.cursor() as cur:
        cur.get_results_from_sfqid('12345678-1234-4123-A123-123456789012')


def test_not_fetching(conn_cnx):
    """Tests whether executing a new query actually cleans up after an async result retrieving.

    If someone tries to retrieve results then the first fetch would have to block. We should not block
    if we executed a new query.
    """
    with conn_cnx() as con, con.cursor() as cur:
        cur.execute_async('select 1')
        sf_qid = cur.sfqid
        cur.get_results_from_sfqid(sf_qid)
        cur.execute('select 2')
        assert cur._inner_cursor is None
        assert cur._prefetch_hook is None
