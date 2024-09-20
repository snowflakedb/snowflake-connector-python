#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import logging

import pytest

from snowflake.connector import DatabaseError, ProgrammingError
from snowflake.connector.constants import QueryStatus

# Mark all tests in this file to time out after 2 minutes to prevent hanging forever
pytestmark = pytest.mark.timeout(120)


async def test_simple_async(conn_cnx):
    """Simple test to that shows the most simple usage of fire and forget.

    This test also makes sure that wait_until_ready function's sleeping is tested and
    that some fields are copied over correctly from the original query.
    """
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute_async(
                "select count(*) from table(generator(timeLimit => 5))"
            )
            await cur.get_results_from_sfqid(cur.sfqid)
            assert len(await cur.fetchall()) == 1
            assert cur.rowcount
            assert cur.description


async def test_async_result_iteration(conn_cnx):
    """Test yielding results of an async query.

    Ensures that wait_until_ready is also called in __iter__() via _prefetch_hook().
    """

    async def result_generator(query):
        async with conn_cnx() as con:
            async with con.cursor() as cur:
                await cur.execute_async(query)
                await cur.get_results_from_sfqid(cur.sfqid)
                async for row in cur:
                    yield row

    gen = result_generator("select count(*) from table(generator(timeLimit => 5))")
    assert await anext(gen)
    with pytest.raises(StopAsyncIteration):
        await anext(gen)


async def test_async_exec(conn_cnx):
    """Tests whether simple async query execution works.

    Runs a query that takes a few seconds to finish and then totally closes connection
    to Snowflake. Then waits enough time for that query to finish, opens a new connection
    and fetches results. It also tests QueryStatus related functionality too.

    This test tends to hang longer than expected when the testing warehouse is overloaded.
    Manually looking at query history reveals that when a full GH actions + Jenkins test load hits one warehouse
    it can be queued for 15 seconds, so for now we wait 5 seconds before checking and then we give it another 25
    seconds to finish.
    """
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute_async(
                "select count(*) from table(generator(timeLimit => 5))"
            )
            q_id = cur.sfqid
            status = await con.get_query_status(q_id)
            assert con.is_still_running(status)
    await asyncio.sleep(5)
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            for _ in range(25):
                # Check upto 15 times once a second to see if it's done
                status = await con.get_query_status(q_id)
                if status == QueryStatus.SUCCESS:
                    break
                await asyncio.sleep(1)
            else:
                pytest.fail(
                    f"We should have broke out of this loop, final query status: {status}"
                )
            status = await con.get_query_status_throw_if_error(q_id)
            assert status == QueryStatus.SUCCESS
            await cur.get_results_from_sfqid(q_id)
            assert len(await cur.fetchall()) == 1


async def test_async_error(conn_cnx, caplog):
    """Tests whether simple async query error retrieval works.

    Runs a query that will fail to execute and then tests that if we tried to get results for the query
    then that would raise an exception. It also tests QueryStatus related functionality too.
    """
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            sql = "select * from nonexistentTable"
            await cur.execute_async(sql)
            q_id = cur.sfqid
            with pytest.raises(ProgrammingError) as sync_error:
                await cur.execute(sql)
            while con.is_still_running(con.get_query_status(q_id)):
                await asyncio.sleep(1)
            status = await con.get_query_status(q_id)
            assert status == QueryStatus.FAILED_WITH_ERROR
            assert con.is_an_error(status)
            with pytest.raises(ProgrammingError) as e1:
                await con.get_query_status_throw_if_error(q_id)
            assert sync_error.value.errno != -1
            with pytest.raises(ProgrammingError) as e2:
                await cur.get_results_from_sfqid(q_id)
            assert e1.value.errno == e2.value.errno == sync_error.value.errno

            sfqid = (await cur.execute_async("SELECT SYSTEM$WAIT(2)"))["queryId"]
            await cur.get_results_from_sfqid(sfqid)
            async with con.cursor() as cancel_cursor:
                # use separate cursor to cancel as execute will overwrite the previous query status
                await cancel_cursor.execute(f"SELECT SYSTEM$CANCEL_QUERY('{sfqid}')")
            with pytest.raises(DatabaseError) as e3, caplog.at_level(logging.INFO):
                await cur.fetchall()
            assert (
                "SQL execution canceled" in e3.value.msg
                and f"Status of query '{sfqid}' is {QueryStatus.FAILED_WITH_ERROR.name}"
                in caplog.text
            )


async def test_mix_sync_async(conn_cnx):
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            # Setup
            await cur.execute(
                "alter session set CLIENT_TIMESTAMP_TYPE_MAPPING=TIMESTAMP_TZ"
            )
            try:
                for table in ["smallTable", "uselessTable"]:
                    await cur.execute(
                        "create or replace table {} (colA string, colB int)".format(
                            table
                        )
                    )
                    await cur.execute(
                        "insert into {} values ('row1', 1), ('row2', 2), ('row3', 3)".format(
                            table
                        )
                    )
                await cur.execute_async("select * from smallTable")
                sf_qid1 = cur.sfqid
                await cur.execute_async("select * from uselessTable")
                sf_qid2 = cur.sfqid
                # Wait until the 2 queries finish
                while con.is_still_running(con.get_query_status(sf_qid1)):
                    await asyncio.sleep(1)
                while con.is_still_running(con.get_query_status(sf_qid2)):
                    await asyncio.sleep(1)
                await cur.execute("drop table uselessTable")
                assert await cur.fetchall() == [("USELESSTABLE successfully dropped.",)]
                await cur.get_results_from_sfqid(sf_qid1)
                assert await cur.fetchall() == [("row1", 1), ("row2", 2), ("row3", 3)]
                await cur.get_results_from_sfqid(sf_qid2)
                assert await cur.fetchall() == [("row1", 1), ("row2", 2), ("row3", 3)]
            finally:
                for table in ["smallTable", "uselessTable"]:
                    await cur.execute(f"drop table if exists {table}")


async def test_async_qmark(conn_cnx):
    """Tests that qmark parameter binding works with async queries."""
    import snowflake.connector

    orig_format = snowflake.connector.paramstyle
    snowflake.connector.paramstyle = "qmark"
    try:
        async with conn_cnx() as con:
            async with con.cursor() as cur:
                try:
                    await cur.execute(
                        "create or replace table qmark_test (aa STRING, bb STRING)"
                    )
                    await cur.execute(
                        "insert into qmark_test VALUES(?, ?)", ("test11", "test12")
                    )
                    await cur.execute_async("select * from qmark_test")
                    async_qid = cur.sfqid
                    async with conn_cnx() as con2:
                        async with con2.cursor() as cur2:
                            await cur2.get_results_from_sfqid(async_qid)
                            assert await cur2.fetchall() == [("test11", "test12")]
                finally:
                    await cur.execute("drop table if exists qmark_test")
    finally:
        snowflake.connector.paramstyle = orig_format


async def test_done_caching(conn_cnx):
    """Tests whether get status caching is working as expected."""
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute_async(
                "select count(*) from table(generator(timeLimit => 5))"
            )
            qid1 = cur.sfqid
            await cur.execute_async(
                "select count(*) from table(generator(timeLimit => 10))"
            )
            qid2 = cur.sfqid
            assert len(con._async_sfqids) == 2
            await asyncio.sleep(5)
            while con.is_still_running(await con.get_query_status(qid1)):
                await asyncio.sleep(1)
            assert await con.get_query_status(qid1) == QueryStatus.SUCCESS
            assert len(con._async_sfqids) == 1
            assert len(con._done_async_sfqids) == 1
            await asyncio.sleep(5)
            while con.is_still_running(await con.get_query_status(qid2)):
                await asyncio.sleep(1)
            assert await con.get_query_status(qid2) == QueryStatus.SUCCESS
            assert len(con._async_sfqids) == 0
            assert len(con._done_async_sfqids) == 2
            assert await con._all_async_queries_finished()


async def test_invalid_uuid_get_status(conn_cnx):
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            with pytest.raises(
                ValueError, match=r"Invalid UUID: 'doesnt exist, dont even look'"
            ):
                await cur.get_results_from_sfqid("doesnt exist, dont even look")


async def test_unknown_sfqid(conn_cnx):
    """Tests the exception that there is no Exception thrown when we attempt to get a status of a not existing query."""
    async with conn_cnx() as con:
        assert (
            await con.get_query_status("12345678-1234-4123-A123-123456789012")
            == QueryStatus.NO_DATA
        )


async def test_unknown_sfqid_results(conn_cnx):
    """Tests that there is no Exception thrown when we attempt to get a status of a not existing query."""
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.get_results_from_sfqid("12345678-1234-4123-A123-123456789012")


async def test_not_fetching(conn_cnx):
    """Tests whether executing a new query actually cleans up after an async result retrieving.

    If someone tries to retrieve results then the first fetch would have to block. We should not block
    if we executed a new query.
    """
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute_async("select 1")
            sf_qid = cur.sfqid
            await cur.get_results_from_sfqid(sf_qid)
            await cur.execute("select 2")
            assert cur._inner_cursor is None
            assert cur._prefetch_hook is None


async def test_close_connection_with_running_async_queries(conn_cnx):
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute_async(
                "select count(*) from table(generator(timeLimit => 10))"
            )
            await cur.execute_async(
                "select count(*) from table(generator(timeLimit => 1))"
            )
        assert not (await con._all_async_queries_finished())
    assert len(con._done_async_sfqids) < 2 and con.rest is None


async def test_close_connection_with_completed_async_queries(conn_cnx):
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute_async("select 1")
            qid1 = cur.sfqid
            await cur.execute_async("select 2")
            qid2 = cur.sfqid
        while con.is_still_running(
            (await con._get_query_status(qid1))[0]
        ):  # use _get_query_status to avoid caching
            await asyncio.sleep(1)
        while con.is_still_running((await con._get_query_status(qid2))[0]):
            await asyncio.sleep(1)
        assert await con._all_async_queries_finished()
    assert len(con._done_async_sfqids) == 2 and con.rest is None
