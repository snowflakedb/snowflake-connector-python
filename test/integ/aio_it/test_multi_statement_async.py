#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from test.helpers import (
    _wait_until_query_success_async,
    _wait_while_query_running_async,
)

import pytest

from snowflake.connector import ProgrammingError, errors
from snowflake.connector.aio import SnowflakeCursor
from snowflake.connector.constants import PARAMETER_MULTI_STATEMENT_COUNT, QueryStatus
from snowflake.connector.util_text import random_string


@pytest.fixture(scope="module", params=[False, True])
def skip_to_last_set(request) -> bool:
    return request.param


async def test_multi_statement_wrong_count(conn_cnx):
    """Tries to send the wrong number of statements."""
    async with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 1}) as con:
        async with con.cursor() as cur:
            with pytest.raises(
                errors.ProgrammingError,
                match="Actual statement count 2 did not match the desired statement count 1.",
            ):
                await cur.execute("select 1; select 2")

            with pytest.raises(
                errors.ProgrammingError,
                match="Actual statement count 2 did not match the desired statement count 1.",
            ):
                await cur.execute(
                    "alter session set MULTI_STATEMENT_COUNT=2; select 1;"
                )

            await cur.execute("alter session set MULTI_STATEMENT_COUNT=5")
            with pytest.raises(
                errors.ProgrammingError,
                match="Actual statement count 1 did not match the desired statement count 5.",
            ):
                await cur.execute("select 1;")

            with pytest.raises(
                errors.ProgrammingError,
                match="Actual statement count 3 did not match the desired statement count 5.",
            ):
                await cur.execute("select 1; select 2; select 3;")


async def _check_multi_statement_results(
    cur: SnowflakeCursor,
    checks: "list[list[tuple] | function]",
    skip_to_last_set: bool,
) -> None:
    savedIds = []
    for index, check in enumerate(checks):
        if not skip_to_last_set or index == len(checks) - 1:
            if callable(check):
                assert check(await cur.fetchall())
            else:
                assert await cur.fetchall() == check
            savedIds.append(cur.sfqid)
        assert await cur.nextset() == (cur if index < len(checks) - 1 else None)
    assert await cur.fetchall() == []

    assert cur.multi_statement_savedIds[-1 if skip_to_last_set else 0 :] == savedIds


async def test_multi_statement_basic(conn_cnx, skip_to_last_set: bool):
    """Selects fixed integer data using statement level parameters."""
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            statement_params = dict()
            await cur.execute(
                "select 1; select 2; select 'a';",
                num_statements=3,
                _statement_params=statement_params,
            )
            await _check_multi_statement_results(
                cur,
                checks=[
                    [(1,)],
                    [(2,)],
                    [("a",)],
                ],
                skip_to_last_set=skip_to_last_set,
            )
            assert len(statement_params) == 0


async def test_insert_select_multi(conn_cnx, db_parameters, skip_to_last_set: bool):
    """Naive use of multi-statement to check multiple SQL functions."""
    async with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 0}) as con:
        async with con.cursor() as cur:
            table_name = random_string(5, "test_multi_table_").upper()
            await cur.execute(
                "use schema {db}.{schema};\n"
                "create table {name} (aa int);\n"
                "insert into {name}(aa) values(123456),(98765),(65432);\n"
                "select aa from {name} order by aa;\n"
                "drop table {name};".format(
                    db=db_parameters["database"],
                    schema=(
                        db_parameters["schema"]
                        if "schema" in db_parameters
                        else "PUBLIC"
                    ),
                    name=table_name,
                )
            )
            await _check_multi_statement_results(
                cur,
                checks=[
                    [("Statement executed successfully.",)],
                    [(f"Table {table_name} successfully created.",)],
                    [(3,)],
                    [(65432,), (98765,), (123456,)],
                    [(f"{table_name} successfully dropped.",)],
                ],
                skip_to_last_set=skip_to_last_set,
            )


@pytest.mark.parametrize("style", ["pyformat", "qmark"])
async def test_binding_multi(conn_cnx, style: str, skip_to_last_set: bool):
    """Tests using pyformat and qmark style bindings with multi-statement"""
    test_string = "select {s}; select {s}, {s}; select {s}, {s}, {s};"
    async with conn_cnx(paramstyle=style) as con:
        async with con.cursor() as cur:
            sql = test_string.format(s="%s" if style == "pyformat" else "?")
            await cur.execute(sql, (10, 20, 30, "a", "b", "c"), num_statements=3)
            await _check_multi_statement_results(
                cur,
                checks=[[(10,)], [(20, 30)], [("a", "b", "c")]],
                skip_to_last_set=skip_to_last_set,
            )


async def test_async_exec_multi(conn_cnx, skip_to_last_set: bool):
    """Tests whether async execution query works within a multi-statement"""
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute_async(
                "select 1; select 2; select count(*) from table(generator(timeLimit => 1)); select 'b';",
                num_statements=4,
            )
            q_id = cur.sfqid
            assert con.is_still_running(await con.get_query_status(q_id))
        await _wait_while_query_running_async(con, q_id, sleep_time=1)
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await _wait_until_query_success_async(
                con, q_id, num_checks=3, sleep_per_check=1
            )
            assert (
                await con.get_query_status_throw_if_error(q_id) == QueryStatus.SUCCESS
            )

            await cur.get_results_from_sfqid(q_id)
            await _check_multi_statement_results(
                cur,
                checks=[[(1,)], [(2,)], lambda x: x > [(0,)], [("b",)]],
                skip_to_last_set=skip_to_last_set,
            )


async def test_async_error_multi(conn_cnx):
    """
    Runs a query that will fail to execute and then tests that if we tried to get results for the query
    then that would raise an exception. It also tests QueryStatus related functionality too.
    """
    async with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 0}) as con:
        async with con.cursor() as cur:
            sql = "select 1; select * from nonexistentTable"
            q_id = (await cur.execute_async(sql)).get("queryId")
            with pytest.raises(
                ProgrammingError,
                match="SQL compilation error:\nObject 'NONEXISTENTTABLE' does not exist or not authorized.",
            ) as sync_error:
                await cur.execute(sql)
            await _wait_while_query_running_async(con, q_id, sleep_time=1)
            assert await con.get_query_status(q_id) == QueryStatus.FAILED_WITH_ERROR
            with pytest.raises(ProgrammingError) as e1:
                await con.get_query_status_throw_if_error(q_id)
            assert sync_error.value.errno != -1
            with pytest.raises(ProgrammingError) as e2:
                await cur.get_results_from_sfqid(q_id)
            assert e1.value.errno == e2.value.errno == sync_error.value.errno


async def test_mix_sync_async_multi(conn_cnx, skip_to_last_set: bool):
    """Tests sending multiple multi-statement async queries at the same time."""
    async with conn_cnx(
        session_parameters={
            PARAMETER_MULTI_STATEMENT_COUNT: 0,
            "CLIENT_TIMESTAMP_TYPE_MAPPING": "TIMESTAMP_TZ",
        }
    ) as con:
        async with con.cursor() as cur:
            await cur.execute(
                "create or replace temp table smallTable (colA string, colB int);"
                "create or replace temp table uselessTable (colA string, colB int);"
            )
            for table in ["smallTable", "uselessTable"]:
                await cur.execute(
                    f"insert into {table} values('row1', 1);"
                    f"insert into {table} values('row2', 2);"
                    f"insert into {table} values('row3', 3);"
                )
            await cur.execute_async("select 1; select 'a'; select * from smallTable;")
            sf_qid1 = cur.sfqid
            await cur.execute_async("select 2; select 'b'; select * from uselessTable")
            sf_qid2 = cur.sfqid
            # Wait until the 2 queries finish
            await _wait_while_query_running_async(con, sf_qid1, sleep_time=1)
            await _wait_while_query_running_async(con, sf_qid2, sleep_time=1)
            await cur.execute("drop table uselessTable")
            assert await cur.fetchall() == [("USELESSTABLE successfully dropped.",)]
            await cur.get_results_from_sfqid(sf_qid1)
            await _check_multi_statement_results(
                cur,
                checks=[[(1,)], [("a",)], [("row1", 1), ("row2", 2), ("row3", 3)]],
                skip_to_last_set=skip_to_last_set,
            )
            await cur.get_results_from_sfqid(sf_qid2)
            await _check_multi_statement_results(
                cur,
                checks=[[(2,)], [("b",)], [("row1", 1), ("row2", 2), ("row3", 3)]],
                skip_to_last_set=skip_to_last_set,
            )


async def test_done_caching_multi(conn_cnx, skip_to_last_set: bool):
    """Tests whether get status caching is working as expected."""
    async with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 0}) as con:
        async with con.cursor() as cur:
            await cur.execute_async(
                "select 1; select 'a'; select count(*) from table(generator(timeLimit => 2));"
            )
            qid1 = cur.sfqid
            await cur.execute_async(
                "select 2; select 'b'; select count(*) from table(generator(timeLimit => 2));"
            )
            qid2 = cur.sfqid
            assert len(con._async_sfqids) == 2
            await _wait_while_query_running_async(con, qid1, sleep_time=1)
            await _wait_until_query_success_async(
                con, qid1, num_checks=3, sleep_per_check=1
            )
            assert await con.get_query_status(qid1) == QueryStatus.SUCCESS
            await cur.get_results_from_sfqid(qid1)
            await _check_multi_statement_results(
                cur,
                checks=[[(1,)], [("a",)], lambda x: x > [(0,)]],
                skip_to_last_set=skip_to_last_set,
            )
            assert len(con._async_sfqids) == 1
            assert len(con._done_async_sfqids) == 1
            await _wait_while_query_running_async(con, qid2, sleep_time=1)
            await _wait_until_query_success_async(
                con, qid2, num_checks=3, sleep_per_check=1
            )
            assert await con.get_query_status(qid2) == QueryStatus.SUCCESS
            await cur.get_results_from_sfqid(qid2)
            await _check_multi_statement_results(
                cur,
                checks=[[(2,)], [("b",)], lambda x: x > [(0,)]],
                skip_to_last_set=skip_to_last_set,
            )
            assert len(con._async_sfqids) == 0
            assert len(con._done_async_sfqids) == 2
            assert await con._all_async_queries_finished()


async def test_alter_session_multi(conn_cnx):
    """Tests whether multiple alter session queries are detected and stored in the connection."""
    async with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 0}) as con:
        async with con.cursor() as cur:
            sql = (
                "select 1;"
                "alter session set autocommit=false;"
                "select 'a';"
                "alter session set json_indent = 4;"
                "alter session set CLIENT_TIMESTAMP_TYPE_MAPPING        =    'TIMESTAMP_TZ'"
            )
            await cur.execute(sql)
            assert con.converter.get_parameter("AUTOCOMMIT") == "false"
            assert con.converter.get_parameter("JSON_INDENT") == "4"
            assert (
                con.converter.get_parameter("CLIENT_TIMESTAMP_TYPE_MAPPING")
                == "TIMESTAMP_TZ"
            )


async def test_executemany_multi(conn_cnx, skip_to_last_set: bool):
    """Tests executemany with multi-statement optimizations enabled through the num_statements parameter."""
    table1 = random_string(5, "test_executemany_multi_")
    table2 = random_string(5, "test_executemany_multi_")
    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute(
                f"create temp table {table1} (aa number); create temp table {table2} (bb number);",
                num_statements=2,
            )
            await cur.executemany(
                f"insert into {table1}(aa) values(%(value1)s); insert into {table2}(bb) values(%(value2)s);",
                [
                    {"value1": 1234, "value2": 4},
                    {"value1": 234, "value2": 34},
                    {"value1": 34, "value2": 234},
                    {"value1": 4, "value2": 1234},
                ],
                num_statements=2,
            )
            assert (await cur.fetchone())[0] == 1
            while await cur.nextset():
                assert (await cur.fetchone())[0] == 1
            await cur.execute(
                f"select aa from {table1}; select bb from {table2};", num_statements=2
            )
            await _check_multi_statement_results(
                cur,
                checks=[[(1234,), (234,), (34,), (4,)], [(4,), (34,), (234,), (1234,)]],
                skip_to_last_set=skip_to_last_set,
            )

    async with conn_cnx() as con:
        async with con.cursor() as cur:
            await cur.execute(
                f"create temp table {table1} (aa number); create temp table {table2} (bb number);",
                num_statements=2,
            )
            await cur.executemany(
                f"insert into {table1}(aa) values(%s); insert into {table2}(bb) values(%s);",
                [
                    (12345, 4),
                    (1234, 34),
                    (234, 234),
                    (34, 1234),
                    (4, 12345),
                ],
                num_statements=2,
            )
            assert (await cur.fetchone())[0] == 1
            while await cur.nextset():
                assert (await cur.fetchone())[0] == 1
            await cur.execute(
                f"select aa from {table1}; select bb from {table2};", num_statements=2
            )
            await _check_multi_statement_results(
                cur,
                checks=[
                    [(12345,), (1234,), (234,), (34,), (4,)],
                    [(4,), (34,), (234,), (1234,), (12345,)],
                ],
                skip_to_last_set=skip_to_last_set,
            )


async def test_executmany_qmark_multi(conn_cnx, skip_to_last_set: bool):
    """Tests executemany with multi-statement optimization with qmark style."""
    table1 = random_string(5, "test_executemany_qmark_multi_")
    table2 = random_string(5, "test_executemany_qmark_multi_")
    async with conn_cnx(paramstyle="qmark") as con:
        async with con.cursor() as cur:
            await cur.execute(
                f"create temp table {table1}(aa number); create temp table {table2}(bb number);",
                num_statements=2,
            )
            await cur.executemany(
                f"insert into {table1}(aa) values(?); insert into {table2}(bb) values(?);",
                [
                    [1234, 4],
                    [234, 34],
                    [34, 234],
                    [4, 1234],
                ],
                num_statements=2,
            )
            assert (await cur.fetchone())[0] == 1
            while await cur.nextset():
                assert (await cur.fetchone())[0] == 1
            await cur.execute(
                f"select aa from {table1}; select bb from {table2};", num_statements=2
            )
            await _check_multi_statement_results(
                cur,
                checks=[
                    [(1234,), (234,), (34,), (4,)],
                    [(4,), (34,), (234,), (1234,)],
                ],
                skip_to_last_set=skip_to_last_set,
            )
