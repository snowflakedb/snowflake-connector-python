#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pytest

from snowflake.connector.version import VERSION

from ..helpers import _wait_until_query_success, _wait_while_query_running

pytestmark = [
    pytest.mark.skipolddriver,
    pytest.mark.xfail(
        VERSION[:3] < (2, 9, 0),
        reason="Multi-statement support not available until connector version 2.9.0.",
    ),
]

import snowflake.connector.cursor
from snowflake.connector import ProgrammingError, errors

try:  # pragma: no cover
    from snowflake.connector.constants import (
        PARAMETER_MULTI_STATEMENT_COUNT,
        QueryStatus,
    )
except ImportError:
    QueryStatus = None

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from ..randomize import random_string


def test_multi_statement_wrong_count(conn_cnx):
    """Tries to send the wrong number of statements."""
    with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 1}) as con:
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


def _check_multi_statement_results(
    cur: snowflake.connector.cursor, checks: "list[list[tuple] | function]"
):
    savedIds = []
    for index, check in enumerate(checks):
        if callable(check):
            assert check(cur.fetchall())
        else:
            assert cur.fetchall() == check
        savedIds.append(cur.sfqid)
        assert cur.nextset() == (cur if index < len(checks) - 1 else None)
    assert cur.fetchall() == []
    assert cur.multi_statement_savedIds == savedIds


def test_multi_statement_basic(conn_cnx):
    """Selects fixed integer data using statement level parameters."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            statement_params = dict()
            cur.execute(
                "select 1; select 2; select 'a';",
                num_statements=3,
                _statement_params=statement_params,
            )
            _check_multi_statement_results(
                cur,
                checks=[
                    [(1,)],
                    [(2,)],
                    [("a",)],
                ],
            )
            assert len(statement_params) == 0


def test_insert_select_multi(conn_cnx, db_parameters):
    """Naive use of multi-statement to check multiple SQL functions."""
    with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 0}) as con:
        with con.cursor() as cur:
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
            _check_multi_statement_results(
                cur,
                checks=[
                    [("Statement executed successfully.",)],
                    [(f"Table {table_name} successfully created.",)],
                    [(3,)],
                    [(65432,), (98765,), (123456,)],
                    [(f"{table_name} successfully dropped.",)],
                ],
            )


@pytest.mark.parametrize("style", ["pyformat", "qmark"])
def test_binding_multi(conn_cnx, style: str):
    """Tests using pyformat and qmark style bindings with multi-statement"""
    test_string = "select {s}; select {s}, {s}; select {s}, {s}, {s};"
    with conn_cnx(paramstyle=style) as con:
        with con.cursor() as cur:
            sql = test_string.format(s="%s" if style == "pyformat" else "?")
            cur.execute(sql, (10, 20, 30, "a", "b", "c"), num_statements=3)
            _check_multi_statement_results(
                cur, checks=[[(10,)], [(20, 30)], [("a", "b", "c")]]
            )


def test_async_exec_multi(conn_cnx):
    """Tests whether async execution query works within a multi-statement"""
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async(
                "select 1; select 2; select count(*) from table(generator(timeLimit => 1)); select 'b';",
                num_statements=4,
            )
            q_id = cur.sfqid
            assert con.is_still_running(con.get_query_status(q_id))
        _wait_while_query_running(con, q_id, sleep_time=1)
    with conn_cnx() as con:
        with con.cursor() as cur:
            _wait_until_query_success(con, q_id, num_checks=3, sleep_per_check=1)
            assert con.get_query_status_throw_if_error(q_id) == QueryStatus.SUCCESS

            cur.get_results_from_sfqid(q_id)
            _check_multi_statement_results(
                cur, checks=[[(1,)], [(2,)], lambda x: x > [(0,)], [("b",)]]
            )


def test_async_error_multi(conn_cnx):
    """
    Runs a query that will fail to execute and then tests that if we tried to get results for the query
    then that would raise an exception. It also tests QueryStatus related functionality too.
    """
    with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 0}) as con:
        with con.cursor() as cur:
            sql = "select 1; select * from nonexistentTable"
            q_id = cur.execute_async(sql).get("queryId")
            with pytest.raises(
                ProgrammingError,
                match="SQL compilation error:\nObject 'NONEXISTENTTABLE' does not exist or not authorized.",
            ) as sync_error:
                cur.execute(sql)
            _wait_while_query_running(con, q_id, sleep_time=1)
            assert con.get_query_status(q_id) == QueryStatus.FAILED_WITH_ERROR
            with pytest.raises(ProgrammingError) as e1:
                con.get_query_status_throw_if_error(q_id)
            assert sync_error.value.errno != -1
            with pytest.raises(ProgrammingError) as e2:
                cur.get_results_from_sfqid(q_id)
            assert e1.value.errno == e2.value.errno == sync_error.value.errno


def test_mix_sync_async_multi(conn_cnx):
    """Tests sending multiple multi-statement async queries at the same time."""
    with conn_cnx(
        session_parameters={
            PARAMETER_MULTI_STATEMENT_COUNT: 0,
            "CLIENT_TIMESTAMP_TYPE_MAPPING": "TIMESTAMP_TZ",
        }
    ) as con:
        with con.cursor() as cur:
            cur.execute(
                "create or replace temp table smallTable (colA string, colB int);"
                "create or replace temp table uselessTable (colA string, colB int);"
            )
            for table in ["smallTable", "uselessTable"]:
                cur.execute(
                    f"insert into {table} values('row1', 1);"
                    f"insert into {table} values('row2', 2);"
                    f"insert into {table} values('row3', 3);"
                )
            cur.execute_async("select 1; select 'a'; select * from smallTable;")
            sf_qid1 = cur.sfqid
            cur.execute_async("select 2; select 'b'; select * from uselessTable")
            sf_qid2 = cur.sfqid
            # Wait until the 2 queries finish
            _wait_while_query_running(con, sf_qid1, sleep_time=1)
            _wait_while_query_running(con, sf_qid2, sleep_time=1)
            cur.execute("drop table uselessTable")
            assert cur.fetchall() == [("USELESSTABLE successfully dropped.",)]
            cur.get_results_from_sfqid(sf_qid1)
            _check_multi_statement_results(
                cur, checks=[[(1,)], [("a",)], [("row1", 1), ("row2", 2), ("row3", 3)]]
            )
            cur.get_results_from_sfqid(sf_qid2)
            _check_multi_statement_results(
                cur, checks=[[(2,)], [("b",)], [("row1", 1), ("row2", 2), ("row3", 3)]]
            )


def test_done_caching_multi(conn_cnx):
    """Tests whether get status caching is working as expected."""
    with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 0}) as con:
        with con.cursor() as cur:
            cur.execute_async(
                "select 1; select 'a'; select count(*) from table(generator(timeLimit => 2));"
            )
            qid1 = cur.sfqid
            cur.execute_async(
                "select 2; select 'b'; select count(*) from table(generator(timeLimit => 2));"
            )
            qid2 = cur.sfqid
            assert len(con._async_sfqids) == 2
            _wait_while_query_running(con, qid1, sleep_time=1)
            _wait_until_query_success(con, qid1, num_checks=3, sleep_per_check=1)
            assert con.get_query_status(qid1) == QueryStatus.SUCCESS
            cur.get_results_from_sfqid(qid1)
            _check_multi_statement_results(
                cur, checks=[[(1,)], [("a",)], lambda x: x > [(0,)]]
            )
            assert len(con._async_sfqids) == 1
            assert len(con._done_async_sfqids) == 1
            _wait_while_query_running(con, qid2, sleep_time=1)
            _wait_until_query_success(con, qid2, num_checks=3, sleep_per_check=1)
            assert con.get_query_status(qid2) == QueryStatus.SUCCESS
            cur.get_results_from_sfqid(qid2)
            _check_multi_statement_results(
                cur, checks=[[(2,)], [("b",)], lambda x: x > [(0,)]]
            )
            assert len(con._async_sfqids) == 0
            assert len(con._done_async_sfqids) == 2
            assert con._all_async_queries_finished()


def test_alter_session_multi(conn_cnx):
    """Tests whether multiple alter session queries are detected and stored in the connection."""
    with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 0}) as con:
        with con.cursor() as cur:
            sql = (
                "select 1;"
                "alter session set autocommit=false;"
                "select 'a';"
                "alter session set json_indent = 4;"
                "alter session set CLIENT_TIMESTAMP_TYPE_MAPPING        =    'TIMESTAMP_TZ'"
            )
            cur.execute(sql)
            assert con.converter.get_parameter("AUTOCOMMIT") == "false"
            assert con.converter.get_parameter("JSON_INDENT") == "4"
            assert (
                con.converter.get_parameter("CLIENT_TIMESTAMP_TYPE_MAPPING")
                == "TIMESTAMP_TZ"
            )


def test_executemany_multi(conn_cnx):
    """Tests executemany with multi-statement optimizations enabled through the num_statements parameter."""
    table1 = random_string(5, "test_executemany_multi_")
    table2 = random_string(5, "test_executemany_multi_")
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute(
                f"create temp table {table1} (aa number); create temp table {table2} (bb number);",
                num_statements=2,
            )
            cur.executemany(
                f"insert into {table1}(aa) values(%(value1)s); insert into {table2}(bb) values(%(value2)s);",
                [
                    {"value1": 1234, "value2": 4},
                    {"value1": 234, "value2": 34},
                    {"value1": 34, "value2": 234},
                    {"value1": 4, "value2": 1234},
                ],
                num_statements=2,
            )
            assert cur.fetchone()[0] == 1
            while cur.nextset():
                assert cur.fetchone()[0] == 1
            cur.execute(
                f"select aa from {table1}; select bb from {table2};", num_statements=2
            )
            _check_multi_statement_results(
                cur,
                checks=[[(1234,), (234,), (34,), (4,)], [(4,), (34,), (234,), (1234,)]],
            )

    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute(
                f"create temp table {table1} (aa number); create temp table {table2} (bb number);",
                num_statements=2,
            )
            cur.executemany(
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
            assert cur.fetchone()[0] == 1
            while cur.nextset():
                assert cur.fetchone()[0] == 1
            cur.execute(
                f"select aa from {table1}; select bb from {table2};", num_statements=2
            )
            _check_multi_statement_results(
                cur,
                checks=[
                    [(12345,), (1234,), (234,), (34,), (4,)],
                    [(4,), (34,), (234,), (1234,), (12345,)],
                ],
            )


def test_executmany_qmark_multi(conn_cnx):
    """Tests executemany with multi-statement optimization with qmark style."""
    table1 = random_string(5, "test_executemany_qmark_multi_")
    table2 = random_string(5, "test_executemany_qmark_multi_")
    with conn_cnx(paramstyle="qmark") as con:
        with con.cursor() as cur:
            cur.execute(
                f"create temp table {table1}(aa number); create temp table {table2}(bb number);",
                num_statements=2,
            )
            cur.executemany(
                f"insert into {table1}(aa) values(?); insert into {table2}(bb) values(?);",
                [
                    [1234, 4],
                    [234, 34],
                    [34, 234],
                    [4, 1234],
                ],
                num_statements=2,
            )
            assert cur.fetchone()[0] == 1
            while cur.nextset():
                assert cur.fetchone()[0] == 1
            cur.execute(
                f"select aa from {table1}; select bb from {table2};", num_statements=2
            )
            _check_multi_statement_results(
                cur,
                checks=[
                    [(1234,), (234,), (34,), (4,)],
                    [(4,), (34,), (234,), (1234,)],
                ],
            )
