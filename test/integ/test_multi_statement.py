#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import logging
import time

import pytest

from snowflake.connector import ProgrammingError, errors
from snowflake.connector.version import VERSION

pytestmark = [
    pytest.mark.skipolddriver,
    pytest.mark.xfail(
        VERSION[:3] < (2, 9, 0),
        reason="Multi-statement support not available until connector version 2.9.0.",
    ),
]

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


def test_multi_statement_basic(conn_cnx):
    """Selects fixed integer data using statement level parameters."""
    savedIds = []
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute("select 1; select 2; select 'a';", _num_statements=3)
            assert cur.fetchall()[0][0] == 1
            savedIds.append(cur.sfqid)
            assert cur.nextset() == cur
            assert cur.fetchall()[0][0] == 2
            savedIds.append(cur.sfqid)
            assert cur.nextset() == cur
            assert cur.fetchall()[0][0] == "a"
            savedIds.append(cur.sfqid)
            assert cur.nextset() is None
            assert not cur.fetchall()
            assert len(cur.multi_statement_savedIds) == 3
            assert savedIds == cur.multi_statement_savedIds


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

            assert cur.fetchall()[0][0] == "Statement executed successfully."
            assert cur.nextset()
            assert cur.fetchall()[0][0] == f"Table {table_name} successfully created."
            assert cur.nextset()
            assert cur.fetchall()[0][0] == 3
            assert cur.nextset()
            results = [rec[0] for rec in cur]
            assert cur.sfqid is not None, "Snowflake query id is None"
            assert cur.rowcount == 3, "the number of records"
            assert results[0] == 65432, "the first result was wrong"
            assert results[1] == 98765, "the second result was wrong"
            assert results[2] == 123456, "the third result was wrong"
            assert cur.nextset()
            assert cur.fetchall()[0][0] == f"{table_name} successfully dropped."
            assert cur.nextset() is None
            assert not cur.fetchall()
            assert len(cur.multi_statement_savedIds) == 5


@pytest.mark.parametrize("style", ["pyformat", "qmark"])
def test_binding_multi(conn_cnx, style: str):
    """Tests using pyformat and qmark style bindings with multi-statement"""
    test_string = "select {s}; select {s}, {s}; select {s}, {s}, {s};"
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


def test_async_exec_multi(conn_cnx):
    """Tests whether async execution query works within a multi-statement"""
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async(
                "select 1; select 2; select count(*) from table(generator(timeLimit => 1)); select 'b';",
                _num_statements=4,
            )
            q_id = cur.sfqid
            assert con.is_still_running(con.get_query_status(q_id))
    while con.is_still_running(con.get_query_status(q_id)):
        time.sleep(1)
    with conn_cnx() as con:
        with con.cursor() as cur:
            for _ in range(3):
                status = con.get_query_status(q_id)
                if status == QueryStatus.SUCCESS:
                    break
                time.sleep(1)
            else:
                pytest.fail(
                    f"We should have broke out of this loop, final query status: {status}"
                )

            assert con.get_query_status_throw_if_error(q_id) == QueryStatus.SUCCESS

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


def test_async_error_multi(conn_cnx):
    """
    Runs a query that will fail to execute and then tests that if we tried to get results for the query
    then that would raise an exception. It also tests QueryStatus related functionality too.
    """
    with conn_cnx() as con:
        with con.cursor() as cur:
            sql = "select 1; select * from nonexistentTable"
            q_id = cur.execute_async(sql).get("queryId")
            with pytest.raises(ProgrammingError) as sync_error:
                cur.execute(sql)
            while con.is_still_running(con.get_query_status(q_id)):
                time.sleep(1)
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
        }
    ) as con:
        with con.cursor() as cur:
            cur.execute("alter session set CLIENT_TIMESTAMP_TYPE_MAPPING=TIMESTAMP_TZ")
            cur.execute(
                "create or replace temp table smallTable (colA string, colB int);"
                "create or replace temp table uselessTable (colA string, colB int);"
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


def test_desc_rewrite_multi(conn_cnx, caplog):
    """Tests whether multiple describe queries are rewritten properly and that this is logged."""
    with conn_cnx(session_parameters={PARAMETER_MULTI_STATEMENT_COUNT: 0}) as con:
        with con.cursor() as cur:
            table1 = random_string(5, "test_desc_rewrite_multi_")
            table2 = random_string(5, "test_desc_rewrite_multi_")
            cur.execute(
                f"create temp table {table1} (a int); create temp table {table2} (b int);"
            )
            caplog.set_level(logging.DEBUG, "snowflake.connector")
            cur.execute(f"desc {table1}; select 3; desc {table2}; select 'b';")
            assert (
                f"query was rewritten: org=desc {table1}; select 3; desc {table2}; select 'b';, new=describe table {table1}; select 3; describe table {table2}; select 'b';"
                in caplog.text
            )


def test_executemany_multi(conn_cnx):
    """Tests executemany with multi-statement optimizations enabled through the _num_statements parameter."""
    table1 = random_string(5, "test_executemany_multi_")
    table2 = random_string(5, "test_executemany_multi_")
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute(
                f"create temp table {table1} (aa number); create temp table {table2} (bb number);",
                _num_statements=2,
            )
            cur.executemany(
                f"insert into {table1}(aa) values(%(value1)s); insert into {table2}(bb) values(%(value2)s);",
                [
                    {"value1": 1234, "value2": 4},
                    {"value1": 234, "value2": 34},
                    {"value1": 34, "value2": 234},
                    {"value1": 4, "value2": 1234},
                ],
                _num_statements=2,
            )
            assert cur.fetchone()[0] == 1
            while cur.nextset():
                assert cur.fetchone()[0] == 1
            cur.execute(
                f"select aa from {table1}; select bb from {table2};", _num_statements=2
            )
            assert cur.fetchall() == [(1234,), (234,), (34,), (4,)]
            assert cur.nextset() == cur
            assert cur.fetchall() == [(4,), (34,), (234,), (1234,)]
            assert cur.nextset() is None
            assert not cur.nextset()

    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute(
                f"create temp table {table1} (aa number); create temp table {table2} (bb number);",
                _num_statements=2,
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
                _num_statements=2,
            )
            assert cur.fetchone()[0] == 1
            while cur.nextset():
                assert cur.fetchone()[0] == 1
            cur.execute(
                f"select aa from {table1}; select bb from {table2};", _num_statements=2
            )
            assert cur.fetchall() == [(12345,), (1234,), (234,), (34,), (4,)]
            assert cur.nextset() == cur
            assert cur.fetchall() == [(4,), (34,), (234,), (1234,), (12345,)]
            assert cur.nextset() is None
            assert not cur.nextset()


def test_executmany_qmark_multi(conn_cnx):
    """Tests executemany with multi-statement optimization with qmark style."""
    table1 = random_string(5, "test_executemany_qmark_multi_")
    table2 = random_string(5, "test_executemany_qmark_multi_")
    with conn_cnx(paramstyle="qmark") as con:
        with con.cursor() as cur:
            cur.execute(
                f"create temp table {table1}(aa number); create temp table {table2}(bb number);",
                _num_statements=2,
            )
            cur.executemany(
                f"insert into {table1}(aa) values(?); insert into {table2}(bb) values(?);",
                [
                    [1234, 4],
                    [234, 34],
                    [34, 234],
                    [4, 1234],
                ],
                _num_statements=2,
            )
            assert cur.fetchone()[0] == 1
            while cur.nextset():
                assert cur.fetchone()[0] == 1
            cur.execute(
                f"select aa from {table1}; select bb from {table2};", _num_statements=2
            )
            assert cur.fetchall() == [(1234,), (234,), (34,), (4,)]
            assert cur.nextset() == cur
            assert cur.fetchall() == [(4,), (34,), (234,), (1234,)]
            assert cur.nextset() is None
            assert not cur.nextset()
