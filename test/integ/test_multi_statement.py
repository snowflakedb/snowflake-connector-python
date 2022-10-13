#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import pytest

from snowflake.connector import errors

from ..randomize import random_string


@pytest.mark.skipolddriver
def test_multi_statement_wrong_count(conn_cnx):
    "Tries to send the wrong number of statements."
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
    "Selects fixed integer data using statement level parameters."
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute("select 1; select 2; select 3;", _num_statements=3)
            assert cur.is_multi_statement
            assert cur.fetchall()[0][0] == 1
            assert cur.nextset() == cur
            assert cur.fetchall()[0][0] == 2
            assert cur.nextset() == cur
            assert cur.fetchall()[0][0] == 3
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
    "Naive use of multi-statement to check multiple SQL functions."
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

            assert cur.is_multi_statement
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
    "Tests using pyformat and qmark style bindings with multi-statement"
    test_string = "select {s}; select {s}, {s}; select {s}, {s}, {s};"
    for style in ("pyformat", "qmark"):
        with conn_cnx(paramstyle=style) as con:
            with con.cursor() as cur:
                sql = test_string.format(s="%s" if style == "pyformat" else "?")
                cur.execute(sql, (10, 20, 30, 40, 50, 60), _num_statements=3)
                assert cur.fetchall()[0] == (10,)
                assert cur.nextset()
                assert cur.fetchall()[0] == (20, 30)
                assert cur.nextset()
                assert cur.fetchall()[0] == (40, 50, 60)
                assert cur.nextset() is None
                assert not cur.fetchall()
