#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from test.randomize import random_string

import pytest

from snowflake.connector import errors


def test_qmark_paramstyle(conn_cnx, db_parameters):
    """Tests that binding question marks is not supported by default."""
    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa STRING, bb STRING)".format(
                    name=db_parameters['name']))
            cnx.cursor().execute(
                "INSERT INTO {name} VALUES('?', '?')".format(
                    name=db_parameters['name']))
            for rec in cnx.cursor().execute(
                    "SELECT * FROM {name}".format(name=db_parameters['name'])):
                assert rec[0] == "?", "First column value"
                with pytest.raises(errors.ProgrammingError):
                    cnx.cursor().execute(
                        "INSERT INTO {name} VALUES(?,?)".format(
                            name=db_parameters['name']))
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(
                    name=db_parameters['name']))


def test_numeric_paramstyle(conn_cnx, db_parameters):
    """Tests that binding numeric positional style is not supported."""
    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa STRING, bb STRING)".format(
                    name=db_parameters['name']))
            cnx.cursor().execute(
                "INSERT INTO {name} VALUES(':1', ':2')".format(
                    name=db_parameters['name']))
            for rec in cnx.cursor().execute(
                    "SELECT * FROM {name}".format(name=db_parameters['name'])):
                assert rec[0] == ":1", "First column value"
                with pytest.raises(errors.ProgrammingError):
                    cnx.cursor().execute(
                        "INSERT INTO {name} VALUES(:1,:2)".format(
                            name=db_parameters['name']))
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(
                    name=db_parameters['name']))


@pytest.mark.internal
def test_qmark_paramstyle_enabled(negative_conn_cnx):
    """Enable qmark binding."""
    table_name = random_string(5, "test_qmark_paramstyle_enabled_")
    try:
        with negative_conn_cnx(paramstyle='qmark') as cnx:
            cnx.cursor().execute(
                f"CREATE OR REPLACE TABLE {table_name} (aa STRING, bb STRING)"
            )
            cnx.cursor().execute(
                f"INSERT INTO {table_name} VALUES(?, ?)", ('test11', 'test12'))
            ret = cnx.cursor().execute(f"select * from {table_name}").fetchone()
            assert ret[0] == 'test11'
            assert ret[1] == 'test12'
    finally:
        with negative_conn_cnx() as cnx:
            cnx.cursor().execute(
                f"DROP TABLE IF EXISTS {table_name}"
            )

    # After changing back to pyformat, binding qmark should fail.
    try:
        with negative_conn_cnx() as cnx:
            cnx.cursor().execute(
                f"CREATE OR REPLACE TABLE {table_name} (aa STRING, bb STRING)"
            )
            with pytest.raises(TypeError):
                cnx.cursor().execute(
                    f"INSERT INTO {table_name} VALUES(?, ?)", ('test11', 'test12')
                )
    finally:
        with negative_conn_cnx() as cnx:
            cnx.cursor().execute(
                f"DROP TABLE IF EXISTS {table_name}"
            )


def test_binding_datetime_qmark(conn_cnx, db_parameters):
    """Ensures datetime can bound."""
    import datetime

    try:
        with conn_cnx(paramstyle='qmark') as cnx:
            cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa TIMESTAMP_NTZ)".format(
                    name=db_parameters['name']))
            days = 2
            inserts = tuple(
                [(datetime.datetime(2018, 1, i + 1),) for i in range(days)])
            cnx.cursor().executemany(
                "INSERT INTO {name} VALUES(?)".format(
                    name=db_parameters['name']),
                inserts)
            ret = cnx.cursor().execute(
                "SELECT * FROM {name} ORDER BY 1".format(
                    name=db_parameters['name'])).fetchall()
            for i in range(days):
                assert ret[i][0] == inserts[i][0]
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(
                    name=db_parameters['name']))


def test_binding_none(conn_cnx):
    with conn_cnx(paramstyle='qmark') as con:
        try:
            table_name = random_string(5, prefix='test_binding_none_')
            con.cursor().execute('CREATE TABLE {table}(bar text)'.format(table=table_name))
            con.cursor().execute('INSERT INTO {table} VALUES (?)'.format(table=table_name), [None])
        finally:
            con.cursor().execute('DROP TABLE {table}'.format(table=table_name))
