#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#


import pytest

from snowflake.connector import errors


def test_qmark_paramstyle(conn_cnx, db_parameters):
    """
    Binding question marks is not supported by default
    """
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
    """
    Binding numeric positional style is not supported
    """
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


def test_qmark_paramstyle_enabled(conn_cnx, db_parameters):
    """
    Enable qmark binding
    """
    import datetime
    import snowflake.connector
    snowflake.connector.paramstyle = u'qmark'
    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa STRING, bb STRING)".format(
                    name=db_parameters['name']))
            cnx.cursor().execute(
                "INSERT INTO {name} VALUES(?, ?)".format(
                    name=db_parameters['name']), ('test11', 'test12'))
            ret = cnx.cursor().execute("select * from {name}".format(
                name=db_parameters['name'])).fetchone()
            assert ret[0] == 'test11'
            assert ret[1] == 'test12'
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(
                    name=db_parameters['name']))
        snowflake.connector.paramstyle = u'pyformat'

    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa TIMESTAMP)".format(
                    name=db_parameters['name']))
            inserts = tuple([(datetime.datetime(2018, 1, i + 1),) for i in range(2)])
            cnx.cursor().executemany(
                "INSERT INTO {name} VALUES(?)".format(
                    name=db_parameters['name']),
                inserts)
            for i, rec in enumerate(cnx.cursor().execute(
                    "SELECT * FROM {name}".format(name=db_parameters['name']))):
                assert rec[0] == inserts[i][0], "First column value"
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(
                    name=db_parameters['name']))

    # After changing back to pyformat, binding qmark should fail.
    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa STRING, bb STRING)".format(
                    name=db_parameters['name']))
            with pytest.raises(TypeError):
                cnx.cursor().execute(
                    "INSERT INTO {name} VALUES(?, ?)".format(
                        name=db_parameters['name']), ('test11', 'test12'))
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "DROP TABLE IF EXISTS {name}".format(
                    name=db_parameters['name']))
