#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#


import pytest

from snowflake.connector import errors


def test_qmark_paramstyle(conn_cnx, db_parameters):
    """
    Binding question marks is not supported in Python
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
    Binding numeric positional style is not supported in Python
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
