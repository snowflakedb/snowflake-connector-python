#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2016 Snowflake Computing Inc. All right reserved.
#

import pytest
from snowflake.connector.errors import (ProgrammingError)


def test_binding_security(conn_cnx, db_parameters):
    """
    SQL Injection Tests
    """
    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa INT, bb STRING)".format(
                    name=db_parameters['name']))
            cnx.cursor().execute(
                "INSERT INTO {name} VALUES(%s, %s)".format(
                    name=db_parameters['name']),
                (1, 'test1'))
            cnx.cursor().execute(
                "INSERT INTO {name} VALUES(%(aa)s, %(bb)s)".format(
                    name=db_parameters['name']),
                {'aa': 2, 'bb': 'test2'})
            for rec in cnx.cursor().execute(
                    "SELECT * FROM {name} ORDER BY 1 DESC".format(
                        name=db_parameters['name'])):
                break
            assert rec[0] == 2, 'First column'
            assert rec[1] == 'test2', 'Second column'
            for rec in cnx.cursor().execute(
                    "SELECT * FROM {name} WHERE aa=%s".format(
                        name=db_parameters['name']), (1,)):
                break
            assert rec[0] == 1, 'First column'
            assert rec[1] == 'test1', 'Second column'

            # SQL injection safe test
            # Good Example
            with pytest.raises(ProgrammingError):
                cnx.cursor().execute(
                    "SELECT * FROM {name} WHERE aa=%s".format(
                        name=db_parameters['name']),
                    ("1 or aa>0",))

            with pytest.raises(ProgrammingError):
                cnx.cursor().execute(
                    "SELECT * FROM {name} WHERE aa=%(aa)s".format(
                        name=db_parameters['name']),
                    {"aa": "1 or aa>0"})

            # Bad Example in application. DON'T DO THIS
            c = cnx.cursor()
            c.execute("SELECT * FROM {name} WHERE aa=%s".format(
                name=db_parameters['name']) % ("1 or aa>0",))
            rec = c.fetchall()
            assert len(rec) == 2, "not raising error unlike the previous one."
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "drop table if exists {name}".format(
                    name=db_parameters['name']))


def test_binding_list(conn_cnx, db_parameters):
    """
    SQL binding list type for IN
    """
    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa INT, bb STRING)".format(
                    name=db_parameters['name']))
            cnx.cursor().execute(
                "INSERT INTO {name} VALUES(%s, %s)".format(
                    name=db_parameters['name']),
                (1, 'test1'))
            cnx.cursor().execute(
                "INSERT INTO {name} VALUES(%(aa)s, %(bb)s)".format(
                    name=db_parameters['name']),
                {'aa': 2, 'bb': 'test2'})
            cnx.cursor().execute(
                "INSERT INTO {name} VALUES(3, 'test3')".format(
                    name=db_parameters['name']))
            for rec in cnx.cursor().execute("""
SELECT * FROM {name} WHERE aa IN (%s) ORDER BY 1 DESC
""".format(name=db_parameters['name']), ([1, 3],)):
                break
            assert rec[0] == 3, 'First column'
            assert rec[1] == 'test3', 'Second column'

            for rec in cnx.cursor().execute(
                    "SELECT * FROM {name} WHERE aa=%s".format(
                        name=db_parameters['name']), (1,)):
                break
            assert rec[0] == 1, 'First column'
            assert rec[1] == 'test1', 'Second column'

            rec = cnx.cursor().execute("""
SELECT * FROM {name} WHERE aa IN (%s) ORDER BY 1 DESC
""".format(name=db_parameters['name']), ((1,),))

    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "drop table if exists {name}".format(
                    name=db_parameters['name']))


def test_unsupported_binding(conn_cnx, db_parameters):
    """
    Unsupported data binding
    """
    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "CREATE OR REPLACE TABLE {name} "
                "(aa INT, bb STRING)".format(
                    name=db_parameters['name']))
            cnx.cursor().execute(
                "INSERT INTO {name} VALUES(%s, %s)".format(
                    name=db_parameters['name']),
                (1, 'test1'))

            sql = 'select count(*) from {name} where aa=%s'.format(
                name=db_parameters['name'])

            with cnx.cursor() as cur:
                rec = cur.execute(sql, (1,)).fetchone()
                assert rec[0] is not None, 'no value is returned'

            # dict
            with pytest.raises(ProgrammingError):
                cnx.cursor().execute(sql, ({'value': 1},))
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "drop table if exists {name}".format(
                    name=db_parameters['name']))
