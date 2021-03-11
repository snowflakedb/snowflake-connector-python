#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import pytest

from snowflake.connector.errors import ProgrammingError

from ..integ_helpers import drop_table
from ..randomize import random_string

pytestmark = pytest.mark.parallel


def test_binding_security(conn_cnx, db_parameters, request):
    """SQL Injection Tests."""
    table_name = random_string(3, prefix="test_binding_security_")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"CREATE TABLE {table_name} (aa INT, bb STRING)")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        cnx.cursor().execute(f"INSERT INTO {table_name} VALUES(%s, %s)", (1, 'test1'))
        cnx.cursor().execute(f"INSERT INTO {table_name} VALUES(%(aa)s, %(bb)s)", {'aa': 2, 'bb': 'test2'})
        for _rec in cnx.cursor().execute(f"SELECT * FROM {table_name} ORDER BY 1 DESC"):
            break
        assert _rec[0] == 2, 'First column'
        assert _rec[1] == 'test2', 'Second column'
        for _rec in cnx.cursor().execute(f"SELECT * FROM {table_name} WHERE aa=%s", (1,)):
            break
        assert _rec[0] == 1, 'First column'
        assert _rec[1] == 'test1', 'Second column'

        # SQL injection safe test
        # Good Example
        with pytest.raises(ProgrammingError):
            cnx.cursor().execute(
                f"SELECT * FROM {table_name} WHERE aa=%s", ("1 or aa>0",))

        with pytest.raises(ProgrammingError):
            cnx.cursor().execute(
                f"SELECT * FROM {table_name} WHERE aa=%(aa)s", {"aa": "1 or aa>0"})

        # Bad Example in application. DON'T DO THIS
        c = cnx.cursor()
        c.execute(f"SELECT * FROM {table_name} WHERE aa=%s" % ("1 or aa>0",))
        rec = c.fetchall()
        assert len(rec) == 2, "not raising error unlike the previous one."


def test_binding_list(conn_cnx, request):
    """SQL binding list type for IN."""
    table_name = random_string(3, prefix="test_binding_list_")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"CREATE TABLE {table_name} (aa INT, bb STRING)")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        cnx.cursor().execute(f"INSERT INTO {table_name} VALUES(%s, %s)", (1, 'test1'))
        cnx.cursor().execute(f"INSERT INTO {table_name} VALUES(%(aa)s, %(bb)s)", {'aa': 2, 'bb': 'test2'})
        cnx.cursor().execute(f"INSERT INTO {table_name} VALUES(3, 'test3')")
        for _rec in cnx.cursor().execute(f"SELECT * FROM {table_name} WHERE aa IN (%s) ORDER BY 1 DESC", ([1, 3],)):
            break
        assert _rec[0] == 3, 'First column'
        assert _rec[1] == 'test3', 'Second column'
        for _rec in cnx.cursor().execute(f"SELECT * FROM {table_name} WHERE aa=%s", (1,)):
            break
        assert _rec[0] == 1, 'First column'
        assert _rec[1] == 'test1', 'Second column'


@pytest.mark.internal
def test_unsupported_binding(negative_conn_cnx, request):
    """Unsupported data binding."""
    table_name = random_string(3, prefix="test_unsupported_binding_")
    with negative_conn_cnx() as cnx:
        cnx.cursor().execute(f"CREATE TABLE {table_name} (aa INT, bb STRING)")
        request.addfinalizer(drop_table(negative_conn_cnx, table_name))
        cnx.cursor().execute(f"INSERT INTO {table_name} VALUES(%s, %s)", (1, 'test1'))
        sql = f'select count(*) from {table_name} where aa=%s'

        with cnx.cursor() as cur:
            rec = cur.execute(sql, (1,)).fetchone()
            assert rec[0] is not None, 'no value is returned'

        # dict
        with pytest.raises(ProgrammingError):
            cnx.cursor().execute(sql, ({'value': 1},))
