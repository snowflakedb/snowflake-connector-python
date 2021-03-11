#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
import pytest

from ..integ_helpers import drop_table
from ..randomize import random_string

pytestmark = pytest.mark.parallel


def _run_autocommit_off(cnx, table_name: str):
    """Runs autocommit off test.

    Args:
        cnx: The database connection context.
        table_name: Name of table used in test.
    """

    def exe(cnx, sql):
        return cnx.cursor().execute(sql.format(name=table_name))

    exe(cnx, """
INSERT INTO {name} VALUES(True), (False), (False)
""")
    res = exe(cnx, """
SELECT CURRENT_TRANSACTION()
""").fetchone()
    assert res[0] is not None
    res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE c1
""").fetchone()
    assert res[0] == 1
    res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""").fetchone()
    assert res[0] == 2
    cnx.rollback()
    res = exe(cnx, """
SELECT CURRENT_TRANSACTION()
""").fetchone()
    assert res[0] is None
    res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""").fetchone()
    assert res[0] == 0
    exe(cnx, """
INSERT INTO {name} VALUES(True), (False), (False)
""")
    cnx.commit()
    res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""").fetchone()
    assert res[0] == 2
    cnx.rollback()
    res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""").fetchone()
    assert res[0] == 2


def _run_autocommit_on(cnx, table_name: str):
    """Run autocommit on test.

    Args:
        cnx: The database connection context.
        table_name: Name of table used in test.
    """

    def exe(cnx, sql):
        return cnx.cursor().execute(sql.format(name=table_name))

    exe(cnx, """
INSERT INTO {name} VALUES(True), (False), (False)
""")
    cnx.rollback()
    res = exe(cnx, """
SELECT COUNT(*) FROM {name} WHERE NOT c1
""").fetchone()
    assert res[0] == 4


def test_autocommit_attribute(conn_cnx, request):
    """Tests autocommit attribute."""
    table_name = random_string(3, prefix="test_autocommit_attribute")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"CREATE TABLE {table_name} (c1 boolean)")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        cnx.autocommit(False)
        _run_autocommit_off(cnx, table_name)
        cnx.autocommit(True)
        _run_autocommit_on(cnx, table_name)


def test_autocommit_parameters(conn_cnx, request):
    """Tests autocommit parameter."""
    table_name = random_string(3, prefix="test_autocommit_parameters")

    def exe(cnx, sql):
        return cnx.cursor().execute(sql.format(name=table_name))

    with conn_cnx(autocommit=False) as cnx:
        exe(cnx, """
CREATE TABLE {name} (c1 boolean)
""")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        _run_autocommit_off(cnx, table_name)

    with conn_cnx(autocommit=True) as cnx:
        _run_autocommit_on(cnx, table_name)
