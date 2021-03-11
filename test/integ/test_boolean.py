#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
import pytest

from ..randomize import random_string

pytestmark = pytest.mark.parallel


def test_binding_fetching_boolean(conn_cnx):
    table_name = random_string(3, prefix="test_binding_fetching_boolean")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"""
create or replace table {table_name} (c1 boolean, c2 integer)
""")

    with conn_cnx() as cnx:
        cnx.cursor().execute(f"""
insert into {table_name} values(%s,%s), (%s,%s), (%s,%s)
""", (True, 1, False, 2, True, 3))
        results = cnx.cursor().execute(f"""
select * from {table_name} order by 1""").fetchall()
        assert not results[0][0]
        assert results[1][0]
        assert results[2][0]
        results = cnx.cursor().execute(f"""
select c1 from {table_name} where c2=2
""").fetchall()
        assert not results[0][0]

        # SNOW-15905: boolean support
        results = cnx.cursor().execute("""
SELECT CASE WHEN (null LIKE trim(null)) THEN null  ELSE null END
""").fetchall()
        assert not results[0][0]


def test_boolean_from_compiler(conn_cnx):
    with conn_cnx() as cnx:
        ret = cnx.cursor().execute("SELECT true").fetchone()
        assert ret[0]

        ret = cnx.cursor().execute("SELECT false").fetchone()
        assert not ret[0]
