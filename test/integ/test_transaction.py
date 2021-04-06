#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import pytest

import snowflake.connector

from ..integ_helpers import drop_table
from ..randomize import random_string


def test_transaction(request, conn_cnx):
    """Tests transaction API."""
    table_name = random_string(3, prefix="test_transaction")

    def assert_sum_of_select_all(cnx, target_sum):
        c = cnx.cursor()
        c.execute(f"select * from {table_name}")
        assert sum(rec[0] for rec in c) == target_sum, "incorrect sum"

    with conn_cnx() as cnx:
        cnx.cursor().execute(f"create table {table_name} (c1 int)")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        cnx.cursor().execute(f"insert into {table_name}(c1) values(1234),(3456)")
        assert_sum_of_select_all(cnx, 4690)

        cnx.cursor().execute("begin")
        cnx.cursor().execute(f"insert into {table_name}(c1) values(5678),(7890)")
        assert_sum_of_select_all(cnx, 18258)
        cnx.rollback()

        assert_sum_of_select_all(cnx, 4690)

        cnx.cursor().execute("begin")
        cnx.cursor().execute(f"insert into {table_name}(c1) values(2345),(6789)")
        assert_sum_of_select_all(cnx, 13824)

        cnx.commit()
        cnx.rollback()
        assert_sum_of_select_all(cnx, 13824)


def test_connection_context_manager(request, conn_cnx):
    table_name = random_string(5, prefix="test_connection_context_manager_")
    request.addfinalizer(drop_table(conn_cnx, table_name))

    with conn_cnx(timezone="UTC") as cnx:
        cnx.autocommit(False)
        cnx.cursor().execute(f"CREATE TABLE {table_name} (cc1 int)")
        cnx.cursor().execute(f"INSERT INTO {table_name} VALUES(1),(2),(3)")
        ret = cnx.cursor().execute(f"SELECT SUM(cc1) FROM {table_name}").fetchone()
        assert ret[0] == 6
        cnx.commit()
        cnx.cursor().execute(f"INSERT INTO {table_name} VALUES(4),(5),(6)")
        ret = cnx.cursor().execute(f"SELECT SUM(cc1) FROM {table_name}").fetchone()
        assert ret[0] == 21
        with pytest.raises(snowflake.connector.Error):
            # syntax error should be caught here
            cnx.cursor().execute("SELECT WRONG SYNTAX QUERY")
    with conn_cnx(timezone="UTC") as cnx:
        # and the last change must have been rollbacked
        ret = cnx.cursor().execute(f"SELECT SUM(cc1) FROM {table_name}").fetchone()
        assert ret[0] == 6
