#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import pytest

from ..integ_helpers import drop_table
from ..randomize import random_string

pytestmark = pytest.mark.parallel


def test_transaction(request, conn_cnx):
    """Tests transaction API."""
    table_name = random_string(3, prefix='test_transaction')

    def assert_sum_of_select_all(cnx, target_sum):
        c = cnx.cursor()
        c.execute(f"select * from {table_name}")
        assert sum(rec[0] for rec in c) == target_sum, 'incorrect sum'

    with conn_cnx() as cnx:
        cnx.cursor().execute(f"create table {table_name} (c1 int)")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        cnx.cursor().execute(f"insert into {table_name}(c1) values(1234),(3456)")
        assert_sum_of_select_all(cnx, 4690)

        cnx.cursor().execute("begin")
        cnx.cursor().execute(
            f"insert into {table_name}(c1) values(5678),(7890)")
        assert_sum_of_select_all(cnx, 18258)
        cnx.rollback()

        assert_sum_of_select_all(cnx, 4690)

        cnx.cursor().execute("begin")
        cnx.cursor().execute(f"insert into {table_name}(c1) values(2345),(6789)")
        assert_sum_of_select_all(cnx, 13824)

        cnx.commit()
        cnx.rollback()
        assert_sum_of_select_all(cnx, 13824)
