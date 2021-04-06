#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#


from ..integ_helpers import drop_table
from ..randomize import random_string


def test_reuse_cursor(request, conn_cnx):
    """Ensures only the last executed command/query's result sets are returned."""
    table_name = random_string(4, prefix="test_reuse_cursor")
    with conn_cnx() as cnx:
        c = cnx.cursor()
        c.execute(f"create table {table_name}(c1 string)")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        c.execute(f"insert into {table_name} values('123'),('456'),('678')")
        c.execute("select current_date()")
        rec = c.fetchone()
        assert len(rec) == 1, "number of records is wrong"
        c.execute(f"select * from {table_name} order by 1")
        recs = c.fetchall()
        assert c.description[0][0] == "C1", "first column name"
        assert len(recs) == 3, "number of records is wrong"
