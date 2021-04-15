#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#


def test_reuse_cursor(conn_cnx, db_parameters):
    """Ensures only the last executed command/query's result sets are returned."""
    with conn_cnx() as cnx:
        c = cnx.cursor()
        c.execute(
            "create or replace table {name}(c1 string)".format(
                name=db_parameters["name"]
            )
        )
        try:
            c.execute(
                "insert into {name} values('123'),('456'),('678')".format(
                    name=db_parameters["name"]
                )
            )
            c.execute("show tables")
            c.execute("select current_date()")
            rec = c.fetchone()
            assert len(rec) == 1, "number of records is wrong"
            c.execute(
                "select * from {name} order by 1".format(name=db_parameters["name"])
            )
            recs = c.fetchall()
            assert c.description[0][0] == "C1", "fisrt column name"
            assert len(recs) == 3, "number of records is wrong"
        finally:
            c.execute("drop table if exists {name}".format(name=db_parameters["name"]))
