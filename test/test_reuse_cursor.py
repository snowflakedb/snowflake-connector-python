#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#


def test_reuse_cursor(conn_cnx, db_parameters):
    """
    Ensure only the last executed command/query's result sets are returned.
    """
    with conn_cnx() as cnx:
        c = cnx.cursor()
        c.execute(u"create or replace table {name}(c1 string)".format(
            name=db_parameters['name']))
        try:
            c.execute(
                u"insert into {name} values('123'),('456'),('678')".format(
                    name=db_parameters['name']))
            c.execute(u"show tables")
            c.execute(u"select current_date()")
            rec = c.fetchone()
            assert len(rec) == 1, u"number of records is wrong"
            c.execute(
                u"select * from {name} order by 1".format(
                    name=db_parameters['name']))
            recs = c.fetchall()
            assert c.description[0][0] == u"C1", u"fisrt column name"
            assert len(recs) == 3, u"number of records is wrong"
        finally:
            c.execute(u"drop table if exists {name}".format(
                name=db_parameters['name']))
