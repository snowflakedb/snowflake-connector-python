#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import pytest

@pytest.mark.skip(
    reason="Cython is not enabled in build env")
def test_select_with_num(conn_cnx):
    with conn_cnx() as json_cnx:
        with conn_cnx() as arrow_cnx:
            row_count = 50000
            sql_text = ("select seq4() as c1, uniform(1, 10, random(12)) as c2 from " +
                        "table(generator(rowcount=>50000)) order by c1")
            cursor_json = json_cnx.cursor()
            cursor_json.execute("alter session set query_result_format='JSON'")
            cursor_json.execute(sql_text)

            cursor_arrow = arrow_cnx.cursor()
            cursor_arrow.execute("alter session set query_result_format='ARROW_FORCE'")
            cursor_arrow.execute(sql_text)

            for i in range(0, row_count):
                (json_c1, json_c2) = cursor_json.fetchone()
                (arrow_c1, arrow_c2) = cursor_arrow.fetchone()
                assert json_c1 == arrow_c1
                assert json_c2 == arrow_c2
