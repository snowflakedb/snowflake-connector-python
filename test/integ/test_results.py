#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import pytest

from snowflake.connector import ProgrammingError


def test_results(conn_cnx):
    """Gets results for the given qid."""
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        cur.execute("select * from values(1,2),(3,4)")
        sfqid = cur.sfqid
        cur = cur.query_result(sfqid)
        got_sfqid = cur.sfqid
        assert cur.fetchall() == [(1, 2), (3, 4)]
        assert sfqid == got_sfqid


def test_results_with_error(conn_cnx):
    """Gets results with error."""
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        sfqid = None
        try:
            cur.execute("select blah")
            pytest.fail("Should fail here!")
        except ProgrammingError as e:
            sfqid = e.sfqid

        got_sfqid = None
        try:
            cur.query_result(sfqid)
            pytest.fail("Should fail here again!")
        except ProgrammingError as e:
            got_sfqid = e.sfqid

        assert got_sfqid is not None
        assert got_sfqid == sfqid
