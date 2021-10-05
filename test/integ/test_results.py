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
        with pytest.raises(ProgrammingError) as e:
            cur.execute("select blah")
        sfqid = e.sfqid

        with pytest.raises(ProgrammingError) as e:
            cur.query_result(sfqid)
        got_sfqid = e.sfqid

        assert sfqid is not None
        assert got_sfqid is not None
        assert got_sfqid == sfqid
