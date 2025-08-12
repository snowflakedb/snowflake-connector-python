#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

from snowflake.connector import ProgrammingError


async def test_results(conn_cnx):
    """Gets results for the given qid."""
    async with conn_cnx() as cnx:
        cur = cnx.cursor()
        await cur.execute("select * from values(1,2),(3,4)")
        sfqid = cur.sfqid
        cur = await cur.query_result(sfqid)
        got_sfqid = cur.sfqid
        assert await cur.fetchall() == [(1, 2), (3, 4)]
        assert sfqid == got_sfqid


async def test_results_with_error(conn_cnx):
    """Gets results with error."""
    async with conn_cnx() as cnx:
        cur = cnx.cursor()
        with pytest.raises(ProgrammingError) as e:
            await cur.execute("select blah")
        sfqid = e.value.sfqid

        with pytest.raises(ProgrammingError) as e:
            await cur.query_result(sfqid)
        got_sfqid = e.value.sfqid

        assert sfqid is not None
        assert got_sfqid is not None
        assert got_sfqid == sfqid
