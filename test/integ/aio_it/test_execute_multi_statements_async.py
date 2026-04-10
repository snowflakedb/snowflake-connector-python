#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import codecs
import os
from io import BytesIO, StringIO
from unittest.mock import patch

import pytest

from snowflake.connector import ProgrammingError
from snowflake.connector.aio import DictCursor

THIS_DIR = os.path.dirname(os.path.realpath(__file__))


async def test_execute_string(conn_cnx, db_parameters):
    async with conn_cnx() as cnx:
        await cnx.execute_string(
            """
CREATE OR REPLACE TABLE {tbl1} (c1 int, c2 string);
CREATE OR REPLACE TABLE {tbl2} (c1 int, c2 string);
INSERT INTO {tbl1} VALUES(1,'test123');
INSERT INTO {tbl1} VALUES(2,'test234');
INSERT INTO {tbl1} VALUES(3,'test345');
INSERT INTO {tbl2} VALUES(101,'test123');
INSERT INTO {tbl2} VALUES(102,'test234');
INSERT INTO {tbl2} VALUES(103,'test345');
""".format(
                tbl1=db_parameters["name"] + "1", tbl2=db_parameters["name"] + "2"
            ),
            return_cursors=False,
        )
    try:
        async with conn_cnx() as cnx:
            ret = await (
                await cnx.cursor().execute(
                    """
SELECT * FROM {tbl1} ORDER BY 1
""".format(
                        tbl1=db_parameters["name"] + "1"
                    )
                )
            ).fetchall()
            assert ret[0][0] == 1
            assert ret[2][1] == "test345"
            ret = await (
                await cnx.cursor().execute(
                    """
SELECT * FROM {tbl2} ORDER BY 2
""".format(
                        tbl2=db_parameters["name"] + "2"
                    )
                )
            ).fetchall()
            assert ret[0][0] == 101
            assert ret[2][1] == "test345"

            curs = await cnx.execute_string(
                """
SELECT * FROM {tbl1} ORDER BY 1 DESC;
SELECT * FROM {tbl2} ORDER BY 1 DESC;
""".format(
                    tbl1=db_parameters["name"] + "1", tbl2=db_parameters["name"] + "2"
                )
            )
            assert curs[0].rowcount == 3
            assert curs[1].rowcount == 3
            ret1 = await curs[0].fetchone()
            assert ret1[0] == 3
            ret2 = await curs[1].fetchone()
            assert ret2[0] == 103
    finally:
        async with conn_cnx() as cnx:
            await cnx.execute_string(
                """
            DROP TABLE IF EXISTS {tbl1};
            DROP TABLE IF EXISTS {tbl2};
            """.format(
                    tbl1=db_parameters["name"] + "1", tbl2=db_parameters["name"] + "2"
                ),
                return_cursors=False,
            )


@pytest.mark.skipolddriver
async def test_execute_string_dict_cursor(conn_cnx, db_parameters):
    async with conn_cnx() as cnx:
        await cnx.execute_string(
            """
CREATE OR REPLACE TABLE {tbl1} (C1 int, C2 string);
CREATE OR REPLACE TABLE {tbl2} (C1 int, C2 string);
INSERT INTO {tbl1} VALUES(1,'test123');
INSERT INTO {tbl1} VALUES(2,'test234');
INSERT INTO {tbl1} VALUES(3,'test345');
INSERT INTO {tbl2} VALUES(101,'test123');
INSERT INTO {tbl2} VALUES(102,'test234');
INSERT INTO {tbl2} VALUES(103,'test345');
""".format(
                tbl1=db_parameters["name"] + "1", tbl2=db_parameters["name"] + "2"
            ),
            return_cursors=False,
        )
    try:
        async with conn_cnx() as cnx:
            ret = await cnx.cursor(cursor_class=DictCursor).execute(
                """
SELECT * FROM {tbl1} ORDER BY 1
""".format(
                    tbl1=db_parameters["name"] + "1"
                )
            )
            assert ret.rowcount == 3
            assert ret._use_dict_result
            ret = await ret.fetchall()
            assert type(ret) is list
            assert type(ret[0]) is dict
            assert type(ret[2]) is dict
            assert ret[0]["C1"] == 1
            assert ret[2]["C2"] == "test345"

            ret = await cnx.cursor(cursor_class=DictCursor).execute(
                """
SELECT * FROM {tbl2} ORDER BY 2
""".format(
                    tbl2=db_parameters["name"] + "2"
                )
            )
            assert ret.rowcount == 3
            ret = await ret.fetchall()
            assert type(ret) is list
            assert type(ret[0]) is dict
            assert type(ret[2]) is dict
            assert ret[0]["C1"] == 101
            assert ret[2]["C2"] == "test345"

            curs = await cnx.execute_string(
                """
SELECT * FROM {tbl1} ORDER BY 1 DESC;
SELECT * FROM {tbl2} ORDER BY 1 DESC;
""".format(
                    tbl1=db_parameters["name"] + "1", tbl2=db_parameters["name"] + "2"
                ),
                cursor_class=DictCursor,
            )
            assert type(curs) is list
            assert curs[0].rowcount == 3
            assert curs[1].rowcount == 3
            ret1 = await curs[0].fetchone()
            assert type(ret1) is dict
            assert ret1["C1"] == 3
            assert ret1["C2"] == "test345"
            ret2 = await curs[1].fetchone()
            assert type(ret2) is dict
            assert ret2["C1"] == 103
    finally:
        async with conn_cnx() as cnx:
            await cnx.execute_string(
                """
            DROP TABLE IF EXISTS {tbl1};
            DROP TABLE IF EXISTS {tbl2};
            """.format(
                    tbl1=db_parameters["name"] + "1", tbl2=db_parameters["name"] + "2"
                ),
                return_cursors=False,
            )


async def test_execute_string_kwargs(conn_cnx, db_parameters):
    async with conn_cnx() as cnx:
        with patch(
            "snowflake.connector.cursor.SnowflakeCursor.execute", autospec=True
        ) as mock_execute:
            await cnx.execute_string(
                """
CREATE OR REPLACE TABLE {tbl1} (c1 int, c2 string);
CREATE OR REPLACE TABLE {tbl2} (c1 int, c2 string);
INSERT INTO {tbl1} VALUES(1,'test123');
INSERT INTO {tbl1} VALUES(2,'test234');
INSERT INTO {tbl1} VALUES(3,'test345');
INSERT INTO {tbl2} VALUES(101,'test123');
INSERT INTO {tbl2} VALUES(102,'test234');
INSERT INTO {tbl2} VALUES(103,'test345');
    """.format(
                    tbl1=db_parameters["name"] + "1", tbl2=db_parameters["name"] + "2"
                ),
                return_cursors=False,
                _no_results=True,
            )
            for call in mock_execute.call_args_list:
                assert call[1].get("_no_results", False)


async def test_execute_string_with_error(conn_cnx):
    async with conn_cnx() as cnx:
        with pytest.raises(ProgrammingError):
            await cnx.execute_string(
                """
SELECT 1;
SELECT 234;
SELECT bafa;
"""
            )


async def test_execute_stream(conn_cnx):
    # file stream
    expected_results = [1, 2, 3]
    with codecs.open(
        os.path.join(THIS_DIR, "../../data", "multiple_statements.sql"),
        encoding="utf-8",
    ) as f:
        async with conn_cnx() as cnx:
            idx = 0
            async for rec in cnx.execute_stream(f):
                assert (await rec.fetchall())[0][0] == expected_results[idx]
                idx += 1

    # text stream
    expected_results = [3, 4, 5, 6]
    async with conn_cnx() as cnx:
        idx = 0
        async for rec in cnx.execute_stream(
            StringIO("SELECT 3; SELECT 4; SELECT 5;\nSELECT 6;")
        ):
            assert (await rec.fetchall())[0][0] == expected_results[idx]
            idx += 1


async def test_execute_stream_with_error(conn_cnx):
    # file stream
    expected_results = [1, 2, 3]
    with open(os.path.join(THIS_DIR, "../../data", "multiple_statements.sql")) as f:
        async with conn_cnx() as cnx:
            idx = 0
            async for rec in cnx.execute_stream(f):
                assert (await rec.fetchall())[0][0] == expected_results[idx]
                idx += 1

    # read a file including syntax error in the middle
    with codecs.open(
        os.path.join(THIS_DIR, "../../data", "multiple_statements_negative.sql"),
        encoding="utf-8",
    ) as f:
        async with conn_cnx() as cnx:
            gen = cnx.execute_stream(f)
            rec = await anext(gen)
            assert (await rec.fetchall())[0][0] == 987
            # rec = await (await anext(gen)).fetchall()
            # assert rec[0][0] == 987  # the first statement succeeds
            with pytest.raises(ProgrammingError):
                await anext(gen)  # the second statement fails

    # binary stream including Ascii data
    async with conn_cnx() as cnx:
        with pytest.raises(TypeError):
            gen = cnx.execute_stream(
                BytesIO(b"SELECT 3; SELECT 4; SELECT 5;\nSELECT 6;")
            )
            await anext(gen)


@pytest.mark.skipolddriver
async def test_execute_string_empty_lines(conn_cnx, db_parameters):
    """Tests whether execute_string can filter out empty lines."""
    async with conn_cnx() as cnx:
        cursors = await cnx.execute_string("select 1;\n\n")
        assert len(cursors) == 1
        assert [await c.fetchall() for c in cursors] == [[(1,)]]
