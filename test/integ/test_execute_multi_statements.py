#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import codecs
import os
from io import BytesIO, StringIO

import pytest
from mock import patch

from snowflake.connector import DictCursor, ProgrammingError

THIS_DIR = os.path.dirname(os.path.realpath(__file__))


def test_execute_string(conn_cnx, db_parameters):
    with conn_cnx() as cnx:
        cnx.execute_string(
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
        with conn_cnx() as cnx:
            ret = (
                cnx.cursor()
                .execute(
                    """
SELECT * FROM {tbl1} ORDER BY 1
""".format(
                        tbl1=db_parameters["name"] + "1"
                    )
                )
                .fetchall()
            )
            assert ret[0][0] == 1
            assert ret[2][1] == "test345"
            ret = (
                cnx.cursor()
                .execute(
                    """
SELECT * FROM {tbl2} ORDER BY 2
""".format(
                        tbl2=db_parameters["name"] + "2"
                    )
                )
                .fetchall()
            )
            assert ret[0][0] == 101
            assert ret[2][1] == "test345"

            curs = cnx.execute_string(
                """
SELECT * FROM {tbl1} ORDER BY 1 DESC;
SELECT * FROM {tbl2} ORDER BY 1 DESC;
""".format(
                    tbl1=db_parameters["name"] + "1", tbl2=db_parameters["name"] + "2"
                )
            )
            assert curs[0].rowcount == 3
            assert curs[1].rowcount == 3
            ret1 = curs[0].fetchone()
            assert ret1[0] == 3
            ret2 = curs[1].fetchone()
            assert ret2[0] == 103
    finally:
        with conn_cnx() as cnx:
            cnx.execute_string(
                """
            DROP TABLE IF EXISTS {tbl1};
            DROP TABLE IF EXISTS {tbl2};
            """.format(
                    tbl1=db_parameters["name"] + "1", tbl2=db_parameters["name"] + "2"
                ),
                return_cursors=False,
            )


@pytest.mark.skipolddriver
def test_execute_string_dict_cursor(conn_cnx, db_parameters):
    with conn_cnx() as cnx:
        cnx.execute_string(
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
        with conn_cnx() as cnx:
            ret = cnx.cursor(cursor_class=DictCursor).execute(
                """
SELECT * FROM {tbl1} ORDER BY 1
""".format(
                    tbl1=db_parameters["name"] + "1"
                )
            )
            assert ret.rowcount == 3
            assert ret._use_dict_result
            ret = ret.fetchall()
            assert type(ret) is list
            assert type(ret[0]) is dict
            assert type(ret[2]) is dict
            assert ret[0]["C1"] == 1
            assert ret[2]["C2"] == "test345"

            ret = cnx.cursor(cursor_class=DictCursor).execute(
                """
SELECT * FROM {tbl2} ORDER BY 2
""".format(
                    tbl2=db_parameters["name"] + "2"
                )
            )
            assert ret.rowcount == 3
            ret = ret.fetchall()
            assert type(ret) is list
            assert type(ret[0]) is dict
            assert type(ret[2]) is dict
            assert ret[0]["C1"] == 101
            assert ret[2]["C2"] == "test345"

            curs = cnx.execute_string(
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
            ret1 = curs[0].fetchone()
            assert type(ret1) is dict
            assert ret1["C1"] == 3
            assert ret1["C2"] == "test345"
            ret2 = curs[1].fetchone()
            assert type(ret2) is dict
            assert ret2["C1"] == 103
    finally:
        with conn_cnx() as cnx:
            cnx.execute_string(
                """
            DROP TABLE IF EXISTS {tbl1};
            DROP TABLE IF EXISTS {tbl2};
            """.format(
                    tbl1=db_parameters["name"] + "1", tbl2=db_parameters["name"] + "2"
                ),
                return_cursors=False,
            )


def test_execute_string_kwargs(conn_cnx, db_parameters):
    with conn_cnx() as cnx:
        with patch(
            "snowflake.connector.cursor.SnowflakeCursor.execute", autospec=True
        ) as mock_execute:
            cnx.execute_string(
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


def test_execute_string_with_error(conn_cnx):
    with conn_cnx() as cnx:
        with pytest.raises(ProgrammingError):
            cnx.execute_string(
                """
SELECT 1;
SELECT 234;
SELECT bafa;
"""
            )


def test_execute_stream(conn_cnx):
    # file stream
    expected_results = [1, 2, 3]
    with codecs.open(
        os.path.join(THIS_DIR, "../data", "multiple_statements.sql"), encoding="utf-8"
    ) as f:
        with conn_cnx() as cnx:
            for idx, rec in enumerate(cnx.execute_stream(f)):
                assert rec.fetchall()[0][0] == expected_results[idx]

    # text stream
    expected_results = [3, 4, 5, 6]
    with conn_cnx() as cnx:
        for idx, rec in enumerate(
            cnx.execute_stream(StringIO("SELECT 3; SELECT 4; SELECT 5;\nSELECT 6;"))
        ):
            assert rec.fetchall()[0][0] == expected_results[idx]


def test_execute_stream_with_error(conn_cnx):
    # file stream
    expected_results = [1, 2, 3]
    with open(os.path.join(THIS_DIR, "../data", "multiple_statements.sql")) as f:
        with conn_cnx() as cnx:
            for idx, rec in enumerate(cnx.execute_stream(f)):
                assert rec.fetchall()[0][0] == expected_results[idx]

    # read a file including syntax error in the middle
    with codecs.open(
        os.path.join(THIS_DIR, "../data", "multiple_statements_negative.sql"),
        encoding="utf-8",
    ) as f:
        with conn_cnx() as cnx:
            gen = cnx.execute_stream(f)
            rec = next(gen).fetchall()
            assert rec[0][0] == 987  # the first statement succeeds
            with pytest.raises(ProgrammingError):
                next(gen)  # the second statement fails

    # binary stream including Ascii data
    with conn_cnx() as cnx:
        with pytest.raises(TypeError):
            gen = cnx.execute_stream(
                BytesIO(b"SELECT 3; SELECT 4; SELECT 5;\nSELECT 6;")
            )
            next(gen)


@pytest.mark.skipolddriver
def test_execute_string_empty_lines(conn_cnx, db_parameters):
    """Tests whether execute_string can filter out empty lines."""
    with conn_cnx() as cnx:
        cursors = cnx.execute_string("select 1;\n\n")
        assert len(cursors) == 1
        assert [c.fetchall() for c in cursors] == [[(1,)]]
