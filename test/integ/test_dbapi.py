#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

"""Script to test database capabilities and the DB-API interface for functionality and data integrity.

Adapted from a script by M-A Lemburg and taken from the MySQL python driver.
"""

import time

import pytest

import snowflake.connector
import snowflake.connector.dbapi
from snowflake.connector import dbapi, errorcode, errors
from snowflake.connector.compat import BASE_EXCEPTION_CLASS

TABLE1 = "dbapi_ddl1"
TABLE2 = "dbapi_ddl2"


def drop_dbapi_tables(conn_cnx):
    with conn_cnx() as cnx:
        with cnx.cursor() as cursor:
            for ddl in (TABLE1, TABLE2):
                dropsql = "drop table if exists {}".format(ddl)
                cursor.execute(dropsql)


def executeDDL1(cursor):
    cursor.execute("create or replace table {} (name string)".format(TABLE1))


def executeDDL2(cursor):
    cursor.execute("create or replace table {} (name string)".format(TABLE2))


@pytest.fixture()
def conn_local(request, conn_cnx):
    def fin():
        drop_dbapi_tables(conn_cnx)

    request.addfinalizer(fin)

    return conn_cnx


def _paraminsert(cur):
    executeDDL1(cur)
    cur.execute("insert into {} values ('string inserted into table')".format(TABLE1))
    assert cur.rowcount in (-1, 1)

    cur.execute(
        "insert into {} values (%(dbapi_ddl2)s)".format(TABLE1), {TABLE2: "Cooper's"}
    )
    assert cur.rowcount in (-1, 1)

    cur.execute("select name from {}".format(TABLE1))
    res = cur.fetchall()
    assert len(res) == 2, "cursor.fetchall returned too few rows"
    dbapi_ddl2s = [res[0][0], res[1][0]]
    dbapi_ddl2s.sort()
    assert dbapi_ddl2s[0] == "Cooper's", "cursor.fetchall retrieved incorrect data"
    assert (
        dbapi_ddl2s[1] == "string inserted into table"
    ), "cursor.fetchall retrieved incorrect data"


def test_connect(conn_cnx):
    with conn_cnx():
        pass


def test_apilevel():
    try:
        apilevel = snowflake.connector.apilevel
        assert apilevel == "2.0", "test_dbapi:test_apilevel"
    except AttributeError:
        raise Exception("test_apilevel: apilevel not defined")


def test_threadsafety():
    try:
        threadsafety = snowflake.connector.threadsafety
        assert threadsafety == 2, "check value of threadsafety is 2"
    except errors.AttributeError:
        raise Exception("AttributeError: not defined in Snowflake.connector")


def test_paramstyle():
    try:
        paramstyle = snowflake.connector.paramstyle
        assert paramstyle == "pyformat"
    except AttributeError:
        raise Exception("snowflake.connector.paramstyle not defined")


def test_exceptions():
    # required exceptions should be defined in a hierarchy
    try:
        assert issubclass(errors._Warning, Exception)
    except AttributeError:
        # Compatibility for olddriver tests
        assert issubclass(errors.Warning, Exception)
    assert issubclass(errors.Error, Exception)
    assert issubclass(errors.InterfaceError, errors.Error)
    assert issubclass(errors.DatabaseError, errors.Error)
    assert issubclass(errors.OperationalError, errors.Error)
    assert issubclass(errors.IntegrityError, errors.Error)
    assert issubclass(errors.InternalError, errors.Error)
    assert issubclass(errors.ProgrammingError, errors.Error)
    assert issubclass(errors.NotSupportedError, errors.Error)


def test_exceptions_as_connection_attributes(conn_cnx):
    with conn_cnx() as con:
        try:
            assert con.Warning == errors._Warning
        except AttributeError:
            # Compatibility for olddriver tests
            assert con.Warning == errors.Warning
        assert con.Error == errors.Error
        assert con.InterfaceError == errors.InterfaceError
        assert con.DatabaseError == errors.DatabaseError
        assert con.OperationalError == errors.OperationalError
        assert con.IntegrityError == errors.IntegrityError
        assert con.InternalError == errors.InternalError
        assert con.ProgrammingError == errors.ProgrammingError
        assert con.NotSupportedError == errors.NotSupportedError


def test_commit(db_parameters):
    con = snowflake.connector.connect(
        account=db_parameters["account"],
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        protocol=db_parameters["protocol"],
    )
    try:
        # Commit must work, even if it doesn't do anything
        con.commit()
    finally:
        con.close()


def test_rollback(conn_cnx, db_parameters):
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        cur.execute("create or replace table {} (a int)".format(db_parameters["name"]))
        cnx.cursor().execute("begin")
        cur.execute(
            """
insert into {} (select seq8() seq
  from table(generator(rowCount => 10)) v)
""".format(
                db_parameters["name"]
            )
        )
        cnx.rollback()
        dbapi_rollback = cur.execute(
            "select count(*) from {}".format(db_parameters["name"])
        ).fetchone()
        assert dbapi_rollback[0] == 0, "transaction not rolled back"
        cur.execute("drop table {}".format(db_parameters["name"]))
        cur.close()


def test_cursor(conn_cnx):
    with conn_cnx() as cnx:
        try:
            cur = cnx.cursor()
        finally:
            cur.close()


def test_cursor_isolation(conn_local):
    with conn_local() as con:
        # two cursors from same connection have transaction isolation
        cur1 = con.cursor()
        cur2 = con.cursor()
        executeDDL1(cur1)
        cur1.execute(
            "insert into {} values ('string inserted into table')".format(TABLE1)
        )
        cur2.execute("select name from {}".format(TABLE1))
        dbapi_ddl1 = cur2.fetchall()
        assert len(dbapi_ddl1) == 1
        assert len(dbapi_ddl1[0]) == 1
        assert dbapi_ddl1[0][0], "string inserted into table"


def test_description(conn_local):
    with conn_local() as con:
        cur = con.cursor()
        assert cur.description is None, (
            "cursor.description should be none if there has not been any "
            "statements executed"
        )

        executeDDL1(cur)
        assert (
            cur.description[0][0].lower() == "status"
        ), "cursor.description returns status of insert"
        cur.execute("select name from %s" % TABLE1)
        assert (
            len(cur.description) == 1
        ), "cursor.description describes too many columns"
        assert (
            len(cur.description[0]) == 7
        ), "cursor.description[x] tuples must have 7 elements"
        assert (
            cur.description[0][0].lower() == "name"
        ), "cursor.description[x][0] must return column name"
        # No, the column type is a numeric value

        # assert cur.description[0][1] == dbapi.STRING, (
        #    'cursor.description[x][1] must return column type. Got %r'
        #    % cur.description[0][1]
        # )

        # Make sure self.description gets reset
        executeDDL2(cur)
        assert len(cur.description) == 1, "cursor.description is not reset"


def test_rowcount(conn_local):
    with conn_local() as con:
        cur = con.cursor()
        assert cur.rowcount is None, (
            "cursor.rowcount not set to None when no statement have not be "
            "executed yet"
        )
        executeDDL1(cur)
        cur.execute(
            ("insert into %s values " "('string inserted into table')") % TABLE1
        )
        cur.execute("select name from %s" % TABLE1)
        assert cur.rowcount == 1, "cursor.rowcount should the number of rows returned"


def test_close(db_parameters):
    con = snowflake.connector.connect(
        account=db_parameters["account"],
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        protocol=db_parameters["protocol"],
    )
    try:
        cur = con.cursor()
    finally:
        con.close()

    # commit is currently a nop; disabling for now
    # connection.commit should raise an Error if called after connection is
    # closed.
    #        assert calling(con.commit()),raises(errors.Error,'con.commit'))

    # disabling due to SNOW-13645
    # cursor.close() should raise an Error if called after connection closed
    #        try:
    #            cur.close()
    # should not get here and raise and exception
    #            assert calling(cur.close()),raises(errors.Error,
    #     'calling cursor.close() twice in a row does not get an error'))
    #        except BASE_EXCEPTION_CLASS as err:
    #            assert error.errno,equal_to(
    #   errorcode.ER_CURSOR_IS_CLOSED),'cursor.close() called twice in a row')

    # calling cursor.execute after connection is closed should raise an error
    try:
        cur.execute("create or replace table {} (name string)".format(TABLE1))
    except BASE_EXCEPTION_CLASS as error:
        assert (
            error.errno == errorcode.ER_CURSOR_IS_CLOSED
        ), "cursor.execute() called twice in a row"

        # try to create a cursor on a closed connection
        try:
            con.cursor()
        except BASE_EXCEPTION_CLASS as error:
            assert (
                error.errno == errorcode.ER_CONNECTION_IS_CLOSED
            ), "tried to create a cursor on a closed cursor"


def test_execute(conn_local):
    with conn_local() as con:
        cur = con.cursor()
        _paraminsert(cur)


def test_executemany(conn_local):
    with conn_local() as con:
        cur = con.cursor()
        executeDDL1(cur)
        margs = [{"dbapi_ddl2": "Cooper's"}, {"dbapi_ddl2": "Boag's"}]

        cur.executemany("insert into %s values (%%(dbapi_ddl2)s)" % (TABLE1), margs)
        assert cur.rowcount == 2, (
            "insert using cursor.executemany set cursor.rowcount to "
            "incorrect value %r" % cur.rowcount
        )
        cur.execute("select name from %s" % TABLE1)
        res = cur.fetchall()
        assert len(res) == 2, "cursor.fetchall retrieved incorrect number of rows"
        dbapi_ddl2s = [res[0][0], res[1][0]]
        dbapi_ddl2s.sort()
        assert dbapi_ddl2s[0] == "Boag's", "incorrect data retrieved"
        assert dbapi_ddl2s[1] == "Cooper's", "incorrect data retrieved"


def test_fetchone(conn_local):
    with conn_local() as con:
        cur = con.cursor()
        # SNOW-13548 - disabled
        #     assert calling(cur.fetchone()),raises(errors.Error),
        #     'cursor.fetchone does not raise an Error if called before
        #      executing a query'
        #     )
        executeDDL1(cur)

        cur.execute("select name from %s" % TABLE1)
        #            assert calling(
        #     cur.fetchone()), is_(None),
        #     'cursor.fetchone should return None if a query does not return any rows')
        #            assert cur.rowcount==-1))

        cur.execute("insert into %s values ('Row 1'),('Row 2')" % TABLE1)
        cur.execute("select name from %s order by 1" % TABLE1)
        r = cur.fetchone()
        assert len(r) == 1, "cursor.fetchone should have returned 1 row"
        assert r[0] == "Row 1", "cursor.fetchone returned incorrect data"
        assert cur.rowcount == 2, "curosr.rowcount should be 2"


SAMPLES = [
    "Carlton Cold",
    "Carlton Draft",
    "Mountain Goat",
    "Redback",
    "String inserted into table",
    "XXXX",
]


def _populate():
    """Returns a list of sql commands to setup the DB for the fetch tests."""
    populate = [
        # NOTE NO GOOD using format to bind data
        "insert into {} values ('{}')".format(TABLE1, s)
        for s in SAMPLES
    ]
    return populate


def test_fetchmany(conn_local):
    with conn_local() as con:
        cur = con.cursor()

        # disable due to SNOW-13648
        #            assert calling(cur.fetchmany()),errors.Error,
        # 'cursor.fetchmany should raise an Error if called without executing a query')

        executeDDL1(cur)
        for sql in _populate():
            cur.execute(sql)

        cur.execute("select name from %s" % TABLE1)
        cur.arraysize = 1
        r = cur.fetchmany()
        assert len(r) == 1, (
            "cursor.fetchmany retrieved incorrect number of rows, "
            "should get 1 rows, received %s" % len(r)
        )
        cur.arraysize = 10
        r = cur.fetchmany(3)  # Should get 3 rows
        assert len(r) == 3, (
            "cursor.fetchmany retrieved incorrect number of rows, "
            "should get 3 rows, received %s" % len(r)
        )
        r = cur.fetchmany(4)  # Should get 2 more
        assert len(r) == 2, (
            "cursor.fetchmany retrieved incorrect number of rows, " "should get 2 more."
        )
        r = cur.fetchmany(4)  # Should be an empty sequence
        assert len(r) == 0, (
            "cursor.fetchmany should return an empty sequence after "
            "results are exhausted"
        )
        assert cur.rowcount in (-1, 6)

        # Same as above, using cursor.arraysize
        cur.arraysize = 4
        cur.execute("select name from %s" % TABLE1)
        r = cur.fetchmany()  # Should get 4 rows
        assert len(r) == 4, "cursor.arraysize not being honoured by fetchmany"
        r = cur.fetchmany()  # Should get 2 more
        assert len(r) == 2
        r = cur.fetchmany()  # Should be an empty sequence
        assert len(r) == 0
        assert cur.rowcount in (-1, 6)

        cur.arraysize = 6
        cur.execute("select name from %s order by 1" % TABLE1)
        rows = cur.fetchmany()  # Should get all rows
        assert cur.rowcount in (-1, 6)
        assert len(rows) == 6
        assert len(rows) == 6
        rows = [row[0] for row in rows]
        rows.sort()

        # Make sure we get the right data back out
        for i in range(0, 6):
            assert rows[i] == SAMPLES[i], "incorrect data retrieved by cursor.fetchmany"

        rows = cur.fetchmany()  # Should return an empty list
        assert len(rows) == 0, (
            "cursor.fetchmany should return an empty sequence if "
            "called after the whole result set has been fetched"
        )
        assert cur.rowcount in (-1, 6)

        executeDDL2(cur)
        cur.execute("select name from %s" % TABLE2)
        r = cur.fetchmany()  # Should get empty sequence
        assert len(r) == 0, (
            "cursor.fetchmany should return an empty sequence if "
            "query retrieved no rows"
        )
        assert cur.rowcount in (-1, 0)


def test_fetchall(conn_local):
    with conn_local() as con:
        cur = con.cursor()
        # disable due to SNOW-13648
        #            assert calling(cur.fetchall()),raises(errors.Error),
        #                        'cursor.fetchall should raise an Error if called without executing a query'
        #                        )
        executeDDL1(cur)
        for sql in _populate():
            cur.execute(sql)
        # assert calling(cur.fetchall()),errors.Error,'cursor.fetchall should raise an Error if called',
        #                                'after executing a a statement that does not return rows'
        #                                )

        cur.execute("select name from {}".format(TABLE1))
        rows = cur.fetchall()
        assert cur.rowcount in (-1, len(SAMPLES))
        assert len(rows) == len(SAMPLES), "cursor.fetchall did not retrieve all rows"
        rows = [r[0] for r in rows]
        rows.sort()
        for i in range(0, len(SAMPLES)):
            assert rows[i] == SAMPLES[i], "cursor.fetchall retrieved incorrect rows"
        rows = cur.fetchall()
        assert len(rows) == 0, (
            "cursor.fetchall should return an empty list if called "
            "after the whole result set has been fetched"
        )
        assert cur.rowcount in (-1, len(SAMPLES))

        executeDDL2(cur)
        cur.execute("select name from %s" % TABLE2)
        rows = cur.fetchall()
        assert cur.rowcount == 0, "executed but no row was returned"
        assert len(rows) == 0, (
            "cursor.fetchall should return an empty list if "
            "a select query returns no rows"
        )


def test_mixedfetch(conn_local):
    with conn_local() as con:
        cur = con.cursor()
        executeDDL1(cur)
        for sql in _populate():
            cur.execute(sql)

        cur.execute("select name from %s" % TABLE1)
        rows1 = cur.fetchone()
        rows23 = cur.fetchmany(2)
        rows4 = cur.fetchone()
        rows56 = cur.fetchall()
        assert cur.rowcount in (-1, 6)
        assert len(rows23) == 2, "fetchmany returned incorrect number of rows"
        assert len(rows56) == 2, "fetchall returned incorrect number of rows"

        rows = [rows1[0]]
        rows.extend([rows23[0][0], rows23[1][0]])
        rows.append(rows4[0])
        rows.extend([rows56[0][0], rows56[1][0]])
        rows.sort()
        for i in range(0, len(SAMPLES)):
            assert rows[i] == SAMPLES[i], "incorrect data returned"


def test_arraysize(conn_cnx):
    with conn_cnx() as con:
        cur = con.cursor()
        assert hasattr(cur, "arraysize"), "cursor.arraysize must be defined"


def test_setinputsizes(conn_local):
    with conn_local() as con:
        cur = con.cursor()
        cur.setinputsizes((25,))
        _paraminsert(cur)  # Make sure cursor still works


def test_setoutputsize_basic(conn_local):
    # Basic test is to make sure setoutputsize doesn't blow up
    with conn_local() as con:
        cur = con.cursor()
        cur.setoutputsize(1000)
        cur.setoutputsize(2000, 0)
        _paraminsert(cur)  # Make sure the cursor still works


def test_description2(conn_local):
    try:
        with conn_local() as con:
            # ENABLE_FIX_67159 changes the column size to the actual size. By default it is disabled at the moment.
            expected_column_size = (
                26 if not con.account.startswith("sfctest0") else 16777216
            )
            cur = con.cursor()
            executeDDL1(cur)
            assert (
                len(cur.description) == 1
            ), "length cursor.description should be 1 after executing an insert"
            cur.execute("select name from %s" % TABLE1)
            assert (
                len(cur.description) == 1
            ), "cursor.description returns too many columns"
            assert (
                len(cur.description[0]) == 7
            ), "cursor.description[x] tuples must have 7 elements"
            assert (
                cur.description[0][0].lower() == "name"
            ), "cursor.description[x][0] must return column name"

            # Make sure self.description gets reset
            executeDDL2(cur)
            # assert cur.description is None, (
            #    'cursor.description not being set to None')
            # description fields:  name | type_code | display_size | internal_size | precision | scale | null_ok
            # name and type_code are mandatory, the other five are optional and are set to None if no meaningful values can be provided.
            expected = [
                ("COL0", 0, None, None, 38, 0, True),
                # number (FIXED)
                ("COL1", 0, None, None, 9, 4, False),
                # decimal
                ("COL2", 2, None, expected_column_size, None, None, False),
                # string
                ("COL3", 3, None, None, None, None, True),
                # date
                ("COL4", 6, None, None, 0, 9, True),
                # timestamp
                ("COL5", 5, None, None, None, None, True),
                # variant
                ("COL6", 6, None, None, 0, 9, True),
                # timestamp_ltz
                ("COL7", 7, None, None, 0, 9, True),
                # timestamp_tz
                ("COL8", 8, None, None, 0, 9, True),
                # timestamp_ntz
                ("COL9", 9, None, None, None, None, True),
                # object
                ("COL10", 10, None, None, None, None, True),
                # array
                #                ('col11', 11, ... # binary
                ("COL12", 12, None, None, 0, 9, True)
                # time
                #                ('col13', 13, ... # boolean
            ]

            with conn_local() as cnx:
                cursor = cnx.cursor()
                cursor.execute(
                    """
alter session set timestamp_input_format = 'YYYY-MM-DD HH24:MI:SS TZH:TZM'
"""
                )
                cursor.execute(
                    """
create or replace table test_description (
col0 number, col1 decimal(9,4) not null,
col2 string not null default 'place-holder', col3 date, col4 timestamp_ltz,
col5 variant, col6 timestamp_ltz, col7 timestamp_tz, col8 timestamp_ntz,
col9 object, col10 array, col12 time)
"""  # col11 binary, col12 time
                )
                cursor.execute(
                    """
insert into test_description select column1, column2, column3, column4,
column5, parse_json(column6), column7, column8, column9, parse_xml(column10),
parse_json(column11), column12 from VALUES
(65538, 12345.1234, 'abcdefghijklmnopqrstuvwxyz',
'2015-09-08','2015-09-08 15:39:20 -00:00','{ name:[1, 2, 3, 4]}',
'2015-06-01 12:00:01 +00:00','2015-04-05 06:07:08 +08:00',
'2015-06-03 12:00:03 +03:00',
'<note> <to>Juliette</to><from>Romeo</from></note>',
'["xx", "yy", "zz", null, 1]', '12:34:56')
"""
                )
                cursor.execute("select * from test_description")
                cursor.fetchone()
                assert cursor.description == expected, "cursor.description is incorrect"
    finally:
        with conn_local() as con:
            with con.cursor() as cursor:
                cursor.execute("drop table if exists test_description")
                cursor.execute("alter session set timestamp_input_format = default")


def test_closecursor(conn_cnx):
    with conn_cnx() as cnx:
        cursor = cnx.cursor()
        cursor.close()
        # The connection will be unusable from this point forward; an Error (or subclass) exception will
        # be raised if any operation is attempted with the connection. The same applies to all cursor
        # objects trying to use the connection.
        # close twice


def test_None(conn_local):
    with conn_local() as con:
        cur = con.cursor()
        executeDDL1(cur)
        cur.execute("insert into %s values (NULL)" % TABLE1)
        cur.execute("select name from %s" % TABLE1)
        r = cur.fetchall()
        assert len(r) == 1
        assert len(r[0]) == 1
        assert r[0][0] is None, "NULL value not returned as None"


def test_Date():
    d1 = snowflake.connector.dbapi.Date(2002, 12, 25)
    d2 = snowflake.connector.dbapi.DateFromTicks(
        time.mktime((2002, 12, 25, 0, 0, 0, 0, 0, 0))
    )
    # API doesn't specify, but it seems to be implied
    assert str(d1) == str(d2)


def test_Time():
    t1 = snowflake.connector.dbapi.Time(13, 45, 30)
    t2 = snowflake.connector.dbapi.TimeFromTicks(
        time.mktime((2001, 1, 1, 13, 45, 30, 0, 0, 0))
    )
    # API doesn't specify, but it seems to be implied
    assert str(t1) == str(t2)


def test_Timestamp():
    t1 = snowflake.connector.dbapi.Timestamp(2002, 12, 25, 13, 45, 30)
    t2 = snowflake.connector.dbapi.TimestampFromTicks(
        time.mktime((2002, 12, 25, 13, 45, 30, 0, 0, 0))
    )
    # API doesn't specify, but it seems to be implied
    assert str(t1) == str(t2)


def test_STRING():
    assert hasattr(dbapi, "STRING"), "dbapi.STRING must be defined"


def test_BINARY():
    assert hasattr(dbapi, "BINARY"), "dbapi.BINARY must be defined."


def test_NUMBER():
    assert hasattr(dbapi, "NUMBER"), "dbapi.NUMBER must be defined."


def test_DATETIME():
    assert hasattr(dbapi, "DATETIME"), "dbapi.DATETIME must be defined."


def test_ROWID():
    assert hasattr(dbapi, "ROWID"), "dbapi.ROWID must be defined."


def test_substring(conn_local):
    with conn_local() as con:
        cur = con.cursor()
        executeDDL1(cur)
        args = {"dbapi_ddl2": '"" "\'",\\"\\""\'"'}
        cur.execute("insert into %s values (%%(dbapi_ddl2)s)" % TABLE1, args)
        cur.execute("select name from %s" % TABLE1)
        res = cur.fetchall()
        dbapi_ddl2 = res[0][0]
        assert (
            dbapi_ddl2 == args["dbapi_ddl2"]
        ), "incorrect data retrieved, got {}, should be {}".format(
            dbapi_ddl2, args["dbapi_ddl2"]
        )


def test_escape(conn_local):
    teststrings = [
        "abc\ndef",
        "abc\\ndef",
        "abc\\\ndef",
        "abc\\\\ndef",
        "abc\\\\\ndef",
        'abc"def',
        'abc""def',
        "abc'def",
        "abc''def",
        'abc"def',
        'abc""def',
        "abc'def",
        "abc''def",
        "abc\tdef",
        "abc\\tdef",
        "abc\\\tdef",
        "\\x",
    ]

    with conn_local() as con:
        cur = con.cursor()
        executeDDL1(cur)
        for i in teststrings:
            args = {"dbapi_ddl2": i}
            cur.execute("insert into %s values (%%(dbapi_ddl2)s)" % TABLE1, args)
            cur.execute("select * from %s" % TABLE1)
            row = cur.fetchone()
            cur.execute("delete from %s where name=%%s" % TABLE1, i)
            assert (
                i == row[0]
            ), "newline not properly converted, got {}, should be {}".format(row[0], i)
