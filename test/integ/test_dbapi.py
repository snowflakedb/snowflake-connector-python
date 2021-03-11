#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

"""Script to test database capabilities and the DB-API interface for functionality and data integrity.

Adapted from a script by M-A Lemburg and taken from the MySQL python driver.
"""

import pytest

from snowflake.connector import DatabaseError, errorcode, errors

from ..integ_helpers import drop_table, execute
from ..randomize import random_string

pytestmark = pytest.mark.parallel


def _create_table(cursor, table_name):
    cursor.execute(f'create table {table_name} (name string)')


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


def test_commit(conn_testaccount):
    try:
        # Commit must work, even if it doesn't do anything
        conn_testaccount.commit()
    finally:
        conn_testaccount.close()


def test_rollback(conn_cnx, request):
    table_name = random_string(3, prefix="test_rollback_")
    with conn_cnx() as cnx, cnx.cursor() as cur:
        cur.execute(f'create table {table_name} (a int)')
        request.addfinalizer(drop_table(conn_cnx, table_name))
        cnx.cursor().execute("begin")
        cur.execute(f"""
insert into {table_name} (select seq8() seq
  from table(generator(rowCount => 10)) v)
""")
        cnx.rollback()
        dbapi_rollback = cur.execute(
            f"select count(*) from {table_name}").fetchone()
        assert dbapi_rollback[0] == 0, 'transaction not rolled back'


def test_cursor_isolation(conn_cnx, request):
    """Tests that two cursors from same connection have transaction isolation."""
    table_1 = random_string(3, prefix="test_cursor_isolation_1_")
    with conn_cnx() as con:
        cur1 = con.cursor()
        cur2 = con.cursor()
        _create_table(cur1, table_1)
        request.addfinalizer(drop_table(conn_cnx, table_1))
        cur1.execute(
            f"insert into {table_1} values ('string inserted into table')")
        cur2.execute(f"select name from {table_1}")
        dbapi_ddl1 = cur2.fetchall()
        assert len(dbapi_ddl1) == 1
        assert len(dbapi_ddl1[0]) == 1
        assert dbapi_ddl1[0][0], 'string inserted into table'


def test_description(conn_cnx, request):
    table_name = random_string(5, prefix="test_description_")
    with conn_cnx() as con, con.cursor() as cur:
        assert cur.description is None, (
            'cursor.description should be none if there has not been any '
            'statements executed')

        _create_table(cur, table_name)
        request.addfinalizer(drop_table(conn_cnx, table_name))

        assert cur.description[0][0].lower() == 'status', (
            'cursor.description returns status of insert'
        )
        cur.execute(f'select name from {table_name}')
        assert len(cur.description) == 1, (
            'cursor.description describes too many columns'
        )
        assert len(cur.description[0]) == 7, (
            'cursor.description[x] tuples must have 7 elements'
        )
        assert cur.description[0][0].lower() == 'name', (
            'cursor.description[x][0] must return column name'
        )

        # Make sure self.description gets reset
        cur.execute("select 1")
        assert len(cur.description) == 1, (
            'cursor.description is not reset')


def test_rowcount(conn_cnx, request):
    with conn_cnx() as con, con.cursor() as cur:
        table_name = random_string(3, prefix="test_rowcount_")
        assert cur.rowcount is None, (
            'cursor.rowcount not set to None when no statement have not be '
            'executed yet'
        )
        _create_table(cur, table_name)
        request.addfinalizer(drop_table(conn_cnx, table_name))

        cur.execute(f"insert into {table_name} values ('string inserted into table')")
        cur.execute(f"select name from {table_name}")
        assert cur.rowcount == 1, (
            'cursor.rowcount indicates wrong number of rows returned'
        )


def test_close(conn_testaccount):
    con = conn_testaccount
    cur = con.cursor()
    con.close()

    with pytest.raises(errors.Error):
        con.commit()

    # calling cursor.execute after connection is closed should raise an error
    with pytest.raises(DatabaseError, match=r"Cursor is closed in execute") as err:
        cur.execute("select 1")
        assert err.errno == errorcode.ER_CURSOR_IS_CLOSED

    # try to create a cursor on a closed connection
    with pytest.raises(DatabaseError, match=r"Connection is closed") as err:
        con.cursor()
        assert err.errno == errorcode.ER_CONNECTION_IS_CLOSED


def test_fetchone(conn_cnx, request):
    table_name = random_string(3, prefix="test_fetchone_")
    with conn_cnx() as con:
        cur = con.cursor()
        _create_table(cur, table_name)
        request.addfinalizer(drop_table(conn_cnx, table_name))
        cur.execute(f'select name from {table_name}')
        cur.execute(
            f"insert into {table_name} values ('Row 1'),('Row 2')")
        cur.execute(
            f'select name from {table_name} order by 1')
        r = cur.fetchone()
        assert len(r) == 1, (
            'cursor.fetchone should have returned 1 row')
        assert r[0] == 'Row 1', (
            'cursor.fetchone returned incorrect data')
        assert cur.rowcount == 2, (
            'curosr.rowcount should be 2')


SAMPLES = [
    'Carlton Cold',
    'Carlton Draft',
    'Mountain Goat',
    'Redback',
    'String inserted into table',
    'XXXX'
]


def _populate(cursor, table_name):
    """Returns a list of sql commands to setup the DB for the fetch tests."""
    cursor.executemany(f'insert into {table_name} values(%(value)s)', [
        {'value': s} for s in SAMPLES
    ])


def test_fetchmany_arraysize(conn_cnx, request):
    table_name = random_string(3, prefix="test_fetchmany_arraysize_1_")
    with conn_cnx() as con, con.cursor() as cur:
        _create_table(cur, table_name)
        request.addfinalizer(drop_table(conn_cnx, table_name))

        cur.execute(f'select name from {table_name}')
        r = cur.fetchmany()  # Should get empty sequence
        assert len(r) == 0, (
            'cursor.fetchmany should return an empty sequence if '
            'query retrieved no rows'
        )
        assert cur.rowcount in (-1, 0)

        _populate(cur, table_name)

        cur.arraysize = 4
        cur.execute(f'select name from {table_name}')
        r = cur.fetchmany()  # Should get 4 rows
        assert len(r) == 4, (
            'cursor.arraysize not being honoured by fetchmany'
        )
        r = cur.fetchmany()  # Should get 2 more
        assert len(r) == 2
        r = cur.fetchmany()  # Should be an empty sequence
        assert len(r) == 0
        assert cur.rowcount in (-1, 6)

        cur.arraysize = 6
        cur.execute(
            f'select name from {table_name} order by 1')
        rows = cur.fetchmany()  # Should get all rows
        assert cur.rowcount in (-1, 6)
        assert len(rows) == 6
        assert len(rows) == 6
        rows = sorted([row[0] for row in rows])

        # Make sure we get the right data back out
        for i in range(0, 6):
            assert rows[i] == SAMPLES[i], (
                'incorrect data retrieved by cursor.fetchmany'
            )

        rows = cur.fetchmany()  # Should return an empty list
        assert len(rows) == 0, (
            'cursor.fetchmany should return an empty sequence if '
            'called after the whole result set has been fetched'
        )
        assert cur.rowcount in (-1, 6)


def test_fetchall(conn_cnx, request):
    table_name = random_string(3, prefix="test_fetchall_")
    with conn_cnx() as con, con.cursor() as cur:
        _create_table(cur, table_name)
        request.addfinalizer(drop_table(conn_cnx, table_name))

        cur.execute(
            f'select name from {table_name}')
        rows = cur.fetchall()
        assert cur.rowcount == 0, 'executed but no row was returned'
        assert len(rows) == 0, (
            'cursor.fetchall should return an empty list if '
            'a select query returns no rows'
        )

        _populate(cur, table_name)

        cur.execute(
            f'select name from {table_name}')
        rows = cur.fetchall()
        assert cur.rowcount in (-1, len(SAMPLES))
        assert len(rows) == len(SAMPLES), (
            'cursor.fetchall did not retrieve all rows'
        )
        rows = sorted([r[0] for r in rows])

        for i in range(0, len(SAMPLES)):
            assert rows[i] == SAMPLES[i], (
                'cursor.fetchall retrieved incorrect rows'
            )
        rows = cur.fetchall()
        assert len(rows) == 0, (
            'cursor.fetchall should return an empty list if called '
            'after the whole result set has been fetched'
        )
        assert cur.rowcount in (-1, len(SAMPLES))


def test_mixedfetch(conn_cnx, request):
    table_name = random_string(3, prefix="test_mixedfetch_")
    with conn_cnx() as con, con.cursor() as cur:
        _create_table(cur, table_name)
        request.addfinalizer(drop_table(conn_cnx, table_name))
        _populate(cur, table_name)

        cur.execute(
            f'select name from {table_name}')
        rows1 = cur.fetchone()
        rows23 = cur.fetchmany(2)
        rows4 = cur.fetchone()
        rows56 = cur.fetchall()
        assert cur.rowcount in (-1, 6)
        assert len(rows23) == 2, (
            'fetchmany returned incorrect number of rows'
        )
        assert len(rows56) == 2, (
            'fetchall returned incorrect number of rows'
        )

        rows = [rows1[0], rows23[0][0], rows23[1][0], rows4[0], rows56[0][0], rows56[1][0]]
        for i in range(0, len(SAMPLES)):
            assert rows[i] == SAMPLES[i], (
                'incorrect data returned'
            )


def test_arraysize(conn_cnx):
    with conn_cnx() as con:
        cur = con.cursor()
        assert hasattr(cur, 'arraysize'), (
            'cursor.arraysize must be defined'
        )


def test_setinputsizes(
        conn_cnx):
    """This test ensures calling setinputsizes() does not report error."""
    with conn_cnx() as con:
        cur = con.cursor()
        cur.setinputsizes((25,))
        # Make sure cursor still works
        res = cur.execute("select 17").fetchall()
        assert res[0][0] == 17


def test_setoutputsize(
        conn_cnx):
    """This test ensures calling setoutputsizes() does report error."""
    with conn_cnx() as con:
        cur = con.cursor()
        cur.setoutputsize(1000)
        cur.setoutputsize(2000, 0)
        # Make sure the cursor still works
        res = cur.execute("select 17").fetchone()
        assert res[0] == 17


def test_description_2(conn_cnx, request):
    table_name = random_string(3, prefix="test_description2_")

    with conn_cnx() as con, con.cursor() as cur:
        # ENABLE_FIX_67159 changes the column size to the actual size. By default it is disabled at the moment.
        expected_column_size = 26 if not con.account.startswith("sfctest0") else 16777216

        _create_table(cur, table_name)
        request.addfinalizer(drop_table(conn_cnx, table_name))

        assert len(
            cur.description) == 1, (
            'length cursor.description should be 1 after executing an insert'
        )
        cur.execute(
            f'select name from {table_name}')
        assert len(
            cur.description) == 1, (
            'cursor.description returns too many columns'
        )
        assert len(
            cur.description[0]) == 7, (
            'cursor.description[x] tuples must have 7 elements'
        )
        assert cur.description[0][0].lower() == 'name', (
            'cursor.description[x][0] must return column name'
        )

        expected = [
            ('COL0', 0, None, None, 38, 0, True),
            # number (FIXED)
            ('COL1', 0, None, None, 9, 4, False),
            # decimal
            ('COL2', 2, None, expected_column_size, None, None, False),
            # string
            ('COL3', 3, None, None, None, None, True),
            # date
            ('COL4', 6, None, None, 0, 9, True),
            # timestamp
            ('COL5', 5, None, None, None, None, True),
            # variant
            ('COL6', 6, None, None, 0, 9, True),
            # timestamp_ltz
            ('COL7', 7, None, None, 0, 9, True),
            # timestamp_tz
            ('COL8', 8, None, None, 0, 9, True),
            # timestamp_ntz
            ('COL9', 9, None, None, None, None, True),
            # object
            ('COL10', 10, None, None,
             None, None, True),
            # array
            #                ('col11', 11, ... # binary
            ('COL12', 12, None, None, 0, 9, True)
            # time
            #                ('col13', 13, ... # boolean
        ]
        description_table = random_string(3, prefix="description_table_")
        with conn_cnx() as cnx:
            cursor = cnx.cursor()
            cursor.execute("""
alter session set timestamp_input_format = 'YYYY-MM-DD HH24:MI:SS TZH:TZM'
""")
            request.addfinalizer(execute(conn_cnx, "alter session set timestamp_input_format = default"))

            cursor.execute(f"""
create table {description_table} (
col0 number, col1 decimal(9,4) not null,
col2 string not null default 'place-holder', col3 date, col4 timestamp_ltz,
col5 variant, col6 timestamp_ltz, col7 timestamp_tz, col8 timestamp_ntz,
col9 object, col10 array, col12 time)
""")
            request.addfinalizer(drop_table(conn_cnx, table_name))
            cursor.execute(f"""
insert into {description_table} select column1, column2, column3, column4,
column5, parse_json(column6), column7, column8, column9, parse_xml(column10),
parse_json(column11), column12 from VALUES
(65538, 12345.1234, 'abcdefghijklmnopqrstuvwxyz',
'2015-09-08','2015-09-08 15:39:20 -00:00','{{ name:[1, 2, 3, 4]}}',
'2015-06-01 12:00:01 +00:00','2015-04-05 06:07:08 +08:00',
'2015-06-03 12:00:03 +03:00',
'<note> <to>Juliette</to><from>Romeo</from></note>',
'["xx", "yy", "zz", null, 1]', '12:34:56')
""")
            cursor.execute(
                f"select * from {description_table}")
            cursor.fetchone()
            assert cursor.description == expected, (
                "cursor.description is incorrect")


def test_None(conn_cnx):
    with conn_cnx() as con, con.cursor() as cur:
        table_name = random_string(3, prefix="test_None_")
        _create_table(cur, table_name)
        cur.execute(
            f'insert into {table_name} values (NULL)')
        cur.execute(
            f'select name from {table_name}')
        r = cur.fetchall()
        assert len(r) == 1
        assert len(r[0]) == 1
        assert r[0][0] is None, 'NULL value not returned as None'


def test_substring(
        conn_cnx, request):
    table_name = random_string(3, prefix="test_substring_")
    with conn_cnx() as con, con.cursor() as cur:
        _create_table(cur, table_name)
        request.addfinalizer(drop_table(conn_cnx, table_name))

        args = {
            'dbapi_ddl2': '"" \"\'\",\\"\\"\"\'\"'}
        cur.execute(
            f'insert into {table_name} values (%(dbapi_ddl2)s)', args)
        cur.execute(
            f'select name from {table_name}')
        res = cur.fetchall()
        dbapi_ddl2 = \
            res[0][0]
        assert dbapi_ddl2 == args['dbapi_ddl2'], (
            f"incorrect data retrieved, got {dbapi_ddl2}, should be {args['dbapi_ddl2']}")


def test_escape(
        conn_cnx, request):
    values = [
        'abc\ndef',
        'abc\\ndef',
        'abc\\\ndef',
        'abc\\\\ndef',
        'abc\\\\\ndef',
        'abc"def',
        'abc""def',
        'abc\'def',
        'abc\'\'def',
        "abc\"def",
        "abc\"\"def",
        "abc'def",
        "abc''def",
        "abc\tdef",
        "abc\\tdef",
        "abc\\\tdef",
        "\\x"
    ]
    table_name = random_string(3, prefix="test_escape_")
    with conn_cnx() as con, con.cursor() as cur:
        cur.execute(f"create table {table_name} (col0 int, col1 string)")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        for i in range(len(values)):
            cur.execute(f"insert into {table_name} values ({i} , %(value)s)", {'value': values[i]})
        cur.execute(f'select * from {table_name}')
        results = cur.fetchall()
        for idx, val in results:
            assert values[idx] == val
