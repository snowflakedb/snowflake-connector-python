#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import calendar
import tempfile
import time
from datetime import date, datetime
from datetime import time as datetime_time
from datetime import timedelta
from decimal import Decimal

import pendulum
import pytest
import pytz
from mock import patch

from snowflake.connector import errors
from snowflake.connector.converter import convert_datetime_to_epoch
from snowflake.connector.errors import ForbiddenError, ProgrammingError

from ..integ_helpers import drop_table
from ..randomize import random_string

pytestmark = pytest.mark.parallel

tempfile.gettempdir()

PST_TZ = "America/Los_Angeles"
JST_TZ = "Asia/Tokyo"
CLIENT_STAGE_ARRAY_BINDING_THRESHOLD = 'CLIENT_STAGE_ARRAY_BINDING_THRESHOLD'


def test_invalid_binding_option(conn_cnx):
    """Invalid paramstyle parameters."""
    with pytest.raises(ProgrammingError):
        with conn_cnx(paramstyle='hahaha'):
            pass

    # valid cases
    for s in ['format', 'pyformat', 'qmark', 'numeric']:
        with conn_cnx(paramstyle=s):
            pass


@pytest.mark.parametrize("bulk_array_optimization", [pytest.param(True, marks=pytest.mark.skipolddriver), False])
def test_binding(request, conn_cnx, bulk_array_optimization):
    """Paramstyle qmark binding tests to cover basic data types."""
    table_name = random_string(3, prefix="test_binding")
    CREATE_TABLE = f'''create table {table_name} (
        c1 BOOLEAN,
        c2 INTEGER,
        c3 NUMBER(38,2),
        c4 VARCHAR(1234),
        c5 FLOAT,
        c6 BINARY,
        c7 BINARY,
        c8 TIMESTAMP_NTZ,
        c9 TIMESTAMP_NTZ,
        c10 TIMESTAMP_NTZ,
        c11 TIMESTAMP_NTZ,
        c12 TIMESTAMP_LTZ,
        c13 TIMESTAMP_LTZ,
        c14 TIMESTAMP_LTZ,
        c15 TIMESTAMP_LTZ,
        c16 TIMESTAMP_TZ,
        c17 TIMESTAMP_TZ,
        c18 TIMESTAMP_TZ,
        c19 TIMESTAMP_TZ,
        c20 DATE,
        c21 TIME,
        c22 TIMESTAMP_NTZ,
        c23 TIME,
        c24 STRING,
        c25 STRING,
        c26 STRING
        )
    '''
    INSERT = f"""
insert into {table_name} values(
?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?,?,?)
"""
    with conn_cnx(paramstyle='qmark') as cnx:
        cnx.cursor().execute(CREATE_TABLE)
    request.addfinalizer(drop_table(conn_cnx, table_name))
    current_utctime = datetime.utcnow()
    current_localtime = pytz.utc.localize(
        current_utctime,
        is_dst=False).astimezone(pytz.timezone(PST_TZ))
    current_localtime_without_tz = datetime.now()
    current_localtime_with_other_tz = pytz.utc.localize(
        current_localtime_without_tz,
        is_dst=False).astimezone(pytz.timezone(JST_TZ))
    dt = date(2017, 12, 30)
    tm = datetime_time(hour=1, minute=2, second=3, microsecond=456)
    struct_time_v = time.strptime("30 Sep 01 11:20:30", "%d %b %y %H:%M:%S")
    tdelta = timedelta(seconds=tm.hour * 3600 + tm.minute * 60 + tm.second,
                       microseconds=tm.microsecond)
    data = (
        True,
        1,
        Decimal("1.2"),
        'str1',
        1.2,
        # Py2 has bytes in str type, so Python Connector
        bytes(b'abc'),
        bytearray(b'def'),
        current_utctime,
        current_localtime,
        current_localtime_without_tz,
        current_localtime_with_other_tz,
        ("TIMESTAMP_LTZ", current_utctime),
        ("TIMESTAMP_LTZ", current_localtime),
        ("TIMESTAMP_LTZ", current_localtime_without_tz),
        ("TIMESTAMP_LTZ", current_localtime_with_other_tz),
        ("TIMESTAMP_TZ", current_utctime),
        ("TIMESTAMP_TZ", current_localtime),
        ("TIMESTAMP_TZ", current_localtime_without_tz),
        ("TIMESTAMP_TZ", current_localtime_with_other_tz),
        dt,
        tm,
        ("TIMESTAMP_NTZ", struct_time_v),
        ("TIME", tdelta),
        ("TEXT", None),
        "",
        ",an\\\\escaped\"line\n"
    )
    with conn_cnx(paramstyle='qmark', timezone=PST_TZ) as cnx:
        csr = cnx.cursor()
        if bulk_array_optimization:
            cnx._session_parameters[CLIENT_STAGE_ARRAY_BINDING_THRESHOLD] = 1
            csr.executemany(INSERT, [data])
        else:
            csr.execute(INSERT, data)

        ret = cnx.cursor().execute(f"""
select * from {table_name} where c1=? and c2=?
""", (True, 1)).fetchone()
        assert len(ret) == 26
        assert ret[0], "BOOLEAN"
        assert ret[2] == Decimal("1.2"), "NUMBER"
        assert ret[4] == 1.2, "FLOAT"
        assert ret[5] == b'abc'
        assert ret[6] == b'def'
        assert ret[7] == current_utctime
        assert convert_datetime_to_epoch(
            ret[8]) == convert_datetime_to_epoch(current_localtime)
        assert convert_datetime_to_epoch(
            ret[9]) == convert_datetime_to_epoch(
            current_localtime_without_tz)
        assert convert_datetime_to_epoch(
            ret[10]) == convert_datetime_to_epoch(
            current_localtime_with_other_tz)
        assert convert_datetime_to_epoch(
            ret[11]) == convert_datetime_to_epoch(current_utctime)
        assert convert_datetime_to_epoch(
            ret[12]) == convert_datetime_to_epoch(current_localtime)
        assert convert_datetime_to_epoch(
            ret[13]) == convert_datetime_to_epoch(
            current_localtime_without_tz)
        assert convert_datetime_to_epoch(
            ret[14]) == convert_datetime_to_epoch(
            current_localtime_with_other_tz)
        assert convert_datetime_to_epoch(
            ret[15]) == convert_datetime_to_epoch(current_utctime)
        assert convert_datetime_to_epoch(
            ret[16]) == convert_datetime_to_epoch(current_localtime)
        assert convert_datetime_to_epoch(
            ret[17]) == convert_datetime_to_epoch(
            current_localtime_without_tz)
        assert convert_datetime_to_epoch(
            ret[18]) == convert_datetime_to_epoch(
            current_localtime_with_other_tz)
        assert ret[19] == dt
        assert ret[20] == tm
        assert convert_datetime_to_epoch(
            ret[21]) == calendar.timegm(struct_time_v)
        assert timedelta(seconds=ret[22].hour * 3600 + ret[22].minute * 60 +
                                 ret[22].second,
                         microseconds=ret[22].microsecond) == tdelta
        assert ret[23] is None
        assert ret[24] == ""
        assert ret[25] == ",an\\\\escaped\"line\n"


def test_pendulum_binding(request, conn_cnx):
    pendulum_test = pendulum.now()
    table_name = random_string(3, prefix="test_pendulum_binding")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"create table {table_name} (c1 timestamp)")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        c = cnx.cursor()
        fmt = f"insert into {table_name}(c1) values(%(v1)s)"
        c.execute(fmt, {'v1': pendulum_test})
    with conn_cnx(paramstyle='qmark') as cnx:
        cnx.cursor().execute(f"""
        insert into {table_name} values(?)
        """, (pendulum_test,))
        ret = cnx.cursor().execute(f"select * from {table_name}").fetchall()
        assert len(ret) == 2
        for r in ret:
            assert convert_datetime_to_epoch(r[0]) == convert_datetime_to_epoch(pendulum_test)


def test_binding_with_numeric(request, conn_cnx):
    """Paramstyle numeric tests. Both qmark and numeric leverages server side bindings."""
    table_name = random_string(3, prefix="test_binding_with_numeric")
    with conn_cnx(paramstyle='numeric') as cnx:
        cnx.cursor().execute(f"create table {table_name} (c1 integer, c2 string)")
        request.addfinalizer(drop_table(conn_cnx, table_name))

    with conn_cnx(paramstyle='numeric') as cnx:
        cnx.cursor().execute(f"""
insert into {table_name}(c1, c2) values(:2, :1)
        """, (
            'str1',
            123
        ))
        cnx.cursor().execute(f"""
insert into {table_name}(c1, c2) values(:2, :1)
        """, (
            'str2',
            456
        ))
        # numeric and qmark can be used in the same session
        rec = cnx.cursor().execute(f"""
select * from {table_name} where c1=?
""", (123,)).fetchall()
        assert len(rec) == 1
        assert rec[0][0] == 123
        assert rec[0][1] == 'str1'


def test_binding_timestamps(conn_cnx, request):
    """Binding datetime object with TIMESTAMP_LTZ.

    The value is bound as TIMESTAMP_NTZ, but since it is converted to UTC in the backend,
    the returned value must be ???.
    """
    table_name = random_string(3, prefix="test_binding_timestamps")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"""
create table {table_name} (
    c1 integer,
    c2 timestamp_ltz)
""")
        request.addfinalizer(drop_table(conn_cnx, table_name))

    with conn_cnx(paramstyle='numeric', timezone=PST_TZ) as cnx:
        current_localtime = datetime.now()
        cnx.cursor().execute(f"""
insert into {table_name}(c1, c2) values(:1, :2)
        """, (
            123,
            ("TIMESTAMP_LTZ", current_localtime)
        ))
        rec = cnx.cursor().execute(f"""
select * from {table_name} where c1=?
        """, (123,)).fetchall()
        assert len(rec) == 1
        assert rec[0][0] == 123
        assert convert_datetime_to_epoch(rec[0][1]) == \
               convert_datetime_to_epoch(current_localtime)


@pytest.mark.parametrize("num_rows", [pytest.param(100000, marks=pytest.mark.skipolddriver), 4])
def test_binding_bulk_insert(conn_cnx, num_rows, request):
    """Bulk insert test."""
    table_name = random_string(3, prefix="test_binding_bulk_insert")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"""
create table {table_name} (
    c1 integer,
    c2 string
)
""")
        request.addfinalizer(drop_table(conn_cnx, table_name))

    with conn_cnx(paramstyle='qmark') as cnx:
        c = cnx.cursor()
        fmt = f'insert into {table_name}(c1,c2) values(?,?)'
        c.executemany(fmt, [
            (idx, 'test{}'.format(idx)) for idx in range(num_rows)
        ])
        assert c.rowcount == num_rows


@pytest.mark.skipolddriver
def test_bulk_insert_binding_fallback(conn_cnx):
    """When stage creation fails, bulk inserts falls back to server side binding and disables stage optimization."""
    with conn_cnx(paramstyle='qmark') as cnx, cnx.cursor() as csr:
        query = f"insert into test_bulk_insert_binding_fallback{random_string(3)}(c1,c2) values(?,?)"
        cnx._session_parameters[CLIENT_STAGE_ARRAY_BINDING_THRESHOLD] = 1
        with patch.object(csr, '_execute_helper') as mocked_execute_helper, \
                patch('snowflake.connector.cursor.BindUploadAgent._create_stage') as mocked_stage_creation:
            mocked_stage_creation.side_effect = ForbiddenError
            csr.executemany(query, [
                (idx, 'test{}'.format(idx)) for idx in range(4)
            ])
        mocked_stage_creation.assert_called_once()
        mocked_execute_helper.assert_called_once()
        assert 'binding_stage' not in mocked_execute_helper.call_args[1], 'Stage binding should fail'
        assert 'binding_params' in mocked_execute_helper.call_args[1], 'Should fall back to server side binding'
        assert cnx._session_parameters[CLIENT_STAGE_ARRAY_BINDING_THRESHOLD] == 0


def test_binding_bulk_update(request, conn_cnx):
    """Bulk update test.

    Notes:
        UPDATE,MERGE and DELETE are not supported for actual bulk operation
        but executemany accepts the multiple rows and iterate DMLs.
    """
    table_name = random_string(3, prefix="test_binding_bulk_update")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"""
create table {table_name} (
    c1 integer,
    c2 string
)
""")
        request.addfinalizer(drop_table(conn_cnx, table_name))

    with conn_cnx(paramstyle='qmark') as cnx:
        # short list
        c = cnx.cursor()
        fmt = f'insert into {table_name}(c1,c2) values(?,?)'
        c.executemany(fmt, [
            (1, 'test1'),
            (2, 'test2'),
            (3, 'test3'),
            (4, 'test4'),
        ])
        assert c.rowcount == 4

        fmt = f"update {table_name} set c2=:2 where c1=:1"
        c.executemany(fmt, [
            (1, 'test5'),
            (2, 'test6'),
        ])
        assert c.rowcount == 2

        fmt = f"select * from {table_name} where c1=?"
        rec = cnx.cursor().execute(fmt, (1,)).fetchall()
        assert rec[0][0] == 1
        assert rec[0][1] == 'test5'


def test_binding_identifier(conn_cnx):
    """Binding a table name."""
    table_name = random_string(3, prefix="test_binding_identifier")
    try:
        with conn_cnx(paramstyle='qmark') as cnx:
            data = 'test'
            cnx.cursor().execute("""
create table identifier(?) (c1 string)
""", (table_name,))
        with conn_cnx(paramstyle='qmark') as cnx:
            cnx.cursor().execute("""
insert into identifier(?) values(?)
""", (table_name, data))
            ret = cnx.cursor().execute("""
select * from identifier(?)
""", (table_name,)).fetchall()
            assert len(ret) == 1
            assert ret[0][0] == data
    finally:
        with conn_cnx(paramstyle='qmark') as cnx:
            cnx.cursor().execute("""
drop table if exists identifier(?)
""", (table_name,))


def test_default_paramstyle(request, conn_cnx):
    """Tests that qmark and numeric are not supported by default."""
    table_name = random_string(4, prefix="test_default_paramstyle")

    with conn_cnx() as cnx:
        cnx.cursor().execute(f"CREATE TABLE {table_name} (aa STRING, bb STRING)")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        # qmark
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(f"INSERT INTO {table_name} VALUES(?,?)")
        # numeric
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(f"INSERT INTO {table_name} VALUES(:1,:2)")
