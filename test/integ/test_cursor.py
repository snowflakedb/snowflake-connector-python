#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import decimal
import json
import logging
import os
import time
from datetime import datetime

import mock
import pytest
import pytz

import snowflake.connector
from snowflake.connector import (
    DatabaseError,
    InterfaceError,
    NotSupportedError,
    ProgrammingError,
    constants,
    errorcode,
    errors,
)
from snowflake.connector.compat import BASE_EXCEPTION_CLASS, IS_WINDOWS
from snowflake.connector.errorcode import ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT, ER_INVALID_VALUE, ER_NOT_POSITIVE_SIZE
from snowflake.connector.sqlstate import SQLSTATE_FEATURE_NOT_SUPPORTED

from ..integ_helpers import drop_table
from ..randomize import random_string

try:
    from snowflake.connector.constants import PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT
    from snowflake.connector.errorcode import ER_NO_ARROW_RESULT, ER_NO_PYARROW, ER_NO_PYARROW_SNOWSQL
except ImportError:
    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT = None
    ER_NO_ARROW_RESULT = None
    ER_NO_PYARROW = None
    ER_NO_PYARROW_SNOWSQL = None


@pytest.fixture()
def created_table(request, conn_cnx):
    table_name = random_string(5, prefix=request.node.originalname)
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"""
create table {table_name} (
aa int,
dt date,
tm time,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(5,2),
b binary)
""")
    request.addfinalizer(drop_table(conn_cnx, table_name))
    return table_name


def _check_results(cursor, results):
    assert cursor.sfqid, 'Snowflake query id is None'
    assert cursor.rowcount == 3, 'the number of records'
    assert results[0] == 65432, 'the first result was wrong'
    assert results[1] == 98765, 'the second result was wrong'
    assert results[2] == 123456, 'the third result was wrong'


def test_insert_select(conn_cnx, created_table):
    """Inserts and selects integer data."""
    table_name = created_table

    with conn_cnx() as cnx, cnx.cursor() as c:
        c.execute(
            f"insert into {table_name}(aa) values(123456),"
            "(98765),(65432)")
        cnt = 0
        for rec in c:
            cnt += int(rec[0])
        assert cnt == 3, 'wrong number of records were inserted'
        assert c.rowcount == 3, 'wrong number of records were inserted'

        with cnx.cursor() as c:
            c.execute(f"select aa from {table_name} order by aa")
            results = [rec[0] for rec in c]
            _check_results(c, results)

        with cnx.cursor(snowflake.connector.DictCursor) as c:
            c.execute(f"select aa from {table_name} order by aa")
            results = [rec['AA'] for rec in c]
            _check_results(c, results)


def test_insert_and_select_by_separate_connection(
        conn_cnx, created_table):
    """Inserts a record and select it by a separate connection."""
    table_name = created_table
    with conn_cnx() as cnx:
        result = cnx.cursor().execute(
            f"insert into {table_name}(aa) values({1234})")
        cnt = 0
        for rec in result:
            cnt += int(rec[0])
        assert cnt == 1, 'wrong number of records were inserted'
        assert result.rowcount == 1, 'wrong number of records were inserted'

    with conn_cnx(timezone='UTC') as cnx, cnx.cursor() as c:
        c.execute(f"select aa from {table_name}")
        results = [rec[0] for rec in c]
        assert results[0] == 1234, 'the first result was wrong'
        assert result.rowcount == 1, 'wrong number of records were selected'


def _total_milliseconds_from_timedelta(td):
    """Returns the total number of milliseconds contained in the duration object."""
    return (td.microseconds + (
            td.seconds + td.days * 24 * 3600) * 10 ** 6) // 10 ** 3


def _total_seconds_from_timedelta(td):
    """Returns the total number of seconds contained in the duration object."""
    return _total_milliseconds_from_timedelta(td) // 10 ** 3


def test_insert_timestamp_select(conn_cnx, created_table):
    """Inserts and gets timestamp, timestamp with tz, date, and time."""
    table_name = created_table
    PST_TZ = "America/Los_Angeles"
    JST_TZ = "Asia/Tokyo"
    current_timestamp = datetime.utcnow()
    current_timestamp = current_timestamp.replace(tzinfo=pytz.timezone(PST_TZ))
    current_date = current_timestamp.date()
    current_time = current_timestamp.time()
    other_timestamp = current_timestamp.replace(tzinfo=pytz.timezone(JST_TZ))

    with conn_cnx() as cnx:
        cnx.cursor().execute("alter session set TIMEZONE=%s", (PST_TZ,))
        with cnx.cursor() as c:
            fmt = (f"insert into {table_name}(aa, tsltz, tstz, tsntz, dt, tm) "
                   "values(%(value)s,%(tsltz)s, %(tstz)s, %(tsntz)s, "
                   "%(dt)s, %(tm)s)")
            c.execute(fmt, {
                'value': 1234,
                'tsltz': current_timestamp,
                'tstz': other_timestamp,
                'tsntz': current_timestamp,
                'dt': current_date,
                'tm': current_time
            })
            cnt = 0
            for rec in c:
                cnt += int(rec[0])
            assert cnt == 1, 'wrong number of records were inserted'
            assert c.rowcount == 1, 'wrong number of records were selected'

    with conn_cnx(timezone='UTC') as cnx2, cnx2.cursor() as c:
        c.execute(f"select aa, tsltz, tstz, tsntz, dt, tm from {table_name}")

        result_numeric_value = []
        result_timestamp_value = []
        result_other_timestamp_value = []
        result_ntz_timestamp_value = []
        result_date_value = []
        result_time_value = []

        for (aa, ts, tstz, tsntz, dt, tm) in c:
            result_numeric_value.append(aa)
            result_timestamp_value.append(ts)
            result_other_timestamp_value.append(tstz)
            result_ntz_timestamp_value.append(tsntz)
            result_date_value.append(dt)
            result_time_value.append(tm)
        assert result_numeric_value[0] == 1234, \
            'the integer result was wrong'

        td_diff = _total_milliseconds_from_timedelta(
            current_timestamp - result_timestamp_value[0])
        assert td_diff == 0, 'the timestamp result was wrong'

        td_diff = _total_milliseconds_from_timedelta(
            other_timestamp - result_other_timestamp_value[0])
        assert td_diff == 0, 'the other timestamp result was wrong'

        td_diff = _total_milliseconds_from_timedelta(
            current_timestamp.replace(tzinfo=None) -
            result_ntz_timestamp_value[0])
        assert td_diff == 0, 'the other timestamp result was wrong'

        assert current_date == result_date_value[0], \
            'the date result was wrong'

        assert current_time == result_time_value[0], \
            'the time result was wrong'

        desc = c.description
        assert len(desc) == 6, 'invalid number of column meta data'
        assert desc[0][0].upper() == 'AA', 'invalid column name'
        assert desc[1][0].upper() == 'TSLTZ', 'invalid column name'
        assert desc[2][0].upper() == 'TSTZ', 'invalid column name'
        assert desc[3][0].upper() == 'TSNTZ', 'invalid column name'
        assert desc[4][0].upper() == 'DT', 'invalid column name'
        assert desc[5][0].upper() == 'TM', 'invalid column name'
        assert constants.FIELD_ID_TO_NAME[desc[0][1]] == 'FIXED', \
            'invalid column name: {}'.format(
                constants.FIELD_ID_TO_NAME[desc[0][1]])
        assert constants.FIELD_ID_TO_NAME[desc[1][1]] == 'TIMESTAMP_LTZ', \
            'invalid column name'
        assert constants.FIELD_ID_TO_NAME[desc[2][1]] == 'TIMESTAMP_TZ', \
            'invalid column name'
        assert constants.FIELD_ID_TO_NAME[desc[3][1]] == 'TIMESTAMP_NTZ', \
            'invalid column name'
        assert constants.FIELD_ID_TO_NAME[desc[4][1]] == 'DATE', \
            'invalid column name'
        assert constants.FIELD_ID_TO_NAME[desc[5][1]] == 'TIME', \
            'invalid column name'


def test_insert_timestamp_ltz(conn_cnx, created_table):
    """Inserts and retrieve timestamp ltz."""
    tzstr = 'America/New_York'
    table_name = created_table
    with conn_cnx() as cnx:
        # sync with the session parameter
        cnx.cursor().execute(
            f"alter session set timezone='{tzstr}'")

        current_time = datetime.now()
        current_time = current_time.replace(tzinfo=pytz.timezone(tzstr))

        with cnx.cursor() as c:
            fmt = f"insert into {table_name}(aa, tsltz) values(%(value)s,%(ts)s)"
            c.execute(fmt, {
                'value': 8765,
                'ts': current_time,
            })
            cnt = 0
            for rec in c:
                cnt += int(rec[0])
            assert cnt == 1, 'wrong number of records were inserted'

        with cnx.cursor() as c:
            c.execute(f"select aa,tsltz from {table_name}")
            result_numeric_value = []
            result_timestamp_value = []
            for (aa, ts) in c:
                result_numeric_value.append(aa)
                result_timestamp_value.append(ts)

            td_diff = _total_milliseconds_from_timedelta(
                current_time - result_timestamp_value[0])

            assert td_diff == 0, 'the first result was wrong'


@mock.patch.dict(os.environ, {"TZ": "'America/New_York'"})
def test_struct_time(conn_cnx, created_table):
    """Binds struct_time object for updating timestamp."""
    table_name = created_table

    if not IS_WINDOWS:
        time.tzset()
    test_time = time.strptime("30 Sep 01 11:20:30", "%d %b %y %H:%M:%S")

    with conn_cnx() as cnx, cnx.cursor() as c:
        fmt = f"insert into {table_name}(aa, tsltz) values(%(value)s,%(ts)s)"
        c.execute(fmt, {
            'value': 87654,
            'ts': test_time,
        })
        cnt = 0
        for rec in c:
            cnt += int(rec[0])

        if not IS_WINDOWS:
            time.tzset()
        assert cnt == 1, 'wrong number of records were inserted'

        result = cnx.cursor().execute(
            f"select aa, tsltz from {table_name}")
        for (_, _tsltz) in result:
            pass

        _tsltz -= _tsltz.tzinfo.utcoffset(_tsltz)

        assert test_time.tm_year == _tsltz.year, "Year didn't match"
        assert test_time.tm_mon == _tsltz.month, "Month didn't match"
        assert test_time.tm_mday == _tsltz.day, "Day didn't match"
        assert test_time.tm_hour == _tsltz.hour, "Hour didn't match"
        assert test_time.tm_min == _tsltz.minute, "Minute didn't match"
        assert test_time.tm_sec == _tsltz.second, "Second didn't match"

        if not IS_WINDOWS:
            time.tzset()


@pytest.mark.parametrize("value", [b'\x00\xFF\xA1\xB2\xC3', bytearray(b'\x00\xFF\xA1\xB2\xC3')])
def test_insert_binary_select(conn_cnx, created_table, value):
    """Inserts and get a binary value."""
    table_name = created_table

    with conn_cnx() as cnx, cnx.cursor() as c:
        fmt = f"insert into {table_name}(b) values(%(b)s)"
        c.execute(fmt, {'b': value})
        count = sum(int(rec[0]) for rec in c)
        assert count == 1, 'wrong number of records were inserted'
        assert c.rowcount == 1, 'wrong number of records were selected'

    with conn_cnx() as cnx2, cnx2.cursor() as c:
        c.execute(f"select b from {table_name}")

        results = [b for (b,) in c]
        assert value == results[0], 'the binary result was wrong'

        desc = c.description
        assert len(desc) == 1, 'invalid number of column meta data'
        assert desc[0][0].upper() == 'B', 'invalid column name'
        assert constants.FIELD_ID_TO_NAME[desc[0][1]] == 'BINARY', \
            'invalid column name'


def test_variant(conn_cnx, request):
    """Variant including JSON object."""
    table_name = random_string(3, prefix="test_variant_")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"""
create table {table_name} (
created_at timestamp, data variant)
""")
        request.addfinalizer(drop_table(conn_cnx, table_name))

    with conn_cnx() as cnx, cnx.cursor() as c:
        current_time = datetime.now()
        fmt = (f"insert into {table_name}(created_at, data) "
               "select column1, parse_json(column2) "
               "from values(%(created_at)s, %(data)s)")
        c.execute(fmt, {
            'created_at': current_time,
            'data': ('{"SESSION-PARAMETERS":{'
                     '"TIMEZONE":"UTC", "SPECIAL_FLAG":true}}')
        })
        cnt = 0
        for rec in c:
            cnt += int(rec[0])
        assert cnt == 1, 'wrong number of records were inserted'
        assert c.rowcount == 1, \
            'wrong number of records were inserted'

        result = cnx.cursor().execute(
            f"select created_at, data from {table_name}")
        _, data = result.fetchone()
        data = json.loads(data)
        assert data['SESSION-PARAMETERS']['SPECIAL_FLAG'], \
            ("JSON data should be parsed properly. "
             "Invalid JSON data")


def test_callproc(conn_cnx):
    """Callproc test.

    Notes:
        It's a nop as of now.
    """
    with conn_cnx() as cnx:
        with pytest.raises(errors.NotSupportedError):
            cnx.cursor().callproc("whatever the stored procedure")


def test_invalid_bind_data_type(conn_cnx):
    """Invalid bind data type."""
    with conn_cnx() as cnx:
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(
                "select 1 from dual where 1=%s", ([1, 2, 3],))


def test_timeout_query(conn_cnx):
    with conn_cnx() as cnx:
        cnx.cursor().execute("select 1")
        c = cnx.cursor()
        try:
            c.execute(
                'select seq8() as c1 '
                'from table(generator(timeLimit => 60))',
                timeout=5)
            raise Exception("Must be canceled")
        except BASE_EXCEPTION_CLASS as err:
            assert isinstance(err, errors.ProgrammingError), \
                "Programming Error Exception"
            assert err.errno == 604, "Invalid error code"
        finally:
            c.close()


def test_executemany(conn_cnx, created_table):
    """Executes many statements. Client binding is supported by either dict, or list data types.

    Notes:
        The binding data type is dict and tuple, respectively.
    """
    table_name = created_table
    with conn_cnx() as cnx, cnx.cursor() as c:
        fmt = f'insert into {table_name}(aa) values(%(value)s)'
        c.executemany(fmt, [
            {'value': '1234'},
            {'value': '234'},
            {'value': '34'},
            {'value': '4'},
        ])
        cnt = 0
        for rec in c:
            cnt += int(rec[0])
        assert cnt == 4, 'number of records'
        assert c.rowcount == 4, 'wrong number of records were inserted'

        fmt = f'insert into {table_name}(aa) values(%s)'
        c.executemany(fmt, [
            (12345,),
            (1234,),
            (234,),
            (34,),
            (4,),
        ])
        rec = c.fetchone()
        assert rec[0] == 5, 'number of records'
        assert c.rowcount == 5, 'wrong number of records were inserted'


def test_closed_cursor(conn_cnx):
    """Attempts to use the closed cursor. It should raise errors.

    Notes:
        The binding data type is scalar.
    """
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        cur.execute("select 1")
        cur.close()
        with pytest.raises(snowflake.connector.Error, match=r"Cursor is closed in execute") as err:
            cur.execute("select 2")
            assert err.errno == errorcode.ER_CURSOR_IS_CLOSED


def test_fetchmany(conn_cnx, created_table):
    table_name = created_table
    with conn_cnx() as cnx, cnx.cursor() as c:
        fmt = f'insert into {table_name}(aa) values(%(value)s)'
        c.executemany(fmt, [
            {'value': '3456789'},
            {'value': '234567'},
            {'value': '1234'},
            {'value': '234'},
            {'value': '34'},
            {'value': '4'},
        ])
        cnt = 0
        for rec in c:
            cnt += int(rec[0])
        assert cnt == 6, 'number of records'
        assert c.rowcount == 6, 'number of records'

        c.execute(f'select aa from {table_name} order by aa desc')

        rows = c.fetchmany(2)
        assert len(rows) == 2, 'The number of records'
        assert rows[1][0] == 234567, 'The second record'

        rows = c.fetchmany(1)
        assert len(rows) == 1, 'The number of records'
        assert rows[0][0] == 1234, 'The first record'

        rows = c.fetchmany(5)
        assert len(rows) == 3, 'The number of records'
        assert rows[-1][0] == 4, 'The last record'

        rows = c.fetchmany(15)
        assert len(rows) == 0, 'The number of records'


def test_process_params(conn_cnx, created_table):
    """Binds variables for insert and other queries."""
    table_name = created_table
    with conn_cnx() as cnx, cnx.cursor() as c:
        fmt = f'insert into {table_name}(aa) values(%(value)s)'
        c.executemany(fmt, [
            {'value': '3456789'},
            {'value': '234567'},
            {'value': '1234'},
            {'value': '234'},
            {'value': '34'},
            {'value': '4'},
        ])
        cnt = 0
        for rec in c:
            cnt += int(rec[0])
        assert cnt == 6, 'number of records'

        fmt = f'select count(aa) from {table_name} where aa > %(value)s'

        c.execute(fmt, {'value': 1233})
        for (_cnt,) in c:
            pass
        assert _cnt == 3, 'the number of records'

        fmt = f'select count(aa) from {table_name} where aa > %s'
        c = cnx.cursor()
        c.execute(fmt, (1234,))
        for (_cnt,) in c:
            pass
        assert _cnt == 2, 'the number of records'


def test_real_decimal(conn_cnx, created_table):
    table_name = created_table
    with conn_cnx() as cnx, cnx.cursor() as c:
        fmt = f'insert into {table_name}(aa, pct, ratio) values(%s,%s,%s)'
        c.execute(fmt, (9876, 12.3, decimal.Decimal('23.4')))
        for (_cnt,) in c:
            pass
        assert _cnt == 1, 'the number of records'

        c.execute(f'select aa, pct, ratio from {table_name}')
        for (_aa, _pct, _ratio) in c:
            pass
        assert _aa == 9876, 'the integer value'
        assert _pct == 12.3, 'the float value'
        assert _ratio == decimal.Decimal('23.4'), 'the decimal value'

        with cnx.cursor(snowflake.connector.DictCursor) as c:
            c.execute(f'select aa, pct, ratio from {table_name}')
            rec = c.fetchone()
            assert rec['AA'] == 9876, 'the integer value'
            assert rec['PCT'] == 12.3, 'the float value'
            assert rec['RATIO'] == decimal.Decimal('23.4'), 'the decimal value'


def test_none_errorhandler(conn_cnx):
    with conn_cnx() as cnx, cnx.cursor() as c:
        with pytest.raises(errors.ProgrammingError):
            c.errorhandler = None


def test_nope_errorhandler(conn_cnx):
    def user_errorhandler(connection, cursor, errorclass, errorvalue):
        pass

    with conn_cnx() as cnx, cnx.cursor() as c:
        c.errorhandler = user_errorhandler
        c.execute("select * foooooo never_exists_table")
        c.execute("select * barrrrr never_exists_table")
        c.execute("select * daaaaaa never_exists_table")
        assert c.messages[0][0] == errors.ProgrammingError, \
            'One error was recorded'
        assert len(c.messages) == 1, 'should be one error'


@pytest.mark.internal
def test_binding_negative(negative_conn_cnx):
    table_name = "non_existent_table"
    with negative_conn_cnx() as cnx:
        with pytest.raises(TypeError):
            cnx.cursor().execute(
                f"INSERT INTO {table_name}(aa) VALUES(%s)", (1, 2, 3))
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(
                f"INSERT INTO {table_name}(aa) VALUES(%s)", ())
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(
                f"INSERT INTO {table_name}(aa) VALUES(%s)", (['a'],))


def test_execute_after_close(conn_testaccount):
    """SNOW-13588: Raises an error if executing after the connection is closed."""
    cursor = conn_testaccount.cursor()
    conn_testaccount.close()
    with pytest.raises(DatabaseError):
        cursor.execute('show tables')


def test_multi_table_insert(conn_cnx, created_table, request):
    table_name = created_table
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        cur.execute(f"""
INSERT INTO {table_name}(aa) VALUES(1234),(9876),(2345)
""")
        assert cur.rowcount == 3, 'the number of records'

        cur.execute(f"""
CREATE TABLE {table_name}_foo (aa_foo int)
    """)
        request.addfinalizer(drop_table(conn_cnx, f"{table_name}_foo"))
        cur.execute(f"""
CREATE TABLE {table_name}_bar (aa_bar int)
    """)
        request.addfinalizer(drop_table(conn_cnx, f"{table_name}_bar"))
        cur.execute(f"""
INSERT ALL
    INTO {table_name}_foo(aa_foo) VALUES(aa)
    INTO {table_name}_bar(aa_bar) VALUES(aa)
    SELECT aa FROM {table_name}
    """)
        assert cur.rowcount == 6


def test_fetch_before_execute(conn_cnx):
    """SNOW-13574: Fetch before execute."""
    with conn_cnx() as cnx:
        with pytest.raises(Exception):
            cnx.cursor().fetchone()


def test_close_twice(conn_testaccount):
    conn_testaccount.close()
    conn_testaccount.close()


def test_fetch_out_of_range_timestamp_value(conn_cnx):
    for result_format in ['arrow', 'json']:
        with conn_cnx() as cnx:
            cur = cnx.cursor()
            cur.execute(f"alter session set python_connector_query_result_format='{result_format}'")
            cur.execute("select '12345-01-02'::timestamp_ntz")
            with pytest.raises(errors.InterfaceError):
                cur.fetchone()


def test_empty_execution(conn_cnx):
    """Checks whether executing an empty string behaves as expected."""
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            cur.execute('')
            assert cur._result is None
            with pytest.raises(Exception):
                cur.fetchall()


def test_rownumber(conn_cnx):
    """Checks whether rownumber is returned as expected."""
    with conn_cnx() as cnx, cnx.cursor() as cur:
        assert cur.execute('select * from values (1), (2)').fetchone() == (1,)
        assert cur.rownumber == 0
        assert cur.fetchone() == (2,)
        assert cur.rownumber == 1


def test_values_set(conn_cnx):
    """Checks whether a bunch of properties start as Nones, but get set to something else when a query was executed."""
    properties = [
        'timestamp_output_format',
        'timestamp_ltz_output_format',
        'timestamp_tz_output_format',
        'timestamp_ntz_output_format',
        'date_output_format',
        'timezone',
        'time_output_format',
        'binary_output_format',
    ]
    with conn_cnx() as cnx, cnx.cursor() as cur:
        for property in properties:
            assert getattr(cur, property) is None
        assert cur.execute('select 1').fetchone() == (1,)
        # The default values might change in future, so let's just check that they aren't None anymore
        for property in properties:
            assert getattr(cur, property) is not None


def test_execute_helper_params_error(conn_cnx):
    """Tests whether calling _execute_helper with a non-dict statement params is handled correctly."""
    with conn_cnx() as cnx, cnx.cursor() as cur:
        with pytest.raises(ProgrammingError,
                           match=r'The data type of statement params is invalid. It must be dict.$'):
            cur._execute_helper('select %()s', statement_params='1')


def test_desc_rewrite(conn_cnx, caplog, request):
    """Tests whether describe queries are rewritten as expected and this action is logged."""
    with conn_cnx() as cnx, cnx.cursor() as cur:
        table_name = random_string(5, 'test_desc_rewrite_')
        cur.execute(f'create table {table_name} (a int)')
        request.addfinalizer(drop_table(conn_cnx, table_name))
        with caplog.at_level(logging.DEBUG, 'snowflake.connector'):
            cur.execute('desc {}'.format(table_name))
            assert ('snowflake.connector.cursor', 20,
                    'query was rewritten: org=desc {table_name}, new=describe table {table_name}'.format(
                        table_name=table_name
                    )) in caplog.record_tuples


@pytest.mark.skipolddriver
@pytest.mark.parametrize('result_format', [False, None, 'json'])
def test_execute_helper_cannot_use_arrow(conn_cnx, caplog, result_format):
    """Tests whether cannot use arrow is handled correctly inside of _execute_helper."""
    with conn_cnx() as cnx, cnx.cursor() as cur:
        with mock.patch('snowflake.connector.cursor.CAN_USE_ARROW_RESULT', False):
            if result_format is False:
                result_format = None
            else:
                result_format = {
                    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: result_format
                }
            with caplog.at_level(logging.DEBUG, 'snowflake.connector'):
                cur.execute("select 1", _statement_params=result_format)
                assert ('snowflake.connector.cursor',
                        logging.DEBUG,
                        "Cannot use arrow result format, fallback to json format") in caplog.record_tuples
                assert cur.fetchone() == (1,)


@pytest.mark.skipolddriver
def test_execute_helper_cannot_use_arrow_exception(conn_cnx):
    """Like test_execute_helper_cannot_use_arrow but when we are trying to force arrow an Exception should be raised."""
    with conn_cnx() as cnx, cnx.cursor() as cur:
        with mock.patch('snowflake.connector.cursor.CAN_USE_ARROW_RESULT', False):
            with pytest.raises(ProgrammingError,
                               match="The result set in Apache Arrow format is not supported for the platform."):
                cur.execute("select 1", _statement_params={
                    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: 'arrow'
                })


@pytest.mark.skipolddriver
def test_check_can_use_arrow_resultset(conn_cnx, caplog):
    """Tests check_can_use_arrow_resultset has no effect when we can use arrow."""
    with conn_cnx() as cnx, cnx.cursor() as cur:
        with mock.patch('snowflake.connector.cursor.CAN_USE_ARROW_RESULT', True), \
                caplog.at_level(logging.DEBUG, 'snowflake.connector'):
            cur.check_can_use_arrow_resultset()
            assert 'Arrow' not in caplog.text


@pytest.mark.skipolddriver
@pytest.mark.parametrize('snowsql', [True, False])
def test_check_cannot_use_arrow_resultset(conn_cnx, caplog, snowsql):
    """Tests check_can_use_arrow_resultset expected outcomes."""
    config = {}
    if snowsql:
        config['application'] = 'SnowSQL'
    with conn_cnx(**config) as cnx:
        with cnx.cursor() as cur:
            with mock.patch('snowflake.connector.cursor.CAN_USE_ARROW_RESULT', False):
                with pytest.raises(
                        ProgrammingError,
                        match="Currently SnowSQL doesn't support the result set in Apache Arrow format." if snowsql else
                        "The result set in Apache Arrow format is not supported for the platform.") as pe:
                    cur.check_can_use_arrow_resultset()
                    assert pe.errno == (ER_NO_PYARROW_SNOWSQL if snowsql else ER_NO_ARROW_RESULT)


@pytest.mark.skipolddriver
def test_check_can_use_pandas(conn_cnx):
    """Tests check_can_use_arrow_resultset has no effect when we can import pandas."""
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            with mock.patch('snowflake.connector.cursor.pyarrow', 'Something other than None'):
                cur.check_can_use_pandas()


@pytest.mark.skipolddriver
def test_check_cannot_use_pandas(conn_cnx):
    """Tests check_can_use_arrow_resultset has expected outcomes."""
    with conn_cnx() as cnx, cnx.cursor() as cur:
        with mock.patch('snowflake.connector.cursor.pyarrow', None):
            with pytest.raises(ProgrammingError,
                               match=r"Optional dependency: 'pyarrow' is not installed, please see the "
                                     "following link for install instructions: https:.*") as pe:
                cur.check_can_use_pandas()
                assert pe.errno == ER_NO_PYARROW


@pytest.mark.skipolddriver
def test_not_supported_pandas(conn_cnx):
    """Check that fetch_pandas functions return expected error when arrow results are not available."""
    result_format = {
        PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: 'json'
    }
    with conn_cnx() as cnx, cnx.cursor() as cur:
        cur.execute("select 1", _statement_params=result_format)
        with mock.patch('snowflake.connector.cursor.pyarrow', 'Something other than None'):
            with pytest.raises(NotSupportedError):
                cur.fetch_pandas_all()
            with pytest.raises(NotSupportedError):
                list(cur.fetch_pandas_batches())


def test_query_cancellation(conn_cnx):
    """Tests whether query_cancellation works."""
    with conn_cnx() as cnx, cnx.cursor() as cur:
        cur.execute('select max(seq8()) from table(generator(timeLimit=>30));', _no_results=True)
        sf_qid = cur.sfqid
        cur.abort_query(sf_qid)


def test_executemany_error(conn_cnx):
    """Tests calling executemany without many things."""
    with conn_cnx() as con, con.cursor() as cur:
        with pytest.raises(InterfaceError,
                           match="No parameters are specified for the command: select 1") as ie:
            cur.executemany('select 1', [])
            assert ie.errno == ER_INVALID_VALUE


def test_executemany_insert_rewrite(conn_cnx):
    """Tests calling executemany with a non rewritable pyformat insert query."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            with pytest.raises(InterfaceError,
                               match="Failed to rewrite multi-row insert") as ie:
                cur.executemany('insert into numbers (select 1)', [1, 2])
                assert ie.errno == ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT


def test_executemany_bulk_insert_size_mismatch(conn_cnx):
    """Tests bulk insert error with variable length of arguments."""
    with conn_cnx(paramstyle='qmark') as con, con.cursor() as cur:
        with pytest.raises(InterfaceError,
                           match="Bulk data size don't match. expected: 1, got: 2") as ie:
            cur.executemany('insert into numbers values (?,?)', [[1], [1, 2]])
            assert ie.errno == ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT


def test_fetchmany_size_error(conn_cnx):
    """Tests retrieving a negative number of results."""
    with conn_cnx() as con, con.cursor() as cur:
        cur.execute('select 1')
        with pytest.raises(ProgrammingError,
                           match="The number of rows is not zero or positive number: -1") as ie:
            cur.fetchmany(-1)
            assert ie.errno == ER_NOT_POSITIVE_SIZE


def test_nextset(conn_cnx, caplog):
    """Tests no op function nextset."""
    caplog.set_level(logging.DEBUG, 'snowflake.connector')
    with caplog.at_level(logging.DEBUG, 'snowflake.connector'):
        with conn_cnx() as con, con.cursor() as cur:
            assert cur.nextset() is None
        assert ('snowflake.connector.cursor', logging.DEBUG, 'nop') in caplog.record_tuples


def test_scroll(conn_cnx):
    """Tests if scroll returns a NotSupported exception."""
    with conn_cnx() as con, con.cursor() as cur:
        with pytest.raises(NotSupportedError, match='scroll is not supported.') as nse:
            cur.scroll(2)
            assert nse.errno == SQLSTATE_FEATURE_NOT_SUPPORTED


def test__log_telemetry_job_data(conn_cnx, caplog):
    """Tests whether we handle missing connection object correctly while logging a telemetry event."""
    with conn_cnx() as con, con.cursor() as cur:
        with mock.patch.object(cur, '_connection', None), \
                caplog.at_level(logging.DEBUG, 'snowflake.connector'):
            cur._log_telemetry_job_data('test', True)
            assert ('snowflake.connector.cursor',
                    logging.WARNING,
                    "Cursor failed to log to telemetry. Connection object may be None.") in caplog.record_tuples
