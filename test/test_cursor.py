#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import decimal
import json
import os
import time
from datetime import datetime

import pytest
import pytz

import snowflake.connector
from snowflake.connector import (constants, errorcode, errors)
from snowflake.connector.compat import (BASE_EXCEPTION_CLASS, PY2)


def _create_warehouse(conn, db_parameters):
    """
    Use the test warehouse, database and schema
    """

    def exe(sql):
        return conn.cursor().execute(sql)

    exe("create or replace warehouse {0} warehouse_size=small, "
        "warehouse_type=standard".format(db_parameters['name_wh']))
    exe("use warehouse {0}".format(db_parameters['name_wh']))
    exe("use {0}.{1}".format(db_parameters['database'],
                             db_parameters['schema']))


def _drop_warehouse(conn, db_parameters):
    conn.cursor().execute("drop warehouse if exists {0}".format(
        db_parameters['name_wh']
    ))


@pytest.fixture()
def conn(request, conn_cnx, db_parameters):
    def fin():
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                'use {db}.{schema}'.format(
                    db=db_parameters['database'],
                    schema=db_parameters['schema']))
            cnx.cursor().execute("drop table {name}".format(
                name=db_parameters['name']))

    request.addfinalizer(fin)

    with conn_cnx() as cnx:
        cnx.cursor().execute("""
create table {name} (
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
""".format(name=db_parameters['name']))

    return conn_cnx


def _check_results(cursor, results):
    assert cursor.sfqid, 'Snowflake query id is None'
    assert cursor.rowcount == 3, 'the number of records'
    assert results[0] == 65432, 'the first result was wrong'
    assert results[1] == 98765, 'the second result was wrong'
    assert results[2] == 123456, 'the third result was wrong'


def test_insert_select(conn, db_parameters):
    """
    Inserts and selects integer data
    """
    with conn() as cnx:
        c = cnx.cursor()
        try:
            c.execute(
                "insert into {name}(aa) values(123456),"
                "(98765),(65432)".format(name=db_parameters['name']))
            cnt = 0
            for rec in c:
                cnt += int(rec[0])
            assert cnt == 3, 'wrong number of records were inserted'
            assert c.rowcount == 3, 'wrong number of records were inserted'
        finally:
            c.close()

        try:
            c = cnx.cursor()
            c.execute("select aa from {name} order by aa".format(
                name=db_parameters['name']))
            results = []
            for rec in c:
                results.append(rec[0])
            _check_results(c, results)
        finally:
            c.close()

        with cnx.cursor(snowflake.connector.DictCursor) as c:
            c.execute("select aa from {name} order by aa".format(
                name=db_parameters['name']))
            results = []
            for rec in c:
                results.append(rec['AA'])
            _check_results(c, results)


def test_insert_and_select_by_separate_connection(
        conn, db_parameters):
    """
    Insert a record and select it by a separate connection.
    """
    with conn() as cnx:
        result = cnx.cursor().execute(
            "insert into {name}(aa) values({value})".format(
                name=db_parameters['name'], value='1234'))
        cnt = 0
        for rec in result:
            cnt += int(rec[0])
        assert cnt == 1, 'wrong number of records were inserted'
        assert result.rowcount == 1, 'wrong number of records were inserted'

    cnx2 = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        database=db_parameters['database'],
        schema=db_parameters['schema'],
        timezone='UTC',
        protocol='http',
    )
    _create_warehouse(cnx2, db_parameters)
    try:
        c = cnx2.cursor()
        c.execute("select aa from {name}".format(name=db_parameters['name']))
        results = []
        for rec in c:
            results.append(rec[0])
        c.close()
        assert results[0] == 1234, 'the first result was wrong'
        assert result.rowcount == 1, 'wrong number of records were selected'
    finally:
        _drop_warehouse(cnx2, db_parameters)
        cnx2.close()


def _total_milliseconds_from_timedelta(td):
    """
    Returns the total number of milliseconds contained in the duration object.
    """
    return (td.microseconds + (
        td.seconds + td.days * 24 * 3600) * 10 ** 6) // 10 ** 3


def _total_seconds_from_timedelta(td):
    """
    Returns the total number of seconds contained in the duration object.
    """
    return _total_milliseconds_from_timedelta(td) // 10 ** 3


def test_insert_timestamp_select(conn, db_parameters):
    """
    Insert and get timestamp, timestamp with tz, date, and time.

    Currently the session parameter TIMEZONE is ignored
    """
    PST_TZ = "America/Los_Angeles"
    JST_TZ = "Asia/Tokyo"
    current_timestamp = datetime.utcnow()
    current_timestamp = current_timestamp.replace(tzinfo=pytz.timezone(PST_TZ))
    current_date = current_timestamp.date()
    current_time = current_timestamp.time()

    other_timestamp = current_timestamp.replace(tzinfo=pytz.timezone(JST_TZ))

    with conn() as cnx:
        cnx.cursor().execute("alter session set TIMEZONE=%s", (PST_TZ,))
        c = cnx.cursor()
        try:
            fmt = ("insert into {name}(aa, ts, tstz, tsntz, dt, tm) "
                   "values(%(value)s,%(ts)s, %(tstz)s, %(tsntz)s, "
                   "%(dt)s, %(tm)s)")
            c.execute(fmt.format(name=db_parameters['name']), {
                'value': 1234,
                'ts': current_timestamp,
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
        finally:
            c.close()

    cnx2 = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        database=db_parameters['database'],
        schema=db_parameters['schema'],
        timezone='UTC',
        protocol='http'
    )
    _create_warehouse(cnx2, db_parameters)
    try:
        c = cnx2.cursor()
        c.execute("select aa, ts, tstz, tsntz, dt, tm from {name}".format(
            name=db_parameters['name']))

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
        c.close()
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
        assert desc[1][0].upper() == 'TS', 'invalid column name'
        assert desc[2][0].upper() == 'TSTZ', 'invalid column name'
        assert desc[3][0].upper() == 'TSNTZ', 'invalid column name'
        assert desc[4][0].upper() == 'DT', 'invalid column name'
        assert desc[5][0].upper() == 'TM', 'invalid column name'
        assert constants.FIELD_ID_TO_NAME[desc[0][1]] == 'FIXED', \
            'invalid column name: {0}'.format(
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
    finally:
        _drop_warehouse(cnx2, db_parameters)
        cnx2.close()


def test_insert_timestamp_ltz(conn, db_parameters):
    """
    Inserts and retrieve timestamp ltz
    """
    tzstr = 'America/New_York'
    # sync with the session parameter
    with conn() as cnx:
        cnx.cursor().execute(
            "alter session set timezone='{tzstr}'".format(tzstr=tzstr))

        current_time = datetime.now()
        current_time = current_time.replace(tzinfo=pytz.timezone(tzstr))

        c = cnx.cursor()
        try:
            fmt = "insert into {name}(aa, tsltz) values(%(value)s,%(ts)s)"
            c.execute(fmt.format(name=db_parameters['name']), {
                'value': 8765,
                'ts': current_time,
            })
            cnt = 0
            for rec in c:
                cnt += int(rec[0])
            assert cnt == 1, 'wrong number of records were inserted'
        finally:
            c.close()

        try:
            c = cnx.cursor()
            c.execute("select aa,tsltz from {name}".format(
                name=db_parameters['name']))
            result_numeric_value = []
            result_timestamp_value = []
            for (aa, ts) in c:
                result_numeric_value.append(aa)
                result_timestamp_value.append(ts)

            td_diff = _total_milliseconds_from_timedelta(
                current_time - result_timestamp_value[0])

            assert td_diff == 0, 'the first result was wrong'
        finally:
            c.close()


def test_struct_time(conn, db_parameters):
    """
    Binds struct_time object for updating timestamp
    """
    tzstr = 'America/New_York'
    os.environ['TZ'] = tzstr
    time.tzset()
    test_time = time.strptime("30 Sep 01 11:20:30", "%d %b %y %H:%M:%S")

    with conn() as cnx:
        c = cnx.cursor()
        try:
            fmt = "insert into {name}(aa, tsltz) values(%(value)s,%(ts)s)"
            c.execute(fmt.format(name=db_parameters['name']), {
                'value': 87654,
                'ts': test_time,
            })
            cnt = 0
            for rec in c:
                cnt += int(rec[0])
        finally:
            c.close()
            os.environ['TZ'] = 'UTC'
            time.tzset()
        assert cnt == 1, 'wrong number of records were inserted'

        try:
            result = cnx.cursor().execute(
                "select aa, tsltz from {name}".format(
                    name=db_parameters['name']))
            for (aa, tsltz) in result:
                pass

            tsltz -= tsltz.tzinfo.utcoffset(tsltz)

            assert test_time.tm_year == tsltz.year, "Year didn't match"
            assert test_time.tm_mon == tsltz.month, "Month didn't match"
            assert test_time.tm_mday == tsltz.day, "Day didn't match"
            assert test_time.tm_hour == tsltz.hour, "Hour didn't match"
            assert test_time.tm_min == tsltz.minute, "Minute didn't match"
            assert test_time.tm_sec == tsltz.second, "Second didn't match"
        finally:
            os.environ['TZ'] = 'UTC'
            time.tzset()


@pytest.mark.skipif(PY2, reason="""
Binary not supported in Python 2 connector.
""")
def test_insert_binary_select(conn, db_parameters):
    """
    Insert and get a binary value.
    """
    value = b'\x00\xFF\xA1\xB2\xC3'

    with conn() as cnx:
        c = cnx.cursor()
        try:
            fmt = ("insert into {name}(b) values(%(b)s)")
            c.execute(fmt.format(name=db_parameters['name']), {'b': value})
            count = sum(int(rec[0]) for rec in c)
            assert count == 1, 'wrong number of records were inserted'
            assert c.rowcount == 1, 'wrong number of records were selected'
        finally:
            c.close()

    cnx2 = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        database=db_parameters['database'],
        schema=db_parameters['schema'],
        protocol='http'
    )
    _create_warehouse(cnx2, db_parameters)
    try:
        c = cnx2.cursor()
        c.execute("select b from {name}".format(name=db_parameters['name']))

        results = [b for (b,) in c]
        assert value == results[0], 'the binary result was wrong'

        desc = c.description
        assert len(desc) == 1, 'invalid number of column meta data'
        assert desc[0][0].upper() == 'B', 'invalid column name'
        assert constants.FIELD_ID_TO_NAME[desc[0][1]] == 'BINARY', \
            'invalid column name'
    finally:
        _drop_warehouse(cnx2, db_parameters)
        cnx2.close()


def test_insert_binary_select_with_bytearray(conn, db_parameters):
    """
    Insert and get a binary value using the bytearray type.
    """
    value = bytearray(b'\x00\xFF\xA1\xB2\xC3')

    with conn() as cnx:
        c = cnx.cursor()
        try:
            fmt = ("insert into {name}(b) values(%(b)s)")
            c.execute(fmt.format(name=db_parameters['name']), {'b': value})
            count = sum(int(rec[0]) for rec in c)
            assert count == 1, 'wrong number of records were inserted'
            assert c.rowcount == 1, 'wrong number of records were selected'
        finally:
            c.close()

    cnx2 = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        database=db_parameters['database'],
        schema=db_parameters['schema'],
        protocol='http'
    )
    _create_warehouse(cnx2, db_parameters)
    try:
        c = cnx2.cursor()
        c.execute("select b from {name}".format(name=db_parameters['name']))

        results = [b for (b,) in c]
        assert bytes(value) == results[0], 'the binary result was wrong'

        desc = c.description
        assert len(desc) == 1, 'invalid number of column meta data'
        assert desc[0][0].upper() == 'B', 'invalid column name'
        assert constants.FIELD_ID_TO_NAME[desc[0][1]] == 'BINARY', \
            'invalid column name'
    finally:
        _drop_warehouse(cnx2, db_parameters)
        cnx2.close()


def test_variant(conn, db_parameters):
    """Variant including JSON object
    """

    name_variant = db_parameters['name'] + "_variant"
    with conn() as cnx:
        cnx.cursor().execute("""
create table {name} (
created_at timestamp, data variant)
""".format(name=name_variant))

    try:
        with conn() as cnx:
            current_time = datetime.now()
            c = cnx.cursor()
            try:
                fmt = ("insert into {name}(created_at, data) "
                       "select column1, parse_json(column2) "
                       "from values(%(created_at)s, %(data)s)")
                c.execute(fmt.format(name=name_variant), {
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
            finally:
                c.close()

            result = cnx.cursor().execute(
                "select created_at, data from {name}".format(
                    name=name_variant))
            _, data = result.fetchone()
            data = json.loads(data)
            assert data['SESSION-PARAMETERS']['SPECIAL_FLAG'], \
                ("JSON data should be parsed properly. "
                 "Invalid JSON data")
    finally:
        with conn() as cnx:
            cnx.cursor().execute(
                "drop table {name}".format(name=name_variant))


def test_callproc(conn_cnx):
    """Callproc. nop as of now
    """
    with conn_cnx() as cnx:
        with pytest.raises(errors.NotSupportedError):
            cnx.cursor().callproc("whatever the stored procedure")


def test_invalid_bind_data_type(conn_cnx):
    """Invalid bind data type
    """
    with conn_cnx() as cnx:
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(
                "select 1 from dual where 1=%s", ([1, 2, 3],))


def test_timeout_query(conn_cnx):
    """Timeout
    """
    with conn_cnx() as cnx:
        c = cnx.cursor()
        try:
            c.execute(
                'select seq8() as c1 '
                'from table(generator(rowCount => 100000001))',
                timeout=1)
            raise Exception("Must be canceled")
        except BASE_EXCEPTION_CLASS as err:
            assert isinstance(err, errors.ProgrammingError), \
                "Programming Error Exception"
            assert err.errno == 604, "Invalid error code"
        finally:
            c.close()
        c = cnx.cursor()
        try:
            c.execute(
                'select seq8() as c1 '
                'from table(generator(rowCount => 100000002))',
                timeout=1)
            raise Exception("Must be canceled")
        except BASE_EXCEPTION_CLASS as err:
            assert isinstance(err, errors.ProgrammingError), \
                "Programming Error Exception"
            assert err.errno == 604, "Invalid error code"
        finally:
            c.close()


def test_executemany(conn, db_parameters):
    """Executes many statements. Client binding is supported by either
    dictor list data types.

    NOTE the binding data type is dict and tuple, respectively
    """
    with conn() as cnx:
        c = cnx.cursor()
        fmt = 'insert into {name}(aa) values(%(value)s)'.format(
            name=db_parameters['name'])
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
        c.close()

        c = cnx.cursor()
        fmt = 'insert into {name}(aa) values(%s)'.format(
            name=db_parameters['name'])
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
        c.close()


def test_closed_cursor(conn, db_parameters):
    """
    Attempt to use the closed cursor. It should raise errors

    NOTE the binding data type is scalar
    """
    with conn() as cnx:
        c = cnx.cursor()
        fmt = 'insert into {name}(aa) values(%s)'.format(
            name=db_parameters['name'])
        c.executemany(fmt, [
            12345,
            1234,
            234,
            34,
            4,
        ])
        rec = c.fetchone()
        assert rec[0] == 5, 'number of records'
        assert c.rowcount == 5, 'number of records'
        c.close()

        fmt = 'select aa from {name}'.format(name=db_parameters['name'])
        try:
            c.execute(fmt)
            raise Exception('should fail as the cursor was closed.')
        except snowflake.connector.Error as err:
            assert err.errno == errorcode.ER_CURSOR_IS_CLOSED


def test_fetchmany(conn, db_parameters):
    """
    Fetches many
    """
    with conn() as cnx:
        c = cnx.cursor()
        fmt = 'insert into {name}(aa) values(%(value)s)'.format(
            name=db_parameters['name'])
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
        c.close()

        c = cnx.cursor()
        fmt = 'select aa from {name} order by aa desc'.format(
            name=db_parameters['name'])
        c.execute(fmt)

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

        c.close()


def test_process_params(conn, db_parameters):
    """Binds variables for insert and other queries
    """
    with conn() as cnx:
        c = cnx.cursor()
        fmt = 'insert into {name}(aa) values(%(value)s)'.format(
            name=db_parameters['name'])
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
        c.close()
        assert cnt == 6, 'number of records'

        fmt = 'select count(aa) from {name} where aa > %(value)s'.format(
            name=db_parameters['name'])

        c = cnx.cursor()
        c.execute(fmt, {'value': 1233})
        for (cnt,) in c:
            pass
        assert cnt == 3, 'the number of records'
        c.close()

        fmt = 'select count(aa) from {name} where aa > %s'.format(
            name=db_parameters['name'])
        c = cnx.cursor()
        c.execute(fmt, (1234,))
        for (cnt,) in c:
            pass
        assert cnt == 2, 'the number of records'
        c.close()


def test_real_decimal(conn, db_parameters):
    """Uses Real and Decimal type
    """
    with conn() as cnx:
        c = cnx.cursor()
        fmt = ('insert into {name}(aa, pct, ratio) '
               'values(%s,%s,%s)').format(
            name=db_parameters['name'])
        c.execute(fmt, (9876, 12.3, decimal.Decimal('23.4')))
        for (cnt,) in c:
            pass
        assert cnt == 1, 'the number of records'
        c.close()

        c = cnx.cursor()
        fmt = 'select aa, pct, ratio from {name}'.format(
            name=db_parameters['name'])
        c.execute(fmt)
        for (aa, pct, ratio) in c:
            pass
        assert aa == 9876, 'the integer value'
        assert pct == 12.3, 'the float value'
        assert ratio == decimal.Decimal('23.4'), 'the decimal value'
        c.close()

        with cnx.cursor(snowflake.connector.DictCursor) as c:
            fmt = 'select aa, pct, ratio from {name}'.format(
                name=db_parameters['name'])
            c.execute(fmt)
            rec = c.fetchone()
            assert rec['AA'] == 9876, 'the integer value'
            assert rec['PCT'] == 12.3, 'the float value'
            assert rec['RATIO'] == decimal.Decimal('23.4'), 'the decimal value'


def test_none_errorhandler(conn_testaccount):
    """
    None errorhandler for Cursor
    """
    c = conn_testaccount.cursor()
    with pytest.raises(errors.ProgrammingError):
        c.errorhandler = None


def test_nope_errorhandler(conn_testaccount):
    """
    NOOP errorhandler for Cursor
    """

    def user_errorhandler(connection, cursor, errorclass, errorvalue):
        pass

    c = conn_testaccount.cursor()
    c.errorhandler = user_errorhandler
    c.execute("select * foooooo never_exists_table")
    c.execute("select * barrrrr never_exists_table")
    c.execute("select * daaaaaa never_exists_table")
    assert c.messages[0][0] == errors.ProgrammingError, \
        'One error was recorded'
    assert len(c.messages) == 1, 'should be one error'


def test_binding_negative(conn_cnx, db_parameters):
    """
    Negative binding tests
    """
    with conn_cnx() as cnx:
        with pytest.raises(TypeError):
            cnx.cursor().execute(
                "INSERT INTO {name}(aa) VALUES(%s)".format(
                    name=db_parameters['name']), (1, 2, 3))
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(
                "INSERT INTO {name}(aa) VALUES(%s)".format(
                    name=db_parameters['name']), ())
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(
                "INSERT INTO {name}(aa) VALUES(%s)".format(
                    name=db_parameters['name']), (['a'],))


def test_execute_after_close(conn_testaccount):
    """
    SNOW-13588: raises an error if executing after the connection is closed
    """
    cursor = conn_testaccount.cursor()
    conn_testaccount.close()
    with pytest.raises(errors.Error):
        cursor.execute('show tables')


def test_cancel_query(conn_cnx):
    with conn_cnx() as cnx:
        # run one query first to set the client API version to V2
        sql = "select count(*) from table(generator(timelimit=>1))"
        cnx.cursor().execute(sql)
        # cancel the query.
        sql = "select count(*) from table(generator(timelimit=>1000))"
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(sql, timeout=1)


def test_multi_table_insert(conn, db_parameters):
    try:
        with conn() as cnx:
            cur = cnx.cursor()
            cur.execute("""
    INSERT INTO {name}(aa) VALUES(1234),(9876),(2345)
    """.format(name=db_parameters['name']))
            assert cur.rowcount == 3, 'the number of records'

            cur.execute("""
CREATE OR REPLACE TABLE {name}_foo (aa_foo int)
    """.format(name=db_parameters['name']))

            cur.execute("""
CREATE OR REPLACE TABLE {name}_bar (aa_bar int)
    """.format(name=db_parameters['name']))

            cur.execute("""
INSERT ALL
    INTO {name}_foo(aa_foo) VALUES(aa)
    INTO {name}_bar(aa_bar) VALUES(aa)
    SELECT aa FROM {name}
    """.format(name=db_parameters['name']))
            assert cur.rowcount == 6
    finally:
        with conn() as cnx:
            cnx.cursor().execute("""
DROP TABLE IF EXISTS {name}_foo
""".format(name=db_parameters['name']))
            cnx.cursor().execute("""
DROP TABLE IF EXISTS {name}_bar
""".format(name=db_parameters['name']))


@pytest.mark.skipif(True, reason="""
Negative test case.
""")
def test_fetch_before_execute(conn_testaccount):
    """
    SNOW-13574: fetch before execute
    """
    cursor = conn_testaccount.cursor()
    with pytest.raises(errors.DataError):
        cursor.fetchone()


def test_close_twice(conn_testaccount):
    conn_testaccount.close()
    conn_testaccount.close()


def test_fetch_out_of_range_timestamp_value(conn):
    with conn() as cnx:
        cur = cnx.cursor()
        cur.execute("""
select '12345-01-02'::timestamp_ntz
""")
        with pytest.raises(errors.InterfaceError):
            cur.fetchone()
