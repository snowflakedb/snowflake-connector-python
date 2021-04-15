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
    InterfaceError,
    NotSupportedError,
    ProgrammingError,
    constants,
    errorcode,
    errors,
)
from snowflake.connector.compat import BASE_EXCEPTION_CLASS, IS_WINDOWS
from snowflake.connector.errorcode import (
    ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT,
    ER_INVALID_VALUE,
    ER_NOT_POSITIVE_SIZE,
)
from snowflake.connector.sqlstate import SQLSTATE_FEATURE_NOT_SUPPORTED

from ..randomize import random_string

try:
    from snowflake.connector.constants import (
        PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT,
    )
    from snowflake.connector.errorcode import (
        ER_NO_ARROW_RESULT,
        ER_NO_PYARROW,
        ER_NO_PYARROW_SNOWSQL,
    )
except ImportError:
    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT = None
    ER_NO_ARROW_RESULT = None
    ER_NO_PYARROW = None
    ER_NO_PYARROW_SNOWSQL = None


def _drop_warehouse(conn, db_parameters):
    conn.cursor().execute(
        "drop warehouse if exists {}".format(db_parameters["name_wh"])
    )


@pytest.fixture()
def conn(request, conn_cnx, db_parameters):
    def fin():
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                "use {db}.{schema}".format(
                    db=db_parameters["database"], schema=db_parameters["schema"]
                )
            )
            cnx.cursor().execute("drop table {name}".format(name=db_parameters["name"]))

    request.addfinalizer(fin)

    with conn_cnx() as cnx:
        cnx.cursor().execute(
            """
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
""".format(
                name=db_parameters["name"]
            )
        )

    return conn_cnx


def _check_results(cursor, results):
    assert cursor.sfqid, "Snowflake query id is None"
    assert cursor.rowcount == 3, "the number of records"
    assert results[0] == 65432, "the first result was wrong"
    assert results[1] == 98765, "the second result was wrong"
    assert results[2] == 123456, "the third result was wrong"


def test_insert_select(conn, db_parameters):
    """Inserts and selects integer data."""
    with conn() as cnx:
        c = cnx.cursor()
        try:
            c.execute(
                "insert into {name}(aa) values(123456),"
                "(98765),(65432)".format(name=db_parameters["name"])
            )
            cnt = 0
            for rec in c:
                cnt += int(rec[0])
            assert cnt == 3, "wrong number of records were inserted"
            assert c.rowcount == 3, "wrong number of records were inserted"
        finally:
            c.close()

        try:
            c = cnx.cursor()
            c.execute(
                "select aa from {name} order by aa".format(name=db_parameters["name"])
            )
            results = []
            for rec in c:
                results.append(rec[0])
            _check_results(c, results)
        finally:
            c.close()

        with cnx.cursor(snowflake.connector.DictCursor) as c:
            c.execute(
                "select aa from {name} order by aa".format(name=db_parameters["name"])
            )
            results = []
            for rec in c:
                results.append(rec["AA"])
            _check_results(c, results)


def test_insert_and_select_by_separate_connection(conn, db_parameters):
    """Inserts a record and select it by a separate connection."""
    with conn() as cnx:
        result = cnx.cursor().execute(
            "insert into {name}(aa) values({value})".format(
                name=db_parameters["name"], value="1234"
            )
        )
        cnt = 0
        for rec in result:
            cnt += int(rec[0])
        assert cnt == 1, "wrong number of records were inserted"
        assert result.rowcount == 1, "wrong number of records were inserted"

    cnx2 = snowflake.connector.connect(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        database=db_parameters["database"],
        schema=db_parameters["schema"],
        protocol=db_parameters["protocol"],
        timezone="UTC",
    )
    try:
        c = cnx2.cursor()
        c.execute("select aa from {name}".format(name=db_parameters["name"]))
        results = []
        for rec in c:
            results.append(rec[0])
        c.close()
        assert results[0] == 1234, "the first result was wrong"
        assert result.rowcount == 1, "wrong number of records were selected"
    finally:
        cnx2.close()


def _total_milliseconds_from_timedelta(td):
    """Returns the total number of milliseconds contained in the duration object."""
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) // 10 ** 3


def _total_seconds_from_timedelta(td):
    """Returns the total number of seconds contained in the duration object."""
    return _total_milliseconds_from_timedelta(td) // 10 ** 3


def test_insert_timestamp_select(conn, db_parameters):
    """Inserts and gets timestamp, timestamp with tz, date, and time.

    Notes:
        Currently the session parameter TIMEZONE is ignored.
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
            fmt = (
                "insert into {name}(aa, tsltz, tstz, tsntz, dt, tm) "
                "values(%(value)s,%(tsltz)s, %(tstz)s, %(tsntz)s, "
                "%(dt)s, %(tm)s)"
            )
            c.execute(
                fmt.format(name=db_parameters["name"]),
                {
                    "value": 1234,
                    "tsltz": current_timestamp,
                    "tstz": other_timestamp,
                    "tsntz": current_timestamp,
                    "dt": current_date,
                    "tm": current_time,
                },
            )
            cnt = 0
            for rec in c:
                cnt += int(rec[0])
            assert cnt == 1, "wrong number of records were inserted"
            assert c.rowcount == 1, "wrong number of records were selected"
        finally:
            c.close()

    cnx2 = snowflake.connector.connect(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        database=db_parameters["database"],
        schema=db_parameters["schema"],
        protocol=db_parameters["protocol"],
        timezone="UTC",
    )
    try:
        c = cnx2.cursor()
        c.execute(
            "select aa, tsltz, tstz, tsntz, dt, tm from {name}".format(
                name=db_parameters["name"]
            )
        )

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
        assert result_numeric_value[0] == 1234, "the integer result was wrong"

        td_diff = _total_milliseconds_from_timedelta(
            current_timestamp - result_timestamp_value[0]
        )
        assert td_diff == 0, "the timestamp result was wrong"

        td_diff = _total_milliseconds_from_timedelta(
            other_timestamp - result_other_timestamp_value[0]
        )
        assert td_diff == 0, "the other timestamp result was wrong"

        td_diff = _total_milliseconds_from_timedelta(
            current_timestamp.replace(tzinfo=None) - result_ntz_timestamp_value[0]
        )
        assert td_diff == 0, "the other timestamp result was wrong"

        assert current_date == result_date_value[0], "the date result was wrong"

        assert current_time == result_time_value[0], "the time result was wrong"

        desc = c.description
        assert len(desc) == 6, "invalid number of column meta data"
        assert desc[0][0].upper() == "AA", "invalid column name"
        assert desc[1][0].upper() == "TSLTZ", "invalid column name"
        assert desc[2][0].upper() == "TSTZ", "invalid column name"
        assert desc[3][0].upper() == "TSNTZ", "invalid column name"
        assert desc[4][0].upper() == "DT", "invalid column name"
        assert desc[5][0].upper() == "TM", "invalid column name"
        assert (
            constants.FIELD_ID_TO_NAME[desc[0][1]] == "FIXED"
        ), "invalid column name: {}".format(constants.FIELD_ID_TO_NAME[desc[0][1]])
        assert (
            constants.FIELD_ID_TO_NAME[desc[1][1]] == "TIMESTAMP_LTZ"
        ), "invalid column name"
        assert (
            constants.FIELD_ID_TO_NAME[desc[2][1]] == "TIMESTAMP_TZ"
        ), "invalid column name"
        assert (
            constants.FIELD_ID_TO_NAME[desc[3][1]] == "TIMESTAMP_NTZ"
        ), "invalid column name"
        assert constants.FIELD_ID_TO_NAME[desc[4][1]] == "DATE", "invalid column name"
        assert constants.FIELD_ID_TO_NAME[desc[5][1]] == "TIME", "invalid column name"
    finally:
        cnx2.close()


def test_insert_timestamp_ltz(conn, db_parameters):
    """Inserts and retrieve timestamp ltz."""
    tzstr = "America/New_York"
    # sync with the session parameter
    with conn() as cnx:
        cnx.cursor().execute("alter session set timezone='{tzstr}'".format(tzstr=tzstr))

        current_time = datetime.now()
        current_time = current_time.replace(tzinfo=pytz.timezone(tzstr))

        c = cnx.cursor()
        try:
            fmt = "insert into {name}(aa, tsltz) values(%(value)s,%(ts)s)"
            c.execute(
                fmt.format(name=db_parameters["name"]),
                {
                    "value": 8765,
                    "ts": current_time,
                },
            )
            cnt = 0
            for rec in c:
                cnt += int(rec[0])
            assert cnt == 1, "wrong number of records were inserted"
        finally:
            c.close()

        try:
            c = cnx.cursor()
            c.execute("select aa,tsltz from {name}".format(name=db_parameters["name"]))
            result_numeric_value = []
            result_timestamp_value = []
            for (aa, ts) in c:
                result_numeric_value.append(aa)
                result_timestamp_value.append(ts)

            td_diff = _total_milliseconds_from_timedelta(
                current_time - result_timestamp_value[0]
            )

            assert td_diff == 0, "the first result was wrong"
        finally:
            c.close()


def test_struct_time(conn, db_parameters):
    """Binds struct_time object for updating timestamp."""
    tzstr = "America/New_York"
    os.environ["TZ"] = tzstr
    if not IS_WINDOWS:
        time.tzset()
    test_time = time.strptime("30 Sep 01 11:20:30", "%d %b %y %H:%M:%S")

    with conn() as cnx:
        c = cnx.cursor()
        try:
            fmt = "insert into {name}(aa, tsltz) values(%(value)s,%(ts)s)"
            c.execute(
                fmt.format(name=db_parameters["name"]),
                {
                    "value": 87654,
                    "ts": test_time,
                },
            )
            cnt = 0
            for rec in c:
                cnt += int(rec[0])
        finally:
            c.close()
            os.environ["TZ"] = "UTC"
            if not IS_WINDOWS:
                time.tzset()
        assert cnt == 1, "wrong number of records were inserted"

        try:
            result = cnx.cursor().execute(
                "select aa, tsltz from {name}".format(name=db_parameters["name"])
            )
            for (_, _tsltz) in result:
                pass

            _tsltz -= _tsltz.tzinfo.utcoffset(_tsltz)

            assert test_time.tm_year == _tsltz.year, "Year didn't match"
            assert test_time.tm_mon == _tsltz.month, "Month didn't match"
            assert test_time.tm_mday == _tsltz.day, "Day didn't match"
            assert test_time.tm_hour == _tsltz.hour, "Hour didn't match"
            assert test_time.tm_min == _tsltz.minute, "Minute didn't match"
            assert test_time.tm_sec == _tsltz.second, "Second didn't match"
        finally:
            os.environ["TZ"] = "UTC"
            if not IS_WINDOWS:
                time.tzset()


def test_insert_binary_select(conn, db_parameters):
    """Inserts and get a binary value."""
    value = b"\x00\xFF\xA1\xB2\xC3"

    with conn() as cnx:
        c = cnx.cursor()
        try:
            fmt = "insert into {name}(b) values(%(b)s)"
            c.execute(fmt.format(name=db_parameters["name"]), {"b": value})
            count = sum(int(rec[0]) for rec in c)
            assert count == 1, "wrong number of records were inserted"
            assert c.rowcount == 1, "wrong number of records were selected"
        finally:
            c.close()

    cnx2 = snowflake.connector.connect(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        database=db_parameters["database"],
        schema=db_parameters["schema"],
        protocol=db_parameters["protocol"],
    )
    try:
        c = cnx2.cursor()
        c.execute("select b from {name}".format(name=db_parameters["name"]))

        results = [b for (b,) in c]
        assert value == results[0], "the binary result was wrong"

        desc = c.description
        assert len(desc) == 1, "invalid number of column meta data"
        assert desc[0][0].upper() == "B", "invalid column name"
        assert constants.FIELD_ID_TO_NAME[desc[0][1]] == "BINARY", "invalid column name"
    finally:
        cnx2.close()


def test_insert_binary_select_with_bytearray(conn, db_parameters):
    """Inserts and get a binary value using the bytearray type."""
    value = bytearray(b"\x00\xFF\xA1\xB2\xC3")

    with conn() as cnx:
        c = cnx.cursor()
        try:
            fmt = "insert into {name}(b) values(%(b)s)"
            c.execute(fmt.format(name=db_parameters["name"]), {"b": value})
            count = sum(int(rec[0]) for rec in c)
            assert count == 1, "wrong number of records were inserted"
            assert c.rowcount == 1, "wrong number of records were selected"
        finally:
            c.close()

    cnx2 = snowflake.connector.connect(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        database=db_parameters["database"],
        schema=db_parameters["schema"],
        protocol=db_parameters["protocol"],
    )
    try:
        c = cnx2.cursor()
        c.execute("select b from {name}".format(name=db_parameters["name"]))

        results = [b for (b,) in c]
        assert bytes(value) == results[0], "the binary result was wrong"

        desc = c.description
        assert len(desc) == 1, "invalid number of column meta data"
        assert desc[0][0].upper() == "B", "invalid column name"
        assert constants.FIELD_ID_TO_NAME[desc[0][1]] == "BINARY", "invalid column name"
    finally:
        cnx2.close()


def test_variant(conn, db_parameters):
    """Variant including JSON object."""
    name_variant = db_parameters["name"] + "_variant"
    with conn() as cnx:
        cnx.cursor().execute(
            """
create table {name} (
created_at timestamp, data variant)
""".format(
                name=name_variant
            )
        )

    try:
        with conn() as cnx:
            current_time = datetime.now()
            c = cnx.cursor()
            try:
                fmt = (
                    "insert into {name}(created_at, data) "
                    "select column1, parse_json(column2) "
                    "from values(%(created_at)s, %(data)s)"
                )
                c.execute(
                    fmt.format(name=name_variant),
                    {
                        "created_at": current_time,
                        "data": (
                            '{"SESSION-PARAMETERS":{'
                            '"TIMEZONE":"UTC", "SPECIAL_FLAG":true}}'
                        ),
                    },
                )
                cnt = 0
                for rec in c:
                    cnt += int(rec[0])
                assert cnt == 1, "wrong number of records were inserted"
                assert c.rowcount == 1, "wrong number of records were inserted"
            finally:
                c.close()

            result = cnx.cursor().execute(
                "select created_at, data from {name}".format(name=name_variant)
            )
            _, data = result.fetchone()
            data = json.loads(data)
            assert data["SESSION-PARAMETERS"]["SPECIAL_FLAG"], (
                "JSON data should be parsed properly. " "Invalid JSON data"
            )
    finally:
        with conn() as cnx:
            cnx.cursor().execute("drop table {name}".format(name=name_variant))


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
            cnx.cursor().execute("select 1 from dual where 1=%s", ([1, 2, 3],))


def test_timeout_query(conn_cnx):
    with conn_cnx() as cnx:
        cnx.cursor().execute("select 1")
        c = cnx.cursor()
        try:
            c.execute(
                "select seq8() as c1 " "from table(generator(timeLimit => 60))",
                timeout=5,
            )
            raise Exception("Must be canceled")
        except BASE_EXCEPTION_CLASS as err:
            assert isinstance(
                err, errors.ProgrammingError
            ), "Programming Error Exception"
            assert err.errno == 604, "Invalid error code"
        finally:
            c.close()


def test_executemany(conn, db_parameters):
    """Executes many statements. Client binding is supported by either dict, or list data types.

    Notes:
        The binding data type is dict and tuple, respectively.
    """
    with conn() as cnx:
        c = cnx.cursor()
        fmt = "insert into {name}(aa) values(%(value)s)".format(
            name=db_parameters["name"]
        )
        c.executemany(
            fmt,
            [
                {"value": "1234"},
                {"value": "234"},
                {"value": "34"},
                {"value": "4"},
            ],
        )
        cnt = 0
        for rec in c:
            cnt += int(rec[0])
        assert cnt == 4, "number of records"
        assert c.rowcount == 4, "wrong number of records were inserted"
        c.close()

        c = cnx.cursor()
        fmt = "insert into {name}(aa) values(%s)".format(name=db_parameters["name"])
        c.executemany(
            fmt,
            [
                (12345,),
                (1234,),
                (234,),
                (34,),
                (4,),
            ],
        )
        rec = c.fetchone()
        assert rec[0] == 5, "number of records"
        assert c.rowcount == 5, "wrong number of records were inserted"
        c.close()


def test_closed_cursor(conn, db_parameters):
    """Attempts to use the closed cursor. It should raise errors.

    Notes:
        The binding data type is scalar.
    """
    with conn() as cnx:
        c = cnx.cursor()
        fmt = "insert into {name}(aa) values(%s)".format(name=db_parameters["name"])
        c.executemany(
            fmt,
            [
                12345,
                1234,
                234,
                34,
                4,
            ],
        )
        rec = c.fetchone()
        assert rec[0] == 5, "number of records"
        assert c.rowcount == 5, "number of records"
        c.close()

        fmt = "select aa from {name}".format(name=db_parameters["name"])
        try:
            c.execute(fmt)
            raise Exception("should fail as the cursor was closed.")
        except snowflake.connector.Error as err:
            assert err.errno == errorcode.ER_CURSOR_IS_CLOSED


def test_fetchmany(conn, db_parameters):
    with conn() as cnx:
        c = cnx.cursor()
        fmt = "insert into {name}(aa) values(%(value)s)".format(
            name=db_parameters["name"]
        )
        c.executemany(
            fmt,
            [
                {"value": "3456789"},
                {"value": "234567"},
                {"value": "1234"},
                {"value": "234"},
                {"value": "34"},
                {"value": "4"},
            ],
        )
        cnt = 0
        for rec in c:
            cnt += int(rec[0])
        assert cnt == 6, "number of records"
        assert c.rowcount == 6, "number of records"
        c.close()

        c = cnx.cursor()
        fmt = "select aa from {name} order by aa desc".format(
            name=db_parameters["name"]
        )
        c.execute(fmt)

        rows = c.fetchmany(2)
        assert len(rows) == 2, "The number of records"
        assert rows[1][0] == 234567, "The second record"

        rows = c.fetchmany(1)
        assert len(rows) == 1, "The number of records"
        assert rows[0][0] == 1234, "The first record"

        rows = c.fetchmany(5)
        assert len(rows) == 3, "The number of records"
        assert rows[-1][0] == 4, "The last record"

        rows = c.fetchmany(15)
        assert len(rows) == 0, "The number of records"

        c.close()


def test_process_params(conn, db_parameters):
    """Binds variables for insert and other queries."""
    with conn() as cnx:
        c = cnx.cursor()
        fmt = "insert into {name}(aa) values(%(value)s)".format(
            name=db_parameters["name"]
        )
        c.executemany(
            fmt,
            [
                {"value": "3456789"},
                {"value": "234567"},
                {"value": "1234"},
                {"value": "234"},
                {"value": "34"},
                {"value": "4"},
            ],
        )
        cnt = 0
        for rec in c:
            cnt += int(rec[0])
        c.close()
        assert cnt == 6, "number of records"

        fmt = "select count(aa) from {name} where aa > %(value)s".format(
            name=db_parameters["name"]
        )

        c = cnx.cursor()
        c.execute(fmt, {"value": 1233})
        for (_cnt,) in c:
            pass
        assert _cnt == 3, "the number of records"
        c.close()

        fmt = "select count(aa) from {name} where aa > %s".format(
            name=db_parameters["name"]
        )
        c = cnx.cursor()
        c.execute(fmt, (1234,))
        for (_cnt,) in c:
            pass
        assert _cnt == 2, "the number of records"
        c.close()


def test_real_decimal(conn, db_parameters):
    with conn() as cnx:
        c = cnx.cursor()
        fmt = ("insert into {name}(aa, pct, ratio) " "values(%s,%s,%s)").format(
            name=db_parameters["name"]
        )
        c.execute(fmt, (9876, 12.3, decimal.Decimal("23.4")))
        for (_cnt,) in c:
            pass
        assert _cnt == 1, "the number of records"
        c.close()

        c = cnx.cursor()
        fmt = "select aa, pct, ratio from {name}".format(name=db_parameters["name"])
        c.execute(fmt)
        for (_aa, _pct, _ratio) in c:
            pass
        assert _aa == 9876, "the integer value"
        assert _pct == 12.3, "the float value"
        assert _ratio == decimal.Decimal("23.4"), "the decimal value"
        c.close()

        with cnx.cursor(snowflake.connector.DictCursor) as c:
            fmt = "select aa, pct, ratio from {name}".format(name=db_parameters["name"])
            c.execute(fmt)
            rec = c.fetchone()
            assert rec["AA"] == 9876, "the integer value"
            assert rec["PCT"] == 12.3, "the float value"
            assert rec["RATIO"] == decimal.Decimal("23.4"), "the decimal value"


def test_none_errorhandler(conn_testaccount):
    c = conn_testaccount.cursor()
    with pytest.raises(errors.ProgrammingError):
        c.errorhandler = None


def test_nope_errorhandler(conn_testaccount):
    def user_errorhandler(connection, cursor, errorclass, errorvalue):
        pass

    c = conn_testaccount.cursor()
    c.errorhandler = user_errorhandler
    c.execute("select * foooooo never_exists_table")
    c.execute("select * barrrrr never_exists_table")
    c.execute("select * daaaaaa never_exists_table")
    assert c.messages[0][0] == errors.ProgrammingError, "One error was recorded"
    assert len(c.messages) == 1, "should be one error"


@pytest.mark.internal
def test_binding_negative(negative_conn_cnx, db_parameters):
    with negative_conn_cnx() as cnx:
        with pytest.raises(TypeError):
            cnx.cursor().execute(
                "INSERT INTO {name}(aa) VALUES(%s)".format(name=db_parameters["name"]),
                (1, 2, 3),
            )
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(
                "INSERT INTO {name}(aa) VALUES(%s)".format(name=db_parameters["name"]),
                (),
            )
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute(
                "INSERT INTO {name}(aa) VALUES(%s)".format(name=db_parameters["name"]),
                (["a"],),
            )


def test_execute_after_close(conn_testaccount):
    """SNOW-13588: Raises an error if executing after the connection is closed."""
    cursor = conn_testaccount.cursor()
    conn_testaccount.close()
    with pytest.raises(errors.Error):
        cursor.execute("show tables")


def test_multi_table_insert(conn, db_parameters):
    try:
        with conn() as cnx:
            cur = cnx.cursor()
            cur.execute(
                """
    INSERT INTO {name}(aa) VALUES(1234),(9876),(2345)
    """.format(
                    name=db_parameters["name"]
                )
            )
            assert cur.rowcount == 3, "the number of records"

            cur.execute(
                """
CREATE OR REPLACE TABLE {name}_foo (aa_foo int)
    """.format(
                    name=db_parameters["name"]
                )
            )

            cur.execute(
                """
CREATE OR REPLACE TABLE {name}_bar (aa_bar int)
    """.format(
                    name=db_parameters["name"]
                )
            )

            cur.execute(
                """
INSERT ALL
    INTO {name}_foo(aa_foo) VALUES(aa)
    INTO {name}_bar(aa_bar) VALUES(aa)
    SELECT aa FROM {name}
    """.format(
                    name=db_parameters["name"]
                )
            )
            assert cur.rowcount == 6
    finally:
        with conn() as cnx:
            cnx.cursor().execute(
                """
DROP TABLE IF EXISTS {name}_foo
""".format(
                    name=db_parameters["name"]
                )
            )
            cnx.cursor().execute(
                """
DROP TABLE IF EXISTS {name}_bar
""".format(
                    name=db_parameters["name"]
                )
            )


@pytest.mark.skipif(
    True,
    reason="""
Negative test case.
""",
)
def test_fetch_before_execute(conn_testaccount):
    """SNOW-13574: Fetch before execute."""
    cursor = conn_testaccount.cursor()
    with pytest.raises(errors.DataError):
        cursor.fetchone()


def test_close_twice(conn_testaccount):
    conn_testaccount.close()
    conn_testaccount.close()


def test_fetch_out_of_range_timestamp_value(conn):
    for result_format in ["arrow", "json"]:
        with conn() as cnx:
            cur = cnx.cursor()
            cur.execute(
                "alter session set python_connector_query_result_format='{}'".format(
                    result_format
                )
            )
            cur.execute("select '12345-01-02'::timestamp_ntz")
            with pytest.raises(errors.InterfaceError):
                cur.fetchone()


def test_empty_execution(conn):
    """Checks whether executing an empty string behaves as expected."""
    with conn() as cnx:
        with cnx.cursor() as cur:
            cur.execute("")
            assert cur._result is None
            with pytest.raises(Exception):
                cur.fetchall()


def test_rownumber(conn):
    """Checks whether rownumber is returned as expected."""
    with conn() as cnx:
        with cnx.cursor() as cur:
            assert cur.execute("select * from values (1), (2)").fetchone() == (1,)
            assert cur.rownumber == 0
            assert cur.fetchone() == (2,)
            assert cur.rownumber == 1


def test_values_set(conn):
    """Checks whether a bunch of properties start as Nones, but get set to something else when a query was executed."""
    properties = [
        "timestamp_output_format",
        "timestamp_ltz_output_format",
        "timestamp_tz_output_format",
        "timestamp_ntz_output_format",
        "date_output_format",
        "timezone",
        "time_output_format",
        "binary_output_format",
    ]
    with conn() as cnx:
        with cnx.cursor() as cur:
            for property in properties:
                assert getattr(cur, property) is None
            assert cur.execute("select 1").fetchone() == (1,)
            # The default values might change in future, so let's just check that they aren't None anymore
            for property in properties:
                assert getattr(cur, property) is not None


def test_execute_helper_params_error(conn_testaccount):
    """Tests whether calling _execute_helper with a non-dict statement params is handled correctly."""
    with conn_testaccount.cursor() as cur:
        with pytest.raises(
            ProgrammingError,
            match=r"The data type of statement params is invalid. It must be dict.$",
        ):
            cur._execute_helper("select %()s", statement_params="1")


def test_desc_rewrite(conn, caplog):
    """Tests whether describe queries are rewritten as expected and this action is logged."""
    with conn() as cnx:
        with cnx.cursor() as cur:
            table_name = random_string(5, "test_desc_rewrite_")
            try:
                cur.execute("create or replace table {} (a int)".format(table_name))
                caplog.set_level(logging.DEBUG, "snowflake.connector")
                cur.execute("desc {}".format(table_name))
                assert (
                    "snowflake.connector.cursor",
                    20,
                    "query was rewritten: org=desc {table_name}, new=describe table {table_name}".format(
                        table_name=table_name
                    ),
                ) in caplog.record_tuples
            finally:
                cur.execute("drop table {}".format(table_name))


@pytest.mark.skipolddriver
@pytest.mark.parametrize("result_format", [False, None, "json"])
def test_execute_helper_cannot_use_arrow(conn_cnx, caplog, result_format):
    """Tests whether cannot use arrow is handled correctly inside of _execute_helper."""
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            with mock.patch("snowflake.connector.cursor.CAN_USE_ARROW_RESULT", False):
                if result_format is False:
                    result_format = None
                else:
                    result_format = {
                        PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: result_format
                    }
                caplog.set_level(logging.DEBUG, "snowflake.connector")
                cur.execute("select 1", _statement_params=result_format)
                assert (
                    "snowflake.connector.cursor",
                    logging.DEBUG,
                    "Cannot use arrow result format, fallback to json format",
                ) in caplog.record_tuples
                assert cur.fetchone() == (1,)


@pytest.mark.skipolddriver
def test_execute_helper_cannot_use_arrow_exception(conn_cnx):
    """Like test_execute_helper_cannot_use_arrow but when we are trying to force arrow an Exception should be raised."""
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            with mock.patch("snowflake.connector.cursor.CAN_USE_ARROW_RESULT", False):
                with pytest.raises(
                    ProgrammingError,
                    match="The result set in Apache Arrow format is not supported for the platform.",
                ):
                    cur.execute(
                        "select 1",
                        _statement_params={
                            PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: "arrow"
                        },
                    )


@pytest.mark.skipolddriver
def test_check_can_use_arrow_resultset(conn_cnx, caplog):
    """Tests check_can_use_arrow_resultset has no effect when we can use arrow."""
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            with mock.patch("snowflake.connector.cursor.CAN_USE_ARROW_RESULT", True):
                caplog.set_level(logging.DEBUG, "snowflake.connector")
                cur.check_can_use_arrow_resultset()
    assert "Arrow" not in caplog.text


@pytest.mark.skipolddriver
@pytest.mark.parametrize("snowsql", [True, False])
def test_check_cannot_use_arrow_resultset(conn_cnx, caplog, snowsql):
    """Tests check_can_use_arrow_resultset expected outcomes."""
    config = {}
    if snowsql:
        config["application"] = "SnowSQL"
    with conn_cnx(**config) as cnx:
        with cnx.cursor() as cur:
            with mock.patch("snowflake.connector.cursor.CAN_USE_ARROW_RESULT", False):
                with pytest.raises(
                    ProgrammingError,
                    match="Currently SnowSQL doesn't support the result set in Apache Arrow format."
                    if snowsql
                    else "The result set in Apache Arrow format is not supported for the platform.",
                ) as pe:
                    cur.check_can_use_arrow_resultset()
                    assert pe.errno == (
                        ER_NO_PYARROW_SNOWSQL if snowsql else ER_NO_ARROW_RESULT
                    )


@pytest.mark.skipolddriver
def test_check_can_use_pandas(conn_cnx):
    """Tests check_can_use_arrow_resultset has no effect when we can import pandas."""
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            with mock.patch(
                "snowflake.connector.cursor.pyarrow", "Something other than None"
            ):
                cur.check_can_use_pandas()


@pytest.mark.skipolddriver
def test_check_cannot_use_pandas(conn_cnx):
    """Tests check_can_use_arrow_resultset has expected outcomes."""
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            with mock.patch("snowflake.connector.cursor.pyarrow", None):
                with pytest.raises(
                    ProgrammingError,
                    match=r"Optional dependency: 'pyarrow' is not installed, please see the "
                    "following link for install instructions: https:.*",
                ) as pe:
                    cur.check_can_use_pandas()
                    assert pe.errno == ER_NO_PYARROW


@pytest.mark.skipolddriver
def test_not_supported_pandas(conn_cnx):
    """Check that fetch_pandas functions return expected error when arrow results are not available."""
    result_format = {PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: "json"}
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            cur.execute("select 1", _statement_params=result_format)
            with mock.patch(
                "snowflake.connector.cursor.pyarrow", "Something other than None"
            ):
                with pytest.raises(NotSupportedError):
                    cur.fetch_pandas_all()
                with pytest.raises(NotSupportedError):
                    list(cur.fetch_pandas_batches())


def test_query_cancellation(conn_cnx):
    """Tests whether query_cancellation works."""
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            cur.execute(
                "select max(seq8()) from table(generator(timeLimit=>30));",
                _no_results=True,
            )
            sf_qid = cur.sfqid
            cur.abort_query(sf_qid)


def test_executemany_error(conn_cnx):
    """Tests calling executemany without many things."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            with pytest.raises(
                InterfaceError,
                match="No parameters are specified for the command: select 1",
            ) as ie:
                cur.executemany("select 1", [])
                assert ie.errno == ER_INVALID_VALUE


def test_executemany_insert_rewrite(conn_cnx):
    """Tests calling executemany with a non rewritable pyformat insert query."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            with pytest.raises(
                InterfaceError, match="Failed to rewrite multi-row insert"
            ) as ie:
                cur.executemany("insert into numbers (select 1)", [1, 2])
                assert ie.errno == ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT


def test_executemany_bulk_insert_size_mismatch(conn_cnx):
    """Tests bulk insert error with variable length of arguments."""
    with conn_cnx(paramstyle="qmark") as con:
        with con.cursor() as cur:
            with pytest.raises(
                InterfaceError, match="Bulk data size don't match. expected: 1, got: 2"
            ) as ie:
                cur.executemany("insert into numbers values (?,?)", [[1], [1, 2]])
                assert ie.errno == ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT


def test_fetchmany_size_error(conn_cnx):
    """Tests retrieving a negative number of results."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute("select 1")
            with pytest.raises(
                ProgrammingError,
                match="The number of rows is not zero or positive number: -1",
            ) as ie:
                cur.fetchmany(-1)
                assert ie.errno == ER_NOT_POSITIVE_SIZE


def test_nextset(conn_cnx, caplog):
    """Tests no op function nextset."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    with conn_cnx() as con:
        with con.cursor() as cur:
            caplog.set_level(logging.DEBUG, "snowflake.connector")
            assert cur.nextset() is None
    assert ("snowflake.connector.cursor", logging.DEBUG, "nop") in caplog.record_tuples


def test_scroll(conn_cnx):
    """Tests if scroll returns a NotSupported exception."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            with pytest.raises(
                NotSupportedError, match="scroll is not supported."
            ) as nse:
                cur.scroll(2)
                assert nse.errno == SQLSTATE_FEATURE_NOT_SUPPORTED


def test__log_telemetry_job_data(conn_cnx, caplog):
    """Tests whether we handle missing connection object correctly while logging a telemetry event."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            with mock.patch.object(cur, "_connection", None):
                caplog.set_level(logging.DEBUG, "snowflake.connector")
                cur._log_telemetry_job_data("test", True)
    assert (
        "snowflake.connector.cursor",
        logging.WARNING,
        "Cursor failed to log to telemetry. Connection object may be None.",
    ) in caplog.record_tuples
