#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import decimal
import json
import logging
import os
import pickle
import time
from datetime import date, datetime
from typing import TYPE_CHECKING, NamedTuple
from unittest import mock

import pytest
import pytz

import snowflake.connector
from snowflake.connector import (
    DictCursor,
    InterfaceError,
    NotSupportedError,
    ProgrammingError,
    connection,
    constants,
    errorcode,
    errors,
)
from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.cursor import SnowflakeCursor

try:
    from snowflake.connector.cursor import ResultMetadata
except ImportError:

    class ResultMetadata(NamedTuple):
        name: str
        type_code: int
        display_size: int
        internal_size: int
        precision: int
        scale: int
        is_nullable: bool


from snowflake.connector.description import CLIENT_VERSION
from snowflake.connector.errorcode import (
    ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT,
    ER_NOT_POSITIVE_SIZE,
)
from snowflake.connector.errors import Error
from snowflake.connector.sqlstate import SQLSTATE_FEATURE_NOT_SUPPORTED
from snowflake.connector.telemetry import TelemetryField

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from ..randomize import random_string

try:
    from snowflake.connector.constants import (
        FIELD_ID_TO_NAME,
        PARAMETER_MULTI_STATEMENT_COUNT,
        PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT,
    )
    from snowflake.connector.errorcode import (
        ER_NO_ARROW_RESULT,
        ER_NO_PYARROW,
        ER_NO_PYARROW_SNOWSQL,
    )
    from snowflake.connector.result_batch import ArrowResultBatch, JSONResultBatch
except ImportError:
    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT = None
    ER_NO_ARROW_RESULT = None
    ER_NO_PYARROW = None
    ER_NO_PYARROW_SNOWSQL = None
    ArrowResultBatch = JSONResultBatch = None
    FIELD_ID_TO_NAME = {}

if TYPE_CHECKING:  # pragma: no cover
    from snowflake.connector.result_batch import ResultBatch

try:  # pragma: no cover
    from snowflake.connector.constants import QueryStatus
except ImportError:
    QueryStatus = None


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


@pytest.mark.skipolddriver
def test_insert_select(conn, db_parameters, caplog):
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
            assert "Number of results in first chunk: 3" in caplog.text
        finally:
            c.close()

        with cnx.cursor(snowflake.connector.DictCursor) as c:
            caplog.clear()
            assert "Number of results in first chunk: 3" not in caplog.text
            c.execute(
                "select aa from {name} order by aa".format(name=db_parameters["name"])
            )
            results = []
            for rec in c:
                results.append(rec["AA"])
            _check_results(c, results)
            assert "Number of results in first chunk: 3" in caplog.text


@pytest.mark.skipolddriver
def test_insert_and_select_by_separate_connection(conn, db_parameters, caplog):
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
        assert "Number of results in first chunk: 1" in caplog.text
    finally:
        cnx2.close()


def _total_milliseconds_from_timedelta(td):
    """Returns the total number of milliseconds contained in the duration object."""
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) // 10**3


def _total_seconds_from_timedelta(td):
    """Returns the total number of seconds contained in the duration object."""
    return _total_milliseconds_from_timedelta(td) // 10**3


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

        for aa, ts, tstz, tsntz, dt, tm in c:
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
        ), f"invalid column name: {constants.FIELD_ID_TO_NAME[desc[0][1]]}"
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
        cnx.cursor().execute(f"alter session set timezone='{tzstr}'")

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
            for aa, ts in c:
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
            for _, _tsltz in result:
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
                f"select created_at, data from {name_variant}"
            )
            _, data = result.fetchone()
            data = json.loads(data)
            assert data["SESSION-PARAMETERS"]["SPECIAL_FLAG"], (
                "JSON data should be parsed properly. " "Invalid JSON data"
            )
    finally:
        with conn() as cnx:
            cnx.cursor().execute(f"drop table {name_variant}")


@pytest.mark.skipolddriver
def test_geography(conn_cnx):
    """Variant including JSON object."""
    name_geo = random_string(5, "test_geography_")
    with conn_cnx(
        session_parameters={
            "GEOGRAPHY_OUTPUT_FORMAT": "geoJson",
        },
    ) as cnx:
        with cnx.cursor() as cur:
            cur.execute(f"create temporary table {name_geo} (geo geography)")
            cur.execute(
                f"insert into {name_geo} values ('POINT(0 0)'), ('LINESTRING(1 1, 2 2)')"
            )
            expected_data = [
                {"coordinates": [0, 0], "type": "Point"},
                {"coordinates": [[1, 1], [2, 2]], "type": "LineString"},
            ]

        with cnx.cursor() as cur:
            # Test with GEOGRAPHY return type
            result = cur.execute(f"select * from {name_geo}")
            metadata = result.description
            assert FIELD_ID_TO_NAME[metadata[0].type_code] == "GEOGRAPHY"
            data = result.fetchall()
            for raw_data in data:
                row = json.loads(raw_data[0])
                assert row in expected_data


@pytest.mark.skipolddriver
def test_geometry(conn_cnx):
    """Variant including JSON object."""
    name_geo = random_string(5, "test_geometry_")
    with conn_cnx(
        session_parameters={
            "GEOMETRY_OUTPUT_FORMAT": "geoJson",
        },
    ) as cnx:
        with cnx.cursor() as cur:
            cur.execute(f"create temporary table {name_geo} (geo GEOMETRY)")
            cur.execute(
                f"insert into {name_geo} values ('POINT(0 0)'), ('LINESTRING(1 1, 2 2)')"
            )
            expected_data = [
                {"coordinates": [0, 0], "type": "Point"},
                {"coordinates": [[1, 1], [2, 2]], "type": "LineString"},
            ]

        with cnx.cursor() as cur:
            # Test with GEOMETRY return type
            result = cur.execute(f"select * from {name_geo}")
            metadata = result.description
            assert FIELD_ID_TO_NAME[metadata[0].type_code] == "GEOMETRY"
            data = result.fetchall()
            for raw_data in data:
                row = json.loads(raw_data[0])
                assert row in expected_data


def test_invalid_bind_data_type(conn_cnx):
    """Invalid bind data type."""
    with conn_cnx() as cnx:
        with pytest.raises(errors.ProgrammingError):
            cnx.cursor().execute("select 1 from dual where 1=%s", ([1, 2, 3],))


def test_timeout_query(conn_cnx):
    with conn_cnx() as cnx:
        with cnx.cursor() as c:
            with pytest.raises(errors.ProgrammingError) as err:
                c.execute(
                    "select seq8() as c1 from table(generator(timeLimit => 60))",
                    timeout=5,
                )
            assert err.value.errno == 604, "Invalid error code"


def test_executemany(conn, db_parameters):
    """Executes many statements. Client binding is supported by either dict, or list data types.

    Notes:
        The binding data type is dict and tuple, respectively.
    """
    table_name = random_string(5, "test_executemany_")
    with conn() as cnx:
        with cnx.cursor() as c:
            c.execute(f"create temp table {table_name} (aa number)")
            c.executemany(
                f"insert into {table_name}(aa) values(%(value)s)",
                [
                    {"value": 1234},
                    {"value": 234},
                    {"value": 34},
                    {"value": 4},
                ],
            )
            assert c.fetchone()[0] == 4, "number of records"
            assert c.rowcount == 4, "wrong number of records were inserted"

        with cnx.cursor() as c:
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
            assert c.fetchone()[0] == 5, "number of records"
            assert c.rowcount == 5, "wrong number of records were inserted"


@pytest.mark.skipolddriver
def test_executemany_qmark_types(conn, db_parameters):
    table_name = random_string(5, "test_executemany_qmark_types_")
    with conn(paramstyle="qmark") as cnx:
        with cnx.cursor() as cur:
            cur.execute(f"create temp table {table_name} (birth_date date)")

            insert_qy = f"INSERT INTO {table_name} (birth_date) values (?)"
            date_1, date_2 = date(1969, 2, 7), date(1969, 1, 1)

            # insert two dates, one in tuple format which specifies
            # the snowflake type similar to how we support it in this
            # example:
            # https://docs.snowflake.com/en/user-guide/python-connector-example.html#using-qmark-or-numeric-binding-with-datetime-objects
            cur.executemany(
                insert_qy,
                [[date_1], [("DATE", date_2)]],
                # test that kwargs get passed through executemany properly
                _statement_params={
                    PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: "json"
                },
            )
            assert all(
                isinstance(rb, JSONResultBatch) for rb in cur.get_result_batches()
            )

            cur.execute(f"select * from {table_name}")
            assert {row[0] for row in cur} == {date_1, date_2}


@pytest.mark.skipolddriver
def test_executemany_params_iterator(conn):
    """Cursor.executemany() works with an interator of params."""
    table_name = random_string(5, "executemany_params_iterator_")
    with conn() as cnx:
        with cnx.cursor() as c:
            c.execute(f"create temp table {table_name}(bar integer)")
            fmt = f"insert into {table_name}(bar) values(%(value)s)"
            c.executemany(fmt, ({"value": x} for x in ("1234", "234", "34", "4")))
            assert c.fetchone()[0] == 4, "number of records"
            assert c.rowcount == 4, "wrong number of records were inserted"

        with cnx.cursor() as c:
            fmt = f"insert into {table_name}(bar) values(%s)"
            c.executemany(fmt, ((x,) for x in (12345, 1234, 234, 34, 4)))
            assert c.fetchone()[0] == 5, "number of records"
            assert c.rowcount == 5, "wrong number of records were inserted"


@pytest.mark.skipolddriver
def test_executemany_empty_params(conn):
    """Cursor.executemany() does nothing if params is empty."""
    table_name = random_string(5, "executemany_empty_params_")
    with conn() as cnx:
        with cnx.cursor() as c:
            # The table isn't created, so if this were executed, it would error.
            c.executemany(f"insert into {table_name}(aa) values(%(value)s)", [])
            assert c.query is None


@pytest.mark.skipolddriver(
    reason="old driver raises DatabaseError instead of InterfaceError"
)
def test_closed_cursor(conn, db_parameters):
    """Attempts to use the closed cursor. It should raise errors.

    Notes:
        The binding data type is scalar.
    """
    table_name = random_string(5, "test_closed_cursor_")
    with conn() as cnx:
        with cnx.cursor() as c:
            c.execute(f"create temp table {table_name} (aa number)")
            fmt = f"insert into {table_name}(aa) values(%s)"
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
            assert c.fetchone()[0] == 5, "number of records"
            assert c.rowcount == 5, "number of records"

        with pytest.raises(InterfaceError, match="Cursor is closed in execute") as err:
            c.execute(f"select aa from {table_name}")
        assert err.value.errno == errorcode.ER_CURSOR_IS_CLOSED
        assert (
            c.rowcount == 5
        ), "SNOW-647539: rowcount should remain available after cursor is closed"


@pytest.mark.skipolddriver
def test_fetchmany(conn, db_parameters, caplog):
    table_name = random_string(5, "test_fetchmany_")
    with conn() as cnx:
        with cnx.cursor() as c:
            c.execute(f"create temp table {table_name} (aa number)")
            c.executemany(
                f"insert into {table_name}(aa) values(%(value)s)",
                [
                    {"value": "3456789"},
                    {"value": "234567"},
                    {"value": "1234"},
                    {"value": "234"},
                    {"value": "34"},
                    {"value": "4"},
                ],
            )
            assert c.fetchone()[0] == 6, "number of records"
            assert c.rowcount == 6, "number of records"

        with cnx.cursor() as c:
            c.execute(f"select aa from {table_name} order by aa desc")
            assert "Number of results in first chunk: 6" in caplog.text

            rows = c.fetchmany(2)
            assert len(rows) == 2, "The number of records"
            assert rows[1][0] == 234567, "The second record"

            rows = c.fetchmany(1)
            assert len(rows) == 1, "The number of records"
            assert rows[0][0] == 1234, "The first record"

            rows = c.fetchmany(5)
            assert len(rows) == 3, "The number of records"
            assert rows[-1][0] == 4, "The last record"

            assert len(c.fetchmany(15)) == 0, "The number of records"


def test_process_params(conn, db_parameters):
    """Binds variables for insert and other queries."""
    table_name = random_string(5, "test_process_params_")
    with conn() as cnx:
        with cnx.cursor() as c:
            c.execute(f"create temp table {table_name} (aa number)")
            c.executemany(
                f"insert into {table_name}(aa) values(%(value)s)",
                [
                    {"value": "3456789"},
                    {"value": "234567"},
                    {"value": "1234"},
                    {"value": "234"},
                    {"value": "34"},
                    {"value": "4"},
                ],
            )
            assert c.fetchone()[0] == 6, "number of records"

        with cnx.cursor() as c:
            c.execute(
                f"select count(aa) from {table_name} where aa > %(value)s",
                {"value": 1233},
            )
            assert c.fetchone()[0] == 3, "the number of records"

        with cnx.cursor() as c:
            c.execute(f"select count(aa) from {table_name} where aa > %s", (1234,))
            assert c.fetchone()[0] == 2, "the number of records"


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    ("interpolate_empty_sequences", "expected_outcome"), [(False, "%%s"), (True, "%s")]
)
def test_process_params_empty(conn_cnx, interpolate_empty_sequences, expected_outcome):
    """SQL is interpolated if params aren't None."""
    with conn_cnx(interpolate_empty_sequences=interpolate_empty_sequences) as cnx:
        with cnx.cursor() as cursor:
            cursor.execute("select '%%s'", None)
            assert cursor.fetchone() == ("%%s",)
            cursor.execute("select '%%s'", ())
            assert cursor.fetchone() == (expected_outcome,)


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
        for _aa, _pct, _ratio in c:
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


@pytest.mark.skipolddriver
def test_execute_stores_query(conn_cnx):
    with conn_cnx() as cnx:
        with cnx.cursor() as cursor:
            assert cursor.query is None
            cursor.execute("select 1")
            assert cursor.query == "select 1"


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


@pytest.mark.parametrize("result_format", ("arrow", "json"))
def test_fetch_out_of_range_timestamp_value(conn, result_format):
    with conn() as cnx:
        cur = cnx.cursor()
        cur.execute(
            f"alter session set python_connector_query_result_format='{result_format}'"
        )
        cur.execute("select '12345-01-02'::timestamp_ntz")
        with pytest.raises(errors.InterfaceError):
            cur.fetchone()


@pytest.mark.skipolddriver
def test_null_in_non_null(conn):
    table_name = random_string(5, "null_in_non_null")
    error_msg = "NULL result in a non-nullable column"
    with conn() as cnx:
        cur = cnx.cursor()
        cur.execute(f"create temp table {table_name}(bar char not null)")
        with pytest.raises(errors.IntegrityError, match=error_msg):
            cur.execute(f"insert into {table_name} values (null)")


@pytest.mark.parametrize("sql", (None, ""), ids=["None", "empty"])
def test_empty_execution(conn, sql):
    """Checks whether executing an empty string, or nothing behaves as expected."""
    with conn() as cnx:
        with cnx.cursor() as cur:
            if sql is not None:
                cur.execute(sql)
            assert cur._result is None
            with pytest.raises(
                TypeError, match="'NoneType' object is not( an)? itera(tor|ble)"
            ):
                cur.fetchone()
            with pytest.raises(
                TypeError, match="'NoneType' object is not( an)? itera(tor|ble)"
            ):
                cur.fetchall()


@pytest.mark.parametrize(
    "reuse_results", (False, pytest.param(True, marks=pytest.mark.skipolddriver))
)
def test_reset_fetch(conn, reuse_results):
    """Tests behavior after resetting an open cursor."""
    with conn(reuse_results=reuse_results) as cnx:
        with cnx.cursor() as cur:
            cur.execute("select 1")
            assert cur.rowcount == 1
            cur.reset()
            assert (
                cur.rowcount is None
            ), "calling reset on an open cursor should unset rowcount"
            assert not cur.is_closed(), "calling reset should not close the cursor"
            if reuse_results:
                assert cur.fetchone() == (1,)
            else:
                assert cur.fetchone() is None
                assert len(cur.fetchall()) == 0


def test_rownumber(conn):
    """Checks whether rownumber is returned as expected."""
    with conn() as cnx:
        with cnx.cursor() as cur:
            assert cur.execute("select * from values (1), (2)")
            assert cur.rownumber is None
            assert cur.fetchone() == (1,)
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
            # use a statement that alters session parameters due to HTAP optimization
            assert cur.execute(
                "alter session set TIMEZONE='America/Los_Angeles'"
            ).fetchone() == ("Statement executed successfully.",)
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
                cur.execute(f"create or replace table {table_name} (a int)")
                caplog.set_level(logging.DEBUG, "snowflake.connector")
                cur.execute(f"desc {table_name}")
                assert (
                    "snowflake.connector.cursor",
                    20,
                    "query was rewritten: org=desc {table_name}, new=describe table {table_name}".format(
                        table_name=table_name
                    ),
                ) in caplog.record_tuples
            finally:
                cur.execute(f"drop table {table_name}")


@pytest.mark.skipolddriver
@pytest.mark.parametrize("result_format", [False, None, "json"])
def test_execute_helper_cannot_use_arrow(conn_cnx, caplog, result_format):
    """Tests whether cannot use arrow is handled correctly inside of _execute_helper."""
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            with mock.patch(
                "snowflake.connector.cursor.CAN_USE_ARROW_RESULT_FORMAT", False
            ):
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
            with mock.patch(
                "snowflake.connector.cursor.CAN_USE_ARROW_RESULT_FORMAT", False
            ):
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
            with mock.patch(
                "snowflake.connector.cursor.CAN_USE_ARROW_RESULT_FORMAT", True
            ):
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
            with mock.patch(
                "snowflake.connector.cursor.CAN_USE_ARROW_RESULT_FORMAT", False
            ):
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
            with mock.patch("snowflake.connector.cursor.installed_pandas", True):
                cur.check_can_use_pandas()


@pytest.mark.skipolddriver
def test_check_cannot_use_pandas(conn_cnx):
    """Tests check_can_use_arrow_resultset has expected outcomes."""
    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            with mock.patch("snowflake.connector.cursor.installed_pandas", False):
                with pytest.raises(
                    ProgrammingError,
                    match=r"Optional dependency: 'pandas' is not installed, please see the "
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
            with mock.patch("snowflake.connector.cursor.installed_pandas", True):
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


def test_scroll(conn_cnx):
    """Tests if scroll returns a NotSupported exception."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            with pytest.raises(
                NotSupportedError, match="scroll is not supported."
            ) as nse:
                cur.scroll(2)
                assert nse.errno == SQLSTATE_FEATURE_NOT_SUPPORTED


@pytest.mark.skipolddriver
def test__log_telemetry_job_data(conn_cnx, caplog):
    """Tests whether we handle missing connection object correctly while logging a telemetry event."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            with mock.patch.object(cur, "_connection", None):
                caplog.set_level(logging.DEBUG, "snowflake.connector")
                cur._log_telemetry_job_data(
                    TelemetryField.ARROW_FETCH_ALL, True
                )  # dummy value
    assert (
        "snowflake.connector.cursor",
        logging.WARNING,
        "Cursor failed to log to telemetry. Connection object may be None.",
    ) in caplog.record_tuples


@pytest.mark.skipolddriver(reason="new feature in v2.5.0")
@pytest.mark.parametrize(
    "result_format,expected_chunk_type",
    (
        ("json", JSONResultBatch),
        ("arrow", ArrowResultBatch),
    ),
)
def test_resultbatch(
    conn_cnx,
    result_format,
    expected_chunk_type,
    capture_sf_telemetry,
):
    """This test checks the following things:
    1. After executing a query can we pickle the result batches
    2. When we get the batches, do we emit a telemetry log
    3. Whether we can iterate through ResultBatches multiple times
    4. Whether the results make sense
    5. See whether getter functions are working
    """
    rowcount = 100000
    with conn_cnx(
        session_parameters={
            "python_connector_query_result_format": result_format,
        }
    ) as con:
        with capture_sf_telemetry.patch_connection(con) as telemetry_data:
            with con.cursor() as cur:
                cur.execute(
                    f"select seq4() from table(generator(rowcount => {rowcount}));"
                )
                assert cur._result_set.total_row_index() == rowcount
                pre_pickle_partitions = cur.get_result_batches()
                assert len(pre_pickle_partitions) > 1
                assert pre_pickle_partitions is not None
                assert all(
                    isinstance(p, expected_chunk_type) for p in pre_pickle_partitions
                )
                pickle_str = pickle.dumps(pre_pickle_partitions)
                assert any(
                    t.message["type"] == TelemetryField.GET_PARTITIONS_USED.value
                    for t in telemetry_data.records
                )
    post_pickle_partitions: list[ResultBatch] = pickle.loads(pickle_str)
    total_rows = 0
    # Make sure the batches can be iterated over individually
    for i, partition in enumerate(post_pickle_partitions):
        # Tests whether the getter functions are working
        if i == 0:
            assert partition.compressed_size is None
            assert partition.uncompressed_size is None
        else:
            assert partition.compressed_size is not None
            assert partition.uncompressed_size is not None
        for row in partition:
            col1 = row[0]
            assert col1 == total_rows
            total_rows += 1
    assert total_rows == rowcount
    total_rows = 0
    # Make sure the batches can be iterated over again
    for partition in post_pickle_partitions:
        for row in partition:
            col1 = row[0]
            assert col1 == total_rows
            total_rows += 1
    assert total_rows == rowcount


@pytest.mark.skipolddriver(reason="new feature in v2.5.0")
@pytest.mark.parametrize(
    "result_format,patch_path",
    (
        ("json", "snowflake.connector.result_batch.JSONResultBatch.create_iter"),
        ("arrow", "snowflake.connector.result_batch.ArrowResultBatch.create_iter"),
    ),
)
def test_resultbatch_lazy_fetching_and_schemas(conn_cnx, result_format, patch_path):
    """Tests whether pre-fetching results chunks fetches the right amount of them."""
    rowcount = 1000000  # We need at least 5 chunks for this test
    with conn_cnx(
        session_parameters={
            "python_connector_query_result_format": result_format,
        }
    ) as con:
        with con.cursor() as cur:
            # Dummy return value necessary to not iterate through every batch with
            #  first fetchone call

            downloads = [iter([(i,)]) for i in range(10)]

            with mock.patch(
                patch_path,
                side_effect=downloads,
            ) as patched_download:
                cur.execute(
                    f"select seq4() as c1, randstr(1,random()) as c2 "
                    f"from table(generator(rowcount => {rowcount}));"
                )
                result_batches = cur.get_result_batches()
                batch_schemas = [batch.schema for batch in result_batches]
                for schema in batch_schemas:
                    # all batches should have the same schema
                    assert schema == [
                        ResultMetadata("C1", 0, None, None, 10, 0, False),
                        ResultMetadata("C2", 2, None, 16777216, None, None, False),
                    ]
                assert patched_download.call_count == 0
                assert len(result_batches) > 5
                assert result_batches[0]._local  # Sanity check first chunk being local
                cur.fetchone()  # Trigger pre-fetching

                # While the first chunk is local we still call _download on it, which
                # short circuits and just parses (for JSON batches) and then returns
                # an iterator through that data, so we expect the call count to be 5.
                # (0 local and 1, 2, 3, 4 pre-fetched) = 5 total
                start_time = time.time()
                while time.time() < start_time + 1:
                    if patched_download.call_count == 5:
                        break
                else:
                    assert patched_download.call_count == 5


@pytest.mark.skipolddriver(reason="new feature in v2.5.0")
@pytest.mark.parametrize("result_format", ["json", "arrow"])
def test_resultbatch_schema_exists_when_zero_rows(conn_cnx, result_format):
    with conn_cnx(
        session_parameters={"python_connector_query_result_format": result_format}
    ) as con:
        with con.cursor() as cur:
            cur.execute(
                "select seq4() as c1, randstr(1,random()) as c2 from table(generator(rowcount => 1)) where 1=0"
            )
            result_batches = cur.get_result_batches()
            # verify there is 1 batch and 0 rows in that batch
            assert len(result_batches) == 1
            assert result_batches[0].rowcount == 0
            # verify that the schema is correct
            schema = result_batches[0].schema
            assert schema == [
                ResultMetadata("C1", 0, None, None, 10, 0, False),
                ResultMetadata("C2", 2, None, 16777216, None, None, False),
            ]


@pytest.mark.skipolddriver
def test_optional_telemetry(conn_cnx, capture_sf_telemetry):
    """Make sure that we do not fail when _first_chunk_time is not present in cursor."""
    with conn_cnx() as con:
        with con.cursor() as cur:
            with capture_sf_telemetry.patch_connection(con, False) as telemetry:
                cur.execute("select 1;")
                cur._first_chunk_time = None
                assert cur.fetchall() == [
                    (1,),
                ]
            assert not any(
                r.message.get("type", "")
                == TelemetryField.TIME_CONSUME_LAST_RESULT.value
                for r in telemetry.records
            )


@pytest.mark.parametrize("result_format", ("json", "arrow"))
@pytest.mark.parametrize("cursor_type", (SnowflakeCursor, DictCursor))
@pytest.mark.parametrize("fetch_method", ("__next__", "fetchone"))
def test_out_of_range_year(conn_cnx, result_format, cursor_type, fetch_method):
    """Tests whether the year 10000 is out of range exception is raised as expected."""
    with conn_cnx(
        session_parameters={
            PARAMETER_PYTHON_CONNECTOR_QUERY_RESULT_FORMAT: result_format
        }
    ) as con:
        with con.cursor(cursor_type) as cur:
            cur.execute(
                "select * from VALUES (1, TO_TIMESTAMP('9999-01-01 00:00:00')), (2, TO_TIMESTAMP('10000-01-01 00:00:00'))"
            )
            iterate_obj = cur if fetch_method == "fetchone" else iter(cur)
            fetch_next_fn = getattr(iterate_obj, fetch_method)
            # first fetch doesn't raise error
            fetch_next_fn()
            with pytest.raises(
                InterfaceError,
                match="date value out of range"
                if IS_WINDOWS
                else "year 10000 is out of range",
            ):
                fetch_next_fn()


@pytest.mark.skipolddriver
def test_describe(conn_cnx):
    with conn_cnx() as con:
        with con.cursor() as cur:
            table_name = random_string(5, "test_describe_")
            # test select
            description = cur.describe(
                "select * from VALUES(1, 3.1415926, 'snow', TO_TIMESTAMP('2021-01-01 00:00:00'))"
            )
            assert description is not None
            column_types = [column[1] for column in description]
            assert constants.FIELD_ID_TO_NAME[column_types[0]] == "FIXED"
            assert constants.FIELD_ID_TO_NAME[column_types[1]] == "FIXED"
            assert constants.FIELD_ID_TO_NAME[column_types[2]] == "TEXT"
            assert "TIMESTAMP" in constants.FIELD_ID_TO_NAME[column_types[3]]
            assert len(cur.fetchall()) == 0

            # test insert
            cur.execute(f"create table {table_name} (aa int)")
            try:
                description = cur.describe(
                    "insert into {name}(aa) values({value})".format(
                        name=table_name, value="1234"
                    )
                )
                assert description[0][0] == "number of rows inserted"
                assert cur.rowcount is None
            finally:
                cur.execute(f"drop table if exists {table_name}")


@pytest.mark.skipolddriver
def test_fetch_batches_with_sessions(conn_cnx):
    rowcount = 250_000
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute(
                f"select seq4() as foo from table(generator(rowcount=>{rowcount}))"
            )

            num_batches = len(cur.get_result_batches())

            with mock.patch(
                "snowflake.connector.network.SnowflakeRestful._use_requests_session",
                side_effect=con._rest._use_requests_session,
            ) as get_session_mock:
                result = cur.fetchall()
                # all but one batch is downloaded using a session
                assert get_session_mock.call_count == num_batches - 1
                assert len(result) == rowcount


@pytest.mark.skipolddriver
def test_null_connection(conn_cnx):
    with conn_cnx() as con:
        with con.cursor() as cur:
            cur.execute_async(
                "select seq4() as c from table(generator(rowcount=>50000))"
            )
            con.rest.delete_session()
            status = con.get_query_status(cur.sfqid)
            assert status == QueryStatus.FAILED_WITH_ERROR
            assert con.is_an_error(status)


@pytest.mark.skipolddriver
def test_multi_statement_failure(conn_cnx):
    """
    This test mocks the driver version sent to Snowflake to be 2.8.1, which does not support multi-statement.
    The backend should not allow multi-statements to be submitted for versions older than 2.9.0 and should raise an
    error when a multi-statement is submitted, regardless of the MULTI_STATEMENT_COUNT parameter.
    """
    try:
        connection.DEFAULT_CONFIGURATION["internal_application_version"] = (
            "2.8.1",
            (type(None), str),
        )
        with conn_cnx() as con:
            with con.cursor() as cur:
                with pytest.raises(
                    ProgrammingError,
                    match="Multiple SQL statements in a single API call are not supported; use one API call per statement instead.",
                ):
                    cur.execute(
                        f"alter session set {PARAMETER_MULTI_STATEMENT_COUNT}=0"
                    )
                    cur.execute("select 1; select 2; select 3;")
    finally:
        connection.DEFAULT_CONFIGURATION["internal_application_version"] = (
            CLIENT_VERSION,
            (type(None), str),
        )


@pytest.mark.skipolddriver
def test_decoding_utf8_for_json_result(conn_cnx):
    # SNOW-787480, if not explicitly setting utf-8 decoding, the data will be
    # detected decoding as windows-1250 by chardet.detect
    with conn_cnx(
        session_parameters={"python_connector_query_result_format": "JSON"}
    ) as con, con.cursor() as cur:
        sql = """select '"",' || '"",' || '"",' || '"",' || '"",' || 'Ofigràfic' || '"",' from TABLE(GENERATOR(ROWCOUNT => 5000)) v;"""
        ret = cur.execute(sql).fetchall()
        assert len(ret) == 5000
        # This test case is tricky, for most of the test cases, the decoding is incorrect and can could be different
        # on different platforms, however, due to randomness, in rare cases the decoding is indeed utf-8,
        # the backend behavior is flaky
        assert ret[0] in (
            ('"","","","","",OfigrĂ\xa0fic"",',),  # AWS Cloud
            ('"","","","","",OfigrÃ\xa0fic"",',),  # GCP Mac and Linux Cloud
            ('"","","","","",Ofigr\xc3\\xa0fic"",',),  # GCP Windows Cloud
            (
                '"","","","","",Ofigràfic"",',
            ),  # regression environment gets the correct decoding
        )

    with conn_cnx(
        session_parameters={"python_connector_query_result_format": "JSON"},
        json_result_force_utf8_decoding=True,
    ) as con, con.cursor() as cur:
        ret = cur.execute(sql).fetchall()
        assert len(ret) == 5000
        assert ret[0] == ('"","","","","",Ofigràfic"",',)

    result_batch = JSONResultBatch(
        None, None, None, None, None, False, json_result_force_utf8_decoding=True
    )
    mock_resp = mock.Mock()
    mock_resp.content = "À".encode("latin1")
    with pytest.raises(Error):
        result_batch._load(mock_resp)
