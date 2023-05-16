#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import calendar
import tempfile
import time
from datetime import date, datetime
from datetime import time as datetime_time
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

import pendulum
import pytest
import pytz

from snowflake.connector.converter import convert_datetime_to_epoch
from snowflake.connector.errors import ForbiddenError, ProgrammingError

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from ..randomize import random_string

tempfile.gettempdir()

PST_TZ = "America/Los_Angeles"
JST_TZ = "Asia/Tokyo"
CLIENT_STAGE_ARRAY_BINDING_THRESHOLD = "CLIENT_STAGE_ARRAY_BINDING_THRESHOLD"


def test_invalid_binding_option(conn_cnx):
    """Invalid paramstyle parameters."""
    with pytest.raises(ProgrammingError):
        with conn_cnx(paramstyle="hahaha"):
            pass

    # valid cases
    for s in ["format", "pyformat", "qmark", "numeric"]:
        with conn_cnx(paramstyle=s):
            pass


@pytest.mark.parametrize(
    "bulk_array_optimization",
    [pytest.param(True, marks=pytest.mark.skipolddriver), False],
)
def test_binding(conn_cnx, db_parameters, bulk_array_optimization):
    """Paramstyle qmark binding tests to cover basic data types."""
    CREATE_TABLE = """create or replace table {name} (
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
    """
    INSERT = """
insert into {name} values(
?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?,?,?)
"""
    with conn_cnx(paramstyle="qmark") as cnx:
        cnx.cursor().execute(CREATE_TABLE.format(name=db_parameters["name"]))
    current_utctime = datetime.utcnow()
    current_localtime = pytz.utc.localize(current_utctime, is_dst=False).astimezone(
        pytz.timezone(PST_TZ)
    )
    current_localtime_without_tz = datetime.now()
    current_localtime_with_other_tz = pytz.utc.localize(
        current_localtime_without_tz, is_dst=False
    ).astimezone(pytz.timezone(JST_TZ))
    dt = date(2017, 12, 30)
    tm = datetime_time(hour=1, minute=2, second=3, microsecond=456)
    struct_time_v = time.strptime("30 Sep 01 11:20:30", "%d %b %y %H:%M:%S")
    tdelta = timedelta(
        seconds=tm.hour * 3600 + tm.minute * 60 + tm.second, microseconds=tm.microsecond
    )
    data = (
        True,
        1,
        Decimal("1.2"),
        "str1",
        1.2,
        # Py2 has bytes in str type, so Python Connector
        b"abc",
        bytearray(b"def"),
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
        ',an\\\\escaped"line\n',
    )
    try:
        with conn_cnx(paramstyle="qmark", timezone=PST_TZ) as cnx:
            csr = cnx.cursor()
            if bulk_array_optimization:
                cnx._session_parameters[CLIENT_STAGE_ARRAY_BINDING_THRESHOLD] = 1
                csr.executemany(INSERT.format(name=db_parameters["name"]), [data])
            else:
                csr.execute(INSERT.format(name=db_parameters["name"]), data)

            ret = (
                cnx.cursor()
                .execute(
                    """
select * from {name} where c1=? and c2=?
""".format(
                        name=db_parameters["name"]
                    ),
                    (True, 1),
                )
                .fetchone()
            )
            assert len(ret) == 26
            assert ret[0], "BOOLEAN"
            assert ret[2] == Decimal("1.2"), "NUMBER"
            assert ret[4] == 1.2, "FLOAT"
            assert ret[5] == b"abc"
            assert ret[6] == b"def"
            assert ret[7] == current_utctime
            assert convert_datetime_to_epoch(ret[8]) == convert_datetime_to_epoch(
                current_localtime
            )
            assert convert_datetime_to_epoch(ret[9]) == convert_datetime_to_epoch(
                current_localtime_without_tz
            )
            assert convert_datetime_to_epoch(ret[10]) == convert_datetime_to_epoch(
                current_localtime_with_other_tz
            )
            assert convert_datetime_to_epoch(ret[11]) == convert_datetime_to_epoch(
                current_utctime
            )
            assert convert_datetime_to_epoch(ret[12]) == convert_datetime_to_epoch(
                current_localtime
            )
            assert convert_datetime_to_epoch(ret[13]) == convert_datetime_to_epoch(
                current_localtime_without_tz
            )
            assert convert_datetime_to_epoch(ret[14]) == convert_datetime_to_epoch(
                current_localtime_with_other_tz
            )
            assert convert_datetime_to_epoch(ret[15]) == convert_datetime_to_epoch(
                current_utctime
            )
            assert convert_datetime_to_epoch(ret[16]) == convert_datetime_to_epoch(
                current_localtime
            )
            assert convert_datetime_to_epoch(ret[17]) == convert_datetime_to_epoch(
                current_localtime_without_tz
            )
            assert convert_datetime_to_epoch(ret[18]) == convert_datetime_to_epoch(
                current_localtime_with_other_tz
            )
            assert ret[19] == dt
            assert ret[20] == tm
            assert convert_datetime_to_epoch(ret[21]) == calendar.timegm(struct_time_v)
            assert (
                timedelta(
                    seconds=ret[22].hour * 3600 + ret[22].minute * 60 + ret[22].second,
                    microseconds=ret[22].microsecond,
                )
                == tdelta
            )
            assert ret[23] is None
            assert ret[24] == ""
            assert ret[25] == ',an\\\\escaped"line\n'
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
drop table if exists {name}
""".format(
                    name=db_parameters["name"]
                )
            )


def test_pendulum_binding(conn_cnx, db_parameters):
    pendulum_test = pendulum.now()
    try:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
    create or replace table {name} (
        c1 timestamp
    )
    """.format(
                    name=db_parameters["name"]
                )
            )
            c = cnx.cursor()
            fmt = "insert into {name}(c1) values(%(v1)s)".format(
                name=db_parameters["name"]
            )
            c.execute(fmt, {"v1": pendulum_test})
            assert (
                len(
                    cnx.cursor()
                    .execute(
                        "select count(*) from {name}".format(name=db_parameters["name"])
                    )
                    .fetchall()
                )
                == 1
            )
        with conn_cnx(paramstyle="qmark") as cnx:
            cnx.cursor().execute(
                """
            create or replace table {name} (c1 timestamp, c2 timestamp)
    """.format(
                    name=db_parameters["name"]
                )
            )
        with conn_cnx(paramstyle="qmark") as cnx:
            cnx.cursor().execute(
                """
            insert into {name} values(?, ?)
            """.format(
                    name=db_parameters["name"]
                ),
                (pendulum_test, pendulum_test),
            )
            ret = (
                cnx.cursor()
                .execute(
                    """
            select * from {name}
            """.format(
                        name=db_parameters["name"]
                    )
                )
                .fetchone()
            )
            assert convert_datetime_to_epoch(ret[0]) == convert_datetime_to_epoch(
                pendulum_test
            )
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
    drop table if exists {name}
    """.format(
                    name=db_parameters["name"]
                )
            )


def test_binding_with_numeric(conn_cnx, db_parameters):
    """Paramstyle numeric tests. Both qmark and numeric leverages server side bindings."""
    with conn_cnx(paramstyle="numeric") as cnx:
        cnx.cursor().execute(
            """
create or replace table {name} (c1 integer, c2 string)
""".format(
                name=db_parameters["name"]
            )
        )

    try:
        with conn_cnx(paramstyle="numeric") as cnx:
            cnx.cursor().execute(
                """
insert into {name}(c1, c2) values(:2, :1)
            """.format(
                    name=db_parameters["name"]
                ),
                ("str1", 123),
            )
            cnx.cursor().execute(
                """
insert into {name}(c1, c2) values(:2, :1)
            """.format(
                    name=db_parameters["name"]
                ),
                ("str2", 456),
            )
            # numeric and qmark can be used in the same session
            rec = (
                cnx.cursor()
                .execute(
                    """
select * from {name} where c1=?
""".format(
                        name=db_parameters["name"]
                    ),
                    (123,),
                )
                .fetchall()
            )
            assert len(rec) == 1
            assert rec[0][0] == 123
            assert rec[0][1] == "str1"
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
drop table if exists {name}
""".format(
                    name=db_parameters["name"]
                )
            )


def test_binding_timestamps(conn_cnx, db_parameters):
    """Binding datetime object with TIMESTAMP_LTZ.

    The value is bound as TIMESTAMP_NTZ, but since it is converted to UTC in the backend,
    the returned value must be ???.
    """
    with conn_cnx() as cnx:
        cnx.cursor().execute(
            """
create or replace table {name} (
    c1 integer,
    c2 timestamp_ltz)
""".format(
                name=db_parameters["name"]
            )
        )

    try:
        with conn_cnx(paramstyle="numeric", timezone=PST_TZ) as cnx:
            current_localtime = datetime.now()
            cnx.cursor().execute(
                """
insert into {name}(c1, c2) values(:1, :2)
            """.format(
                    name=db_parameters["name"]
                ),
                (123, ("TIMESTAMP_LTZ", current_localtime)),
            )
            rec = (
                cnx.cursor()
                .execute(
                    """
select * from {name} where c1=?
            """.format(
                        name=db_parameters["name"]
                    ),
                    (123,),
                )
                .fetchall()
            )
            assert len(rec) == 1
            assert rec[0][0] == 123
            assert convert_datetime_to_epoch(rec[0][1]) == convert_datetime_to_epoch(
                current_localtime
            )
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
drop table if exists {name}
""".format(
                    name=db_parameters["name"]
                )
            )


@pytest.mark.parametrize(
    "num_rows", [pytest.param(100000, marks=pytest.mark.skipolddriver), 4]
)
def test_binding_bulk_insert(conn_cnx, db_parameters, num_rows):
    """Bulk insert test."""
    with conn_cnx() as cnx:
        cnx.cursor().execute(
            """
create or replace table {name} (
    c1 integer,
    c2 string
)
""".format(
                name=db_parameters["name"]
            )
        )
    try:
        with conn_cnx(paramstyle="qmark") as cnx:
            c = cnx.cursor()
            fmt = "insert into {name}(c1,c2) values(?,?)".format(
                name=db_parameters["name"]
            )
            c.executemany(fmt, [(idx, f"test{idx}") for idx in range(num_rows)])
            assert c.rowcount == num_rows
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
drop table if exists {name}
""".format(
                    name=db_parameters["name"]
                )
            )


@pytest.mark.skipolddriver
def test_binding_bulk_insert_date(conn_cnx, db_parameters):
    """Bulk insert test."""
    with conn_cnx() as cnx:
        cnx.cursor().execute(
            """
create or replace table {name} (
    c1 date
)
""".format(
                name=db_parameters["name"]
            )
        )
    try:
        with conn_cnx(paramstyle="qmark") as cnx:
            c = cnx.cursor()
            cnx._session_parameters[CLIENT_STAGE_ARRAY_BINDING_THRESHOLD] = 1
            dates = [
                [date.fromisoformat("1750-05-09")],
                [date.fromisoformat("1969-12-31")],
                [date.fromisoformat("1970-01-01")],
                [date.fromisoformat("2023-05-12")],
                [date.fromisoformat("2999-12-31")],
                [date.fromisoformat("3000-12-31")],
                [date.fromisoformat("9999-12-31")],
            ]
            c.executemany(f'INSERT INTO {db_parameters["name"]}(c1) VALUES (?)', dates)
            assert c.rowcount == len(dates)
            ret = c.execute(f'SELECT c1 from {db_parameters["name"]}').fetchall()
            assert ret == [
                (date(1750, 5, 9),),
                (date(1969, 12, 31),),
                (date(1970, 1, 1),),
                (date(2023, 5, 12),),
                (date(2999, 12, 31),),
                (date(3000, 12, 31),),
                (date(9999, 12, 31),),
            ]
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
drop table if exists {name}
""".format(
                    name=db_parameters["name"]
                )
            )


@pytest.mark.skipolddriver
def test_bulk_insert_binding_fallback(conn_cnx):
    """When stage creation fails, bulk inserts falls back to server side binding and disables stage optimization."""
    with conn_cnx(paramstyle="qmark") as cnx, cnx.cursor() as csr:
        query = f"insert into {random_string(5)}(c1,c2) values(?,?)"
        cnx._session_parameters[CLIENT_STAGE_ARRAY_BINDING_THRESHOLD] = 1
        with patch.object(csr, "_execute_helper") as mocked_execute_helper, patch(
            "snowflake.connector.cursor.BindUploadAgent._create_stage"
        ) as mocked_stage_creation:
            mocked_stage_creation.side_effect = ForbiddenError
            csr.executemany(query, [(idx, f"test{idx}") for idx in range(4)])
        mocked_stage_creation.assert_called_once()
        mocked_execute_helper.assert_called_once()
        assert (
            "binding_stage" not in mocked_execute_helper.call_args[1]
        ), "Stage binding should fail"
        assert (
            "binding_params" in mocked_execute_helper.call_args[1]
        ), "Should fall back to server side binding"
        assert cnx._session_parameters[CLIENT_STAGE_ARRAY_BINDING_THRESHOLD] == 0


def test_binding_bulk_update(conn_cnx, db_parameters):
    """Bulk update test.

    Notes:
        UPDATE,MERGE and DELETE are not supported for actual bulk operation
        but executemany accepts the multiple rows and iterate DMLs.
    """
    with conn_cnx() as cnx:
        cnx.cursor().execute(
            """
create or replace table {name} (
    c1 integer,
    c2 string
)
""".format(
                name=db_parameters["name"]
            )
        )
    try:
        with conn_cnx(paramstyle="qmark") as cnx:
            # short list
            c = cnx.cursor()
            fmt = "insert into {name}(c1,c2) values(?,?)".format(
                name=db_parameters["name"]
            )
            c.executemany(
                fmt,
                [
                    (1, "test1"),
                    (2, "test2"),
                    (3, "test3"),
                    (4, "test4"),
                ],
            )
            assert c.rowcount == 4

            fmt = "update {name} set c2=:2 where c1=:1".format(
                name=db_parameters["name"]
            )
            c.executemany(
                fmt,
                [
                    (1, "test5"),
                    (2, "test6"),
                ],
            )
            assert c.rowcount == 2

            fmt = "select * from {name} where c1=?".format(name=db_parameters["name"])
            rec = cnx.cursor().execute(fmt, (1,)).fetchall()
            assert rec[0][0] == 1
            assert rec[0][1] == "test5"

    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute(
                """
drop table if exists {name}
""".format(
                    name=db_parameters["name"]
                )
            )


def test_binding_identifier(conn_cnx, db_parameters):
    """Binding a table name."""
    try:
        with conn_cnx(paramstyle="qmark") as cnx:
            data = "test"
            cnx.cursor().execute(
                """
create or replace table identifier(?) (c1 string)
""",
                (db_parameters["name"],),
            )
        with conn_cnx(paramstyle="qmark") as cnx:
            cnx.cursor().execute(
                """
insert into identifier(?) values(?)
""",
                (db_parameters["name"], data),
            )
            ret = (
                cnx.cursor()
                .execute(
                    """
select * from identifier(?)
""",
                    (db_parameters["name"],),
                )
                .fetchall()
            )
            assert len(ret) == 1
            assert ret[0][0] == data
    finally:
        with conn_cnx(paramstyle="qmark") as cnx:
            cnx.cursor().execute(
                """
drop table if exists identifier(?)
""",
                (db_parameters["name"],),
            )
