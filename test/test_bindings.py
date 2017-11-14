#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

import time
from datetime import datetime, date, timedelta
from datetime import time as datetime_time
from decimal import Decimal

import pytz

from snowflake.connector.compat import PY2
from snowflake.connector.converter import convert_datetime_to_epoch


def test_binding(conn_cnx, db_parameters):
    with conn_cnx(paramstyle=u'qmark') as cnx:
        cnx.cursor().execute("""
create or replace table {name} (
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
    c24 STRING
    )
""".format(name=db_parameters['name']))
    PST_TZ = "America/Los_Angeles"
    JST_TZ = "Asia/Tokyo"
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
    try:
        with conn_cnx(paramstyle=u'qmark', timezone=PST_TZ) as cnx:
            cnx.cursor().execute("""
insert into {name} values(
?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?, ?,?,?)
""".format(name=db_parameters['name']), (
                True,
                1,
                Decimal("1.2"),
                'str1',
                1.2,
                bytes(b'abc') if not PY2 else bytearray(b'abc'),
                bytearray(b'def'),
                current_utctime,
                current_localtime,
                current_localtime_without_tz,
                current_localtime_with_other_tz,
                (u"TIMESTAMP_LTZ", current_utctime),
                (u"TIMESTAMP_LTZ", current_localtime),
                (u"TIMESTAMP_LTZ", current_localtime_without_tz),
                (u"TIMESTAMP_LTZ", current_localtime_with_other_tz),
                (u"TIMESTAMP_TZ", current_utctime),
                (u"TIMESTAMP_TZ", current_localtime),
                (u"TIMESTAMP_TZ", current_localtime_without_tz),
                (u"TIMESTAMP_TZ", current_localtime_with_other_tz),
                dt,
                tm,
                (u"TIMESTAMP_NTZ", struct_time_v),
                (u"TIME", tdelta),
                (u"TEXT", None)
            ))
            ret = cnx.cursor().execute("""
select * from {name} where c1=? and c2=?
""".format(name=db_parameters['name']), (
                True,
                1
            )).fetchone()
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
                ret[21]) == time.mktime(struct_time_v)
            assert timedelta(seconds=ret[22].hour * 3600 + ret[22].minute * 60 +
                                     ret[22].second,
                             microseconds=ret[22].microsecond) == tdelta
            assert ret[23] is None
    finally:
        with conn_cnx() as cnx:
            cnx.cursor().execute("""
drop table if exists {name}
""".format(name=db_parameters['name']))
