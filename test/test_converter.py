#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

from datetime import datetime, timedelta, time

import pytz

from snowflake.connector.converter import (SnowflakeConverter, ZERO_EPOCH)
from snowflake.connector.converter_snowsql import (SnowflakeConverterSnowSQL)


def test_fetch_timestamps(conn_cnx):
    PST_TZ = "America/Los_Angeles"

    tzdiff = 1860 - 1440  # -07:00
    tzinfo = SnowflakeConverter._generate_tzinfo_from_tzoffset(tzdiff)

    # TIMESTAMP_TZ
    r0 = datetime.fromtimestamp(float('1325568896.123456'), tz=tzinfo)
    r1 = datetime.fromtimestamp(float('1325568896.123456'), tz=tzinfo)
    r2 = datetime.fromtimestamp(float('1325568896.123456'), tz=tzinfo)
    r3 = 1  # SNOW-28597: wrong result
    r4 = datetime.fromtimestamp(float('1325568896.12345'), tz=tzinfo)
    r5 = datetime.fromtimestamp(float('1325568896.1234'), tz=tzinfo)
    r6 = datetime.fromtimestamp(float('1325568896.123'), tz=tzinfo)
    r7 = datetime.fromtimestamp(float('1325568896.12'), tz=tzinfo)
    r8 = datetime.fromtimestamp(float('1325568896.1'), tz=tzinfo)
    r9 = datetime.fromtimestamp(float('1325568896'), tz=tzinfo)

    # TIMESTAMP_NTZ
    r10 = ZERO_EPOCH + timedelta(seconds=float('1325568896.123456'))
    r11 = ZERO_EPOCH + timedelta(seconds=float('1325568896.123456'))
    r12 = ZERO_EPOCH + timedelta(seconds=float('1325568896.123456'))
    r13 = ZERO_EPOCH + timedelta(seconds=float('1325568896.123456'))
    r14 = ZERO_EPOCH + timedelta(seconds=float('1325568896.12345'))
    r15 = ZERO_EPOCH + timedelta(seconds=float('1325568896.1234'))
    r16 = ZERO_EPOCH + timedelta(seconds=float('1325568896.123'))
    r17 = ZERO_EPOCH + timedelta(seconds=float('1325568896.12'))
    r18 = ZERO_EPOCH + timedelta(seconds=float('1325568896.1'))
    r19 = ZERO_EPOCH + timedelta(seconds=float('1325568896'))

    # TIMESTAMP_LTZ
    r20 = ZERO_EPOCH + timedelta(seconds=float('1325568896.123456'))
    r20 = pytz.utc.localize(r20, is_dst=False).astimezone(
        pytz.timezone(PST_TZ))
    r21 = ZERO_EPOCH + timedelta(seconds=float('1325568896.123456'))
    r21 = pytz.utc.localize(r21, is_dst=False).astimezone(
        pytz.timezone(PST_TZ))
    r22 = ZERO_EPOCH + timedelta(seconds=float('1325568896.123456'))
    r22 = pytz.utc.localize(r22, is_dst=False).astimezone(
        pytz.timezone(PST_TZ))
    r23 = ZERO_EPOCH + timedelta(seconds=float('1325568896.123456'))
    r23 = pytz.utc.localize(r23, is_dst=False).astimezone(
        pytz.timezone(PST_TZ))
    r24 = ZERO_EPOCH + timedelta(seconds=float('1325568896.12345'))
    r24 = pytz.utc.localize(r24, is_dst=False).astimezone(
        pytz.timezone(PST_TZ))
    r25 = ZERO_EPOCH + timedelta(seconds=float('1325568896.1234'))
    r25 = pytz.utc.localize(r25, is_dst=False).astimezone(
        pytz.timezone(PST_TZ))
    r26 = ZERO_EPOCH + timedelta(seconds=float('1325568896.123'))
    r26 = pytz.utc.localize(r26, is_dst=False).astimezone(
        pytz.timezone(PST_TZ))
    r27 = ZERO_EPOCH + timedelta(seconds=float('1325568896.12'))
    r27 = pytz.utc.localize(r27, is_dst=False).astimezone(
        pytz.timezone(PST_TZ))
    r28 = ZERO_EPOCH + timedelta(seconds=float('1325568896.1'))
    r28 = pytz.utc.localize(r28, is_dst=False).astimezone(
        pytz.timezone(PST_TZ))
    r29 = ZERO_EPOCH + timedelta(seconds=float('1325568896'))
    r29 = pytz.utc.localize(r29, is_dst=False).astimezone(
        pytz.timezone(PST_TZ))

    # TIME
    r30 = time(5, 7, 8, 123456)
    r31 = time(5, 7, 8, 123456)
    r32 = time(5, 7, 8, 123456)
    r33 = time(5, 7, 8, 123456)
    r34 = time(5, 7, 8, 123450)
    r35 = time(5, 7, 8, 123400)
    r36 = time(5, 7, 8, 123000)
    r37 = time(5, 7, 8, 120000)
    r38 = time(5, 7, 8, 100000)
    r39 = time(5, 7, 8)

    with conn_cnx() as cnx:
        cur = cnx.cursor()
        cur.execute("""
ALTER SESSION SET TIMEZONE='{tz}';
""".format(tz=PST_TZ))
        cur.execute("""
SELECT
    '2012-01-03 12:34:56.123456789+07:00'::timestamp_tz(9),
    '2012-01-03 12:34:56.12345678+07:00'::timestamp_tz(8),
    '2012-01-03 12:34:56.1234567+07:00'::timestamp_tz(7),
    1,
    -- '2012-01-03 12:34:56.123456+07:00'::timestamp_tz(6),
    '2012-01-03 12:34:56.12345+07:00'::timestamp_tz(5),
    '2012-01-03 12:34:56.1234+07:00'::timestamp_tz(4),
    '2012-01-03 12:34:56.123+07:00'::timestamp_tz(3),
    '2012-01-03 12:34:56.12+07:00'::timestamp_tz(2),
    '2012-01-03 12:34:56.1+07:00'::timestamp_tz(1),
    '2012-01-03 12:34:56+07:00'::timestamp_tz(0),
    '2012-01-03 05:34:56.123456789'::timestamp_ntz(9),
    '2012-01-03 05:34:56.12345678'::timestamp_ntz(8),
    '2012-01-03 05:34:56.1234567'::timestamp_ntz(7),
    '2012-01-03 05:34:56.123456'::timestamp_ntz(6),
    '2012-01-03 05:34:56.12345'::timestamp_ntz(5),
    '2012-01-03 05:34:56.1234'::timestamp_ntz(4),
    '2012-01-03 05:34:56.123'::timestamp_ntz(3),
    '2012-01-03 05:34:56.12'::timestamp_ntz(2),
    '2012-01-03 05:34:56.1'::timestamp_ntz(1),
    '2012-01-03 05:34:56'::timestamp_ntz(0),
    '2012-01-02 21:34:56.123456789'::timestamp_ltz(9),
    '2012-01-02 21:34:56.12345678'::timestamp_ltz(8),
    '2012-01-02 21:34:56.1234567'::timestamp_ltz(7),
    '2012-01-02 21:34:56.123456'::timestamp_ltz(6),
    '2012-01-02 21:34:56.12345'::timestamp_ltz(5),
    '2012-01-02 21:34:56.1234'::timestamp_ltz(4),
    '2012-01-02 21:34:56.123'::timestamp_ltz(3),
    '2012-01-02 21:34:56.12'::timestamp_ltz(2),
    '2012-01-02 21:34:56.1'::timestamp_ltz(1),
    '2012-01-02 21:34:56'::timestamp_ltz(0),
    '05:07:08.123456789'::time(9),
    '05:07:08.12345678'::time(8),
    '05:07:08.1234567'::time(7),
    '05:07:08.123456'::time(6),
    '05:07:08.12345'::time(5),
    '05:07:08.1234'::time(4),
    '05:07:08.123'::time(3),
    '05:07:08.12'::time(2),
    '05:07:08.1'::time(1),
    '05:07:08'::time(0)
""")
        ret = cur.fetchone()
        assert ret[0] == r0
        assert ret[1] == r1
        assert ret[2] == r2
        assert ret[3] == r3
        assert ret[4] == r4
        assert ret[5] == r5
        assert ret[6] == r6
        assert ret[7] == r7
        assert ret[8] == r8
        assert ret[9] == r9
        assert ret[10] == r10
        assert ret[11] == r11
        assert ret[12] == r12
        assert ret[13] == r13
        assert ret[14] == r14
        assert ret[15] == r15
        assert ret[16] == r16
        assert ret[17] == r17
        assert ret[18] == r18
        assert ret[19] == r19
        assert ret[20] == r20
        assert ret[21] == r21
        assert ret[22] == r22
        assert ret[23] == r23
        assert ret[24] == r24
        assert ret[25] == r25
        assert ret[26] == r26
        assert ret[27] == r27
        assert ret[28] == r28
        assert ret[29] == r29
        assert ret[30] == r30
        assert ret[31] == r31
        assert ret[32] == r32
        assert ret[33] == r33
        assert ret[34] == r34
        assert ret[35] == r35
        assert ret[36] == r36
        assert ret[37] == r37
        assert ret[38] == r38
        assert ret[39] == r39


def test_fetch_timestamps_snowsql(conn_cnx):
    PST_TZ = "America/Los_Angeles"

    converter_class = SnowflakeConverterSnowSQL
    sql = """
SELECT
    '2012-01-03 12:34:56.123456789+07:00'::timestamp_tz(9),
    '2012-01-03 12:34:56.12345678+07:00'::timestamp_tz(8),
    '2012-01-03 12:34:56.1234567+07:00'::timestamp_tz(7),
    1,
    -- '2012-01-03 12:34:56.123456+07:00'::timestamp_tz(6),
    '2012-01-03 12:34:56.12345+07:00'::timestamp_tz(5),
    '2012-01-03 12:34:56.1234+07:00'::timestamp_tz(4),
    '2012-01-03 12:34:56.123+07:00'::timestamp_tz(3),
    '2012-01-03 12:34:56.12+07:00'::timestamp_tz(2),
    '2012-01-03 12:34:56.1+07:00'::timestamp_tz(1),
    '2012-01-03 12:34:56+07:00'::timestamp_tz(0),
    '2012-01-03 05:34:56.123456789'::timestamp_ntz(9),
    '2012-01-03 05:34:56.12345678'::timestamp_ntz(8),
    '2012-01-03 05:34:56.1234567'::timestamp_ntz(7),
    '2012-01-03 05:34:56.123456'::timestamp_ntz(6),
    '2012-01-03 05:34:56.12345'::timestamp_ntz(5),
    '2012-01-03 05:34:56.1234'::timestamp_ntz(4),
    '2012-01-03 05:34:56.123'::timestamp_ntz(3),
    '2012-01-03 05:34:56.12'::timestamp_ntz(2),
    '2012-01-03 05:34:56.1'::timestamp_ntz(1),
    '2012-01-03 05:34:56'::timestamp_ntz(0),
    '2012-01-02 21:34:56.123456789'::timestamp_ltz(9),
    '2012-01-02 21:34:56.12345678'::timestamp_ltz(8),
    '2012-01-02 21:34:56.1234567'::timestamp_ltz(7),
    '2012-01-02 21:34:56.123456'::timestamp_ltz(6),
    '2012-01-02 21:34:56.12345'::timestamp_ltz(5),
    '2012-01-02 21:34:56.1234'::timestamp_ltz(4),
    '2012-01-02 21:34:56.123'::timestamp_ltz(3),
    '2012-01-02 21:34:56.12'::timestamp_ltz(2),
    '2012-01-02 21:34:56.1'::timestamp_ltz(1),
    '2012-01-02 21:34:56'::timestamp_ltz(0),
    '05:07:08.123456789'::time(9),
    '05:07:08.12345678'::time(8),
    '05:07:08.1234567'::time(7),
    '05:07:08.123456'::time(6),
    '05:07:08.12345'::time(5),
    '05:07:08.1234'::time(4),
    '05:07:08.123'::time(3),
    '05:07:08.12'::time(2),
    '05:07:08.1'::time(1),
    '05:07:08'::time(0)
"""
    with conn_cnx(converter_class=converter_class) as cnx:
        cur = cnx.cursor()
        cur.execute("""
ALTER SESSION SET TIMEZONE='{tz}';
""".format(tz=PST_TZ))
        cur.execute("""
ALTER SESSION SET
    TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM',
    TIME_OUTPUT_FORMAT='HH24:MI:SS.FF9';
        """)
        cur.execute(sql)
        ret = cur.fetchone()
        assert ret[0] == '2012-01-03 12:34:56.123456789 +0700'
        assert ret[1] == '2012-01-03 12:34:56.123456780 +0700'
        assert ret[2] == '2012-01-03 12:34:56.123456700 +0700'
        assert ret[3] == '1'
        assert ret[4] == '2012-01-03 12:34:56.123450000 +0700'
        assert ret[5] == '2012-01-03 12:34:56.123400000 +0700'
        assert ret[6] == '2012-01-03 12:34:56.123000000 +0700'
        assert ret[7] == '2012-01-03 12:34:56.120000000 +0700'
        assert ret[8] == '2012-01-03 12:34:56.100000000 +0700'
        assert ret[9] == '2012-01-03 12:34:56.000000000 +0700'
        assert ret[10] == '2012-01-03 05:34:56.123456789 '
        assert ret[11] == '2012-01-03 05:34:56.123456780 '
        assert ret[12] == '2012-01-03 05:34:56.123456700 '
        assert ret[13] == '2012-01-03 05:34:56.123456000 '
        assert ret[14] == '2012-01-03 05:34:56.123450000 '
        assert ret[15] == '2012-01-03 05:34:56.123400000 '
        assert ret[16] == '2012-01-03 05:34:56.123000000 '
        assert ret[17] == '2012-01-03 05:34:56.120000000 '
        assert ret[18] == '2012-01-03 05:34:56.100000000 '
        assert ret[19] == '2012-01-03 05:34:56.000000000 '
        assert ret[20] == '2012-01-02 21:34:56.123456789 -0800'
        assert ret[21] == '2012-01-02 21:34:56.123456780 -0800'
        assert ret[22] == '2012-01-02 21:34:56.123456700 -0800'
        assert ret[23] == '2012-01-02 21:34:56.123456000 -0800'
        assert ret[24] == '2012-01-02 21:34:56.123450000 -0800'
        assert ret[25] == '2012-01-02 21:34:56.123400000 -0800'
        assert ret[26] == '2012-01-02 21:34:56.123000000 -0800'
        assert ret[27] == '2012-01-02 21:34:56.120000000 -0800'
        assert ret[28] == '2012-01-02 21:34:56.100000000 -0800'
        assert ret[29] == '2012-01-02 21:34:56.000000000 -0800'
        assert ret[30] == '05:07:08.123456789'
        assert ret[31] == '05:07:08.123456780'
        assert ret[32] == '05:07:08.123456700'
        assert ret[33] == '05:07:08.123456000'
        assert ret[34] == '05:07:08.123450000'
        assert ret[35] == '05:07:08.123400000'
        assert ret[36] == '05:07:08.123000000'
        assert ret[37] == '05:07:08.120000000'
        assert ret[38] == '05:07:08.100000000'
        assert ret[39] == '05:07:08.000000000'

        cur.execute("""
ALTER SESSION SET
    TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF6 TZH:TZM',
    TIME_OUTPUT_FORMAT='HH24:MI:SS.FF6';
        """)
        cur.execute(sql)
        ret = cur.fetchone()
        assert ret[0] == '2012-01-03 12:34:56.123456 +0700'
        assert ret[1] == '2012-01-03 12:34:56.123456 +0700'
        assert ret[2] == '2012-01-03 12:34:56.123456 +0700'
        assert ret[3] == '1'
        assert ret[4] == '2012-01-03 12:34:56.123450 +0700'
        assert ret[5] == '2012-01-03 12:34:56.123400 +0700'
        assert ret[6] == '2012-01-03 12:34:56.123000 +0700'
        assert ret[7] == '2012-01-03 12:34:56.120000 +0700'
        assert ret[8] == '2012-01-03 12:34:56.100000 +0700'
        assert ret[9] == '2012-01-03 12:34:56.000000 +0700'
        assert ret[10] == '2012-01-03 05:34:56.123456 '
        assert ret[11] == '2012-01-03 05:34:56.123456 '
        assert ret[12] == '2012-01-03 05:34:56.123456 '
        assert ret[13] == '2012-01-03 05:34:56.123456 '
        assert ret[14] == '2012-01-03 05:34:56.123450 '
        assert ret[15] == '2012-01-03 05:34:56.123400 '
        assert ret[16] == '2012-01-03 05:34:56.123000 '
        assert ret[17] == '2012-01-03 05:34:56.120000 '
        assert ret[18] == '2012-01-03 05:34:56.100000 '
        assert ret[19] == '2012-01-03 05:34:56.000000 '
        assert ret[20] == '2012-01-02 21:34:56.123456 -0800'
        assert ret[21] == '2012-01-02 21:34:56.123456 -0800'
        assert ret[22] == '2012-01-02 21:34:56.123456 -0800'
        assert ret[23] == '2012-01-02 21:34:56.123456 -0800'
        assert ret[24] == '2012-01-02 21:34:56.123450 -0800'
        assert ret[25] == '2012-01-02 21:34:56.123400 -0800'
        assert ret[26] == '2012-01-02 21:34:56.123000 -0800'
        assert ret[27] == '2012-01-02 21:34:56.120000 -0800'
        assert ret[28] == '2012-01-02 21:34:56.100000 -0800'
        assert ret[29] == '2012-01-02 21:34:56.000000 -0800'
        assert ret[30] == '05:07:08.123456'
        assert ret[31] == '05:07:08.123456'
        assert ret[32] == '05:07:08.123456'
        assert ret[33] == '05:07:08.123456'
        assert ret[34] == '05:07:08.123450'
        assert ret[35] == '05:07:08.123400'
        assert ret[36] == '05:07:08.123000'
        assert ret[37] == '05:07:08.120000'
        assert ret[38] == '05:07:08.100000'
        assert ret[39] == '05:07:08.000000'
