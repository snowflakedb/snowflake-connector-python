#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from datetime import time, timedelta

import pytest
import pytz

from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.converter import ZERO_EPOCH, _generate_tzinfo_from_tzoffset
from snowflake.connector.converter_snowsql import SnowflakeConverterSnowSQL


def _compose_tz(dt, tzinfo):
    ret = ZERO_EPOCH + timedelta(seconds=float(dt))
    ret += tzinfo.utcoffset(ret)
    return ret.replace(tzinfo=tzinfo)


def _compose_ntz(dt):
    return ZERO_EPOCH + timedelta(seconds=float(dt))


def _compose_ltz(dt, tz):
    ret = ZERO_EPOCH + timedelta(seconds=float(dt))
    return pytz.utc.localize(ret).astimezone(pytz.timezone(tz))


def test_fetch_timestamps(conn_cnx):
    PST_TZ = "America/Los_Angeles"

    tzdiff = 1860 - 1440  # -07:00
    tzinfo = _generate_tzinfo_from_tzoffset(tzdiff)

    # TIMESTAMP_TZ
    r0 = _compose_tz("1325568896.123456", tzinfo)
    r1 = _compose_tz("1325568896.123456", tzinfo)
    r2 = _compose_tz("1325568896.123456", tzinfo)
    r3 = _compose_tz("1325568896.123456", tzinfo)
    r4 = _compose_tz("1325568896.12345", tzinfo)
    r5 = _compose_tz("1325568896.1234", tzinfo)
    r6 = _compose_tz("1325568896.123", tzinfo)
    r7 = _compose_tz("1325568896.12", tzinfo)
    r8 = _compose_tz("1325568896.1", tzinfo)
    r9 = _compose_tz("1325568896", tzinfo)

    # TIMESTAMP_NTZ
    r10 = _compose_ntz("1325568896.123456")
    r11 = _compose_ntz("1325568896.123456")
    r12 = _compose_ntz("1325568896.123456")
    r13 = _compose_ntz("1325568896.123456")
    r14 = _compose_ntz("1325568896.12345")
    r15 = _compose_ntz("1325568896.1234")
    r16 = _compose_ntz("1325568896.123")
    r17 = _compose_ntz("1325568896.12")
    r18 = _compose_ntz("1325568896.1")
    r19 = _compose_ntz("1325568896")

    # TIMESTAMP_LTZ
    r20 = _compose_ltz("1325568896.123456", PST_TZ)
    r21 = _compose_ltz("1325568896.123456", PST_TZ)
    r22 = _compose_ltz("1325568896.123456", PST_TZ)
    r23 = _compose_ltz("1325568896.123456", PST_TZ)
    r24 = _compose_ltz("1325568896.12345", PST_TZ)
    r25 = _compose_ltz("1325568896.1234", PST_TZ)
    r26 = _compose_ltz("1325568896.123", PST_TZ)
    r27 = _compose_ltz("1325568896.12", PST_TZ)
    r28 = _compose_ltz("1325568896.1", PST_TZ)
    r29 = _compose_ltz("1325568896", PST_TZ)

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
        cur.execute(
            """
ALTER SESSION SET TIMEZONE='{tz}';
""".format(
                tz=PST_TZ
            )
        )
        cur.execute(
            """
SELECT
    '2012-01-03 12:34:56.123456789+07:00'::timestamp_tz(9),
    '2012-01-03 12:34:56.12345678+07:00'::timestamp_tz(8),
    '2012-01-03 12:34:56.1234567+07:00'::timestamp_tz(7),
    '2012-01-03 12:34:56.123456+07:00'::timestamp_tz(6),
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
        )
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
    '2012-01-03 12:34:56.123456+07:00'::timestamp_tz(6),
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
        cur.execute(
            """
alter session set python_connector_query_result_format='JSON'
"""
        )
        cur.execute(
            """
ALTER SESSION SET TIMEZONE='{tz}';
""".format(
                tz=PST_TZ
            )
        )
        cur.execute(
            """
ALTER SESSION SET
    TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM',
    TIMESTAMP_NTZ_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM',
    TIME_OUTPUT_FORMAT='HH24:MI:SS.FF9';
        """
        )
        cur.execute(sql)
        ret = cur.fetchone()
        assert ret[0] == "2012-01-03 12:34:56.123456789 +0700"
        assert ret[1] == "2012-01-03 12:34:56.123456780 +0700"
        assert ret[2] == "2012-01-03 12:34:56.123456700 +0700"
        assert ret[3] == "2012-01-03 12:34:56.123456000 +0700"
        assert ret[4] == "2012-01-03 12:34:56.123450000 +0700"
        assert ret[5] == "2012-01-03 12:34:56.123400000 +0700"
        assert ret[6] == "2012-01-03 12:34:56.123000000 +0700"
        assert ret[7] == "2012-01-03 12:34:56.120000000 +0700"
        assert ret[8] == "2012-01-03 12:34:56.100000000 +0700"
        assert ret[9] == "2012-01-03 12:34:56.000000000 +0700"
        assert ret[10] == "2012-01-03 05:34:56.123456789 "
        assert ret[11] == "2012-01-03 05:34:56.123456780 "
        assert ret[12] == "2012-01-03 05:34:56.123456700 "
        assert ret[13] == "2012-01-03 05:34:56.123456000 "
        assert ret[14] == "2012-01-03 05:34:56.123450000 "
        assert ret[15] == "2012-01-03 05:34:56.123400000 "
        assert ret[16] == "2012-01-03 05:34:56.123000000 "
        assert ret[17] == "2012-01-03 05:34:56.120000000 "
        assert ret[18] == "2012-01-03 05:34:56.100000000 "
        assert ret[19] == "2012-01-03 05:34:56.000000000 "
        assert ret[20] == "2012-01-02 21:34:56.123456789 -0800"
        assert ret[21] == "2012-01-02 21:34:56.123456780 -0800"
        assert ret[22] == "2012-01-02 21:34:56.123456700 -0800"
        assert ret[23] == "2012-01-02 21:34:56.123456000 -0800"
        assert ret[24] == "2012-01-02 21:34:56.123450000 -0800"
        assert ret[25] == "2012-01-02 21:34:56.123400000 -0800"
        assert ret[26] == "2012-01-02 21:34:56.123000000 -0800"
        assert ret[27] == "2012-01-02 21:34:56.120000000 -0800"
        assert ret[28] == "2012-01-02 21:34:56.100000000 -0800"
        assert ret[29] == "2012-01-02 21:34:56.000000000 -0800"
        assert ret[30] == "05:07:08.123456789"
        assert ret[31] == "05:07:08.123456780"
        assert ret[32] == "05:07:08.123456700"
        assert ret[33] == "05:07:08.123456000"
        assert ret[34] == "05:07:08.123450000"
        assert ret[35] == "05:07:08.123400000"
        assert ret[36] == "05:07:08.123000000"
        assert ret[37] == "05:07:08.120000000"
        assert ret[38] == "05:07:08.100000000"
        assert ret[39] == "05:07:08.000000000"

        cur.execute(
            """
ALTER SESSION SET
    TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF6 TZH:TZM',
    TIMESTAMP_NTZ_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF6 TZH:TZM',
    TIME_OUTPUT_FORMAT='HH24:MI:SS.FF6';
        """
        )
        cur.execute(sql)
        ret = cur.fetchone()
        assert ret[0] == "2012-01-03 12:34:56.123456 +0700"
        assert ret[1] == "2012-01-03 12:34:56.123456 +0700"
        assert ret[2] == "2012-01-03 12:34:56.123456 +0700"
        assert ret[3] == "2012-01-03 12:34:56.123456 +0700"
        assert ret[4] == "2012-01-03 12:34:56.123450 +0700"
        assert ret[5] == "2012-01-03 12:34:56.123400 +0700"
        assert ret[6] == "2012-01-03 12:34:56.123000 +0700"
        assert ret[7] == "2012-01-03 12:34:56.120000 +0700"
        assert ret[8] == "2012-01-03 12:34:56.100000 +0700"
        assert ret[9] == "2012-01-03 12:34:56.000000 +0700"
        assert ret[10] == "2012-01-03 05:34:56.123456 "
        assert ret[11] == "2012-01-03 05:34:56.123456 "
        assert ret[12] == "2012-01-03 05:34:56.123456 "
        assert ret[13] == "2012-01-03 05:34:56.123456 "
        assert ret[14] == "2012-01-03 05:34:56.123450 "
        assert ret[15] == "2012-01-03 05:34:56.123400 "
        assert ret[16] == "2012-01-03 05:34:56.123000 "
        assert ret[17] == "2012-01-03 05:34:56.120000 "
        assert ret[18] == "2012-01-03 05:34:56.100000 "
        assert ret[19] == "2012-01-03 05:34:56.000000 "
        assert ret[20] == "2012-01-02 21:34:56.123456 -0800"
        assert ret[21] == "2012-01-02 21:34:56.123456 -0800"
        assert ret[22] == "2012-01-02 21:34:56.123456 -0800"
        assert ret[23] == "2012-01-02 21:34:56.123456 -0800"
        assert ret[24] == "2012-01-02 21:34:56.123450 -0800"
        assert ret[25] == "2012-01-02 21:34:56.123400 -0800"
        assert ret[26] == "2012-01-02 21:34:56.123000 -0800"
        assert ret[27] == "2012-01-02 21:34:56.120000 -0800"
        assert ret[28] == "2012-01-02 21:34:56.100000 -0800"
        assert ret[29] == "2012-01-02 21:34:56.000000 -0800"
        assert ret[30] == "05:07:08.123456"
        assert ret[31] == "05:07:08.123456"
        assert ret[32] == "05:07:08.123456"
        assert ret[33] == "05:07:08.123456"
        assert ret[34] == "05:07:08.123450"
        assert ret[35] == "05:07:08.123400"
        assert ret[36] == "05:07:08.123000"
        assert ret[37] == "05:07:08.120000"
        assert ret[38] == "05:07:08.100000"
        assert ret[39] == "05:07:08.000000"


def test_fetch_timestamps_negative_epoch(conn_cnx):
    """Negative epoch."""
    r0 = _compose_ntz("-602594703.876544")
    r1 = _compose_ntz("1325594096.123456")
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        cur.execute(
            """
SELECT
    '1950-11-27 12:34:56.123456'::timestamp_ntz(6),
    '2012-01-03 12:34:56.123456'::timestamp_ntz(6)
"""
        )
        ret = cur.fetchone()
        assert ret[0] == r0
        assert ret[1] == r1


def test_date_0001_9999(conn_cnx):
    """Test 0001 and 9999 for all platforms."""
    with conn_cnx(
        converter_class=SnowflakeConverterSnowSQL, support_negative_year=True
    ) as cnx:
        cnx.cursor().execute(
            """
ALTER SESSION SET
    DATE_OUTPUT_FORMAT='YYYY-MM-DD'
"""
        )
        cur = cnx.cursor()
        cur.execute(
            """
alter session set python_connector_query_result_format='JSON'
"""
        )
        cur.execute(
            """
SELECT
    DATE_FROM_PARTS(1900, 1, 1),
    DATE_FROM_PARTS(2500, 2, 3),
    DATE_FROM_PARTS(1, 10, 31),
    DATE_FROM_PARTS(9999, 3, 20)
    ;
"""
        )
        ret = cur.fetchone()
        assert ret[0] == "1900-01-01"
        assert ret[1] == "2500-02-03"
        assert ret[2] == "0001-10-31"
        assert ret[3] == "9999-03-20"


@pytest.mark.skipif(IS_WINDOWS, reason="year out of range error")
def test_five_or_more_digit_year_date_converter(conn_cnx):
    """Past and future dates."""
    with conn_cnx(
        converter_class=SnowflakeConverterSnowSQL, support_negative_year=True
    ) as cnx:
        cnx.cursor().execute(
            """
ALTER SESSION SET
    DATE_OUTPUT_FORMAT='YYYY-MM-DD'
"""
        )
        cur = cnx.cursor()
        cur.execute(
            """
alter session set python_connector_query_result_format='JSON'
"""
        )
        cur.execute(
            """
SELECT
    DATE_FROM_PARTS(10000, 1, 1),
    DATE_FROM_PARTS(-0001, 2, 5),
    DATE_FROM_PARTS(56789, 3, 4),
    DATE_FROM_PARTS(198765, 4, 3),
    DATE_FROM_PARTS(-234567, 5, 2)
    ;
"""
        )
        ret = cur.fetchone()
        assert ret[0] == "10000-01-01"
        assert ret[1] == "-0001-02-05"
        assert ret[2] == "56789-03-04"
        assert ret[3] == "198765-04-03"
        assert ret[4] == "-234567-05-02"

        cnx.cursor().execute(
            """
ALTER SESSION SET
    DATE_OUTPUT_FORMAT='YY-MM-DD'
"""
        )
        cur = cnx.cursor()
        cur.execute(
            """
SELECT
    DATE_FROM_PARTS(10000, 1, 1),
    DATE_FROM_PARTS(-0001, 2, 5),
    DATE_FROM_PARTS(56789, 3, 4),
    DATE_FROM_PARTS(198765, 4, 3),
    DATE_FROM_PARTS(-234567, 5, 2)
    ;
"""
        )
        ret = cur.fetchone()
        assert ret[0] == "00-01-01"
        assert ret[1] == "-01-02-05"
        assert ret[2] == "89-03-04"
        assert ret[3] == "65-04-03"
        assert ret[4] == "-67-05-02"


def test_franction_followed_by_year_format(conn_cnx):
    """Both year and franctions are included but fraction shows up followed by year."""
    with conn_cnx(converter_class=SnowflakeConverterSnowSQL) as cnx:
        cnx.cursor().execute(
            """
alter session set python_connector_query_result_format='JSON'
"""
        )
        cnx.cursor().execute(
            """
ALTER SESSION SET
    TIMESTAMP_OUTPUT_FORMAT='HH24:MI:SS.FF6 MON DD, YYYY',
    TIMESTAMP_NTZ_OUTPUT_FORMAT='HH24:MI:SS.FF6 MON DD, YYYY'
"""
        )
        for rec in cnx.cursor().execute(
            """
SELECT
    '2012-01-03 05:34:56.123456'::TIMESTAMP_NTZ(6)
"""
        ):
            assert rec[0] == "05:34:56.123456 Jan 03, 2012"


def test_fetch_fraction_timestamp(conn_cnx):
    """Additional fetch timestamp tests. Mainly used for SnowSQL which converts to string representations."""
    PST_TZ = "America/Los_Angeles"

    converter_class = SnowflakeConverterSnowSQL
    sql = """
SELECT
    '1900-01-01T05:00:00.000Z'::timestamp_tz(7),
    '1900-01-01T05:00:00.000'::timestamp_ntz(7),
    '1900-01-01T05:00:01.000Z'::timestamp_tz(7),
    '1900-01-01T05:00:01.000'::timestamp_ntz(7),
    '1900-01-01T05:00:01.012Z'::timestamp_tz(7),
    '1900-01-01T05:00:01.012'::timestamp_ntz(7),
    '1900-01-01T05:00:00.012Z'::timestamp_tz(7),
    '1900-01-01T05:00:00.012'::timestamp_ntz(7),
    '2100-01-01T05:00:00.012Z'::timestamp_tz(7),
    '2100-01-01T05:00:00.012'::timestamp_ntz(7),
    '1970-01-01T00:00:00Z'::timestamp_tz(7),
    '1970-01-01T00:00:00'::timestamp_ntz(7)
"""
    with conn_cnx(converter_class=converter_class) as cnx:
        cur = cnx.cursor()
        cur.execute(
            """
alter session set python_connector_query_result_format='JSON'
"""
        )
        cur.execute(
            """
ALTER SESSION SET TIMEZONE='{tz}';
""".format(
                tz=PST_TZ
            )
        )
        cur.execute(
            """
ALTER SESSION SET
    TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM',
    TIMESTAMP_NTZ_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF9',
    TIME_OUTPUT_FORMAT='HH24:MI:SS.FF9';
        """
        )
        cur.execute(sql)
        ret = cur.fetchone()
        assert ret[0] == "1900-01-01 05:00:00.000000000 +0000"
        assert ret[1] == "1900-01-01 05:00:00.000000000"
        assert ret[2] == "1900-01-01 05:00:01.000000000 +0000"
        assert ret[3] == "1900-01-01 05:00:01.000000000"
        assert ret[4] == "1900-01-01 05:00:01.012000000 +0000"
        assert ret[5] == "1900-01-01 05:00:01.012000000"
        assert ret[6] == "1900-01-01 05:00:00.012000000 +0000"
        assert ret[7] == "1900-01-01 05:00:00.012000000"
        assert ret[8] == "2100-01-01 05:00:00.012000000 +0000"
        assert ret[9] == "2100-01-01 05:00:00.012000000"
        assert ret[10] == "1970-01-01 00:00:00.000000000 +0000"
        assert ret[11] == "1970-01-01 00:00:00.000000000"
