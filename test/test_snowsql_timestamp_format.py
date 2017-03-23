#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
from snowflake.connector.converter_snowsql import SnowflakeConverterSnowSQL


def test_snowsql_timestamp_format(conn_cnx):
    """
    In SnowSQL, OverflowError should not happen
    """
    with conn_cnx(converter_class=SnowflakeConverterSnowSQL) as cnx:
        ret = cnx.cursor().execute("""
SELECT
    '19999-09-30 12:34:56'::timestamp_ltz,
    '19999-09-30 12:34:56'::timestamp_ntz
""").fetchone()
        assert ret[0] == 'Thu, 30 Sep 19999 19:34:56 +0000'
        assert ret[1] == 'Thu, 30 Sep 19999 12:34:56 +0000'

        # NOTE timestamp_tz doesn't accept the timestamp out of range
        # what is the range?


def test_snowsql_timestamp_negative_epoch(conn_cnx):
    with conn_cnx(converter_class=SnowflakeConverterSnowSQL) as cnx:
        cnx.cursor().execute("""
ALTER SESSION SET
    TIMEZONE='America/Los_Angeles',
    TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM';
""")
        ret = cnx.cursor().execute("""
    SELECT
        '1969-09-30 12:34:56.123456789'::timestamp_ltz(7),
        '1969-09-30 12:34:56.123456789'::timestamp_ntz(8),
        '1969-09-30 12:34:56.123456789 -08:00'::timestamp_tz(8),
        '1969-09-30 12:34:56.123456789 -08:00'::timestamp_tz(4)
    """).fetchone()
        assert ret[0] == '1969-09-30 12:34:56.123456700 -0700'
        assert ret[1] == '1969-09-30 12:34:56.123456780 '
        assert ret[2] == '1969-09-30 12:34:56.123456780 -0800'
        assert ret[3] == '1969-09-30 12:34:56.123400000 -0800'
        cnx.cursor().execute("""
ALTER SESSION SET
    TIMEZONE='America/Los_Angeles',
    TIMESTAMP_OUTPUT_FORMAT='YYYY-MM-DD HH24:MI:SS.FF TZH:TZM';
""")
        ret = cnx.cursor().execute("""
    SELECT
        '1969-09-30 12:34:56.123456789'::timestamp_ltz(7),
        '1969-09-30 12:34:56.123456789'::timestamp_ntz(8),
        '1969-09-30 12:34:56.123456789 -08:00'::timestamp_tz(8),
        '1969-09-30 12:34:56.123456789 -08:00'::timestamp_tz(4)
    """).fetchone()
        assert ret[0] == '1969-09-30 12:34:56.1234567 -0700'
        assert ret[1] == '1969-09-30 12:34:56.12345678 '
        assert ret[2] == '1969-09-30 12:34:56.12345678 -0800'
        assert ret[3] == '1969-09-30 12:34:56.1234 -0800'
