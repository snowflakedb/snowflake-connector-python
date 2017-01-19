#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import snowflake.connector
from snowflake.connector.converter_snowsql import SnowflakeConverterSnowSQL


def test_snowsql_timestamp_format(db_parameters):
    """
    In SnowSQL, OverflowError should not happen
    """
    connection = snowflake.connector.connect(
        protocol=db_parameters['protocol'],
        account=db_parameters['account'],
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        database=db_parameters['database'],
        schema=db_parameters['schema'],
        converter_class=SnowflakeConverterSnowSQL,
    )
    ret = connection.cursor().execute(
        "SELECT '19999-09-30 12:34:56'::timestamp_ltz").fetchone()
    assert ret[0] == 'Thu, 30 Sep 19999 19:34:56 +0000'

    ret = connection.cursor().execute(
        "SELECT '19999-09-30 12:34:56'::timestamp_ntz").fetchone()
    assert ret[0] == 'Thu, 30 Sep 19999 12:34:56 +0000'

    # NOTE timestamp_tz doesn't accept the timestamp out of range
    # what is the range?
