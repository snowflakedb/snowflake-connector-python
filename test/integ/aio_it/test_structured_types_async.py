#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations

from textwrap import dedent

import pytest


async def test_structured_array_types(conn_cnx):
    async with conn_cnx() as cnx:
        cur = cnx.cursor()
        sql = dedent(
            """select
            [1, 2]::array(int),
            [1.1::float, 1.2::float]::array(float),
            ['a', 'b']::array(string not null),
            [current_timestamp(), current_timestamp()]::array(timestamp),
            [current_timestamp()::timestamp_ltz, current_timestamp()::timestamp_ltz]::array(timestamp_ltz),
            [current_timestamp()::timestamp_tz, current_timestamp()::timestamp_tz]::array(timestamp_tz),
            [current_timestamp()::timestamp_ntz, current_timestamp()::timestamp_ntz]::array(timestamp_ntz),
            [current_date(), current_date()]::array(date),
            [current_time(), current_time()]::array(time),
            [True, False]::array(boolean),
            [1::variant, 'b'::variant]::array(variant not null),
            [{'a': 'b'}, {'c': 1}]::array(object)
            """
        )
        # Geography and geometry are not supported in an array
        # [TO_GEOGRAPHY('POINT(-122.35 37.55)'), TO_GEOGRAPHY('POINT(-123.35 37.55)')]::array(GEOGRAPHY),
        # [TO_GEOMETRY('POINT(1820.12 890.56)'), TO_GEOMETRY('POINT(1820.12 890.56)')]::array(GEOMETRY),
        await cur.execute(sql)
        for metadata in cur.description:
            assert metadata.type_code == 10  # same as a regular array
        for metadata in await cur.describe(sql):
            assert metadata.type_code == 10


@pytest.mark.xfail(
    reason="SNOW-1305289: Param difference in aws environment", strict=False
)
async def test_structured_map_types(conn_cnx):
    async with conn_cnx() as cnx:
        cur = cnx.cursor()
        sql = dedent(
            """select
            {'a': 1}::map(string, variant),
            {'a': 1.1::float}::map(string, float),
            {'a': 'b'}::map(string, string),
            {'a': current_timestamp()}::map(string, timestamp),
            {'a': current_timestamp()::timestamp_ltz}::map(string, timestamp_ltz),
            {'a': current_timestamp()::timestamp_ntz}::map(string, timestamp_ntz),
            {'a': current_timestamp()::timestamp_tz}::map(string, timestamp_tz),
            {'a': current_date()}::map(string, date),
            {'a': current_time()}::map(string, time),
            {'a': False}::map(string, boolean),
            {'a': 'b'::variant}::map(string, variant not null),
            {'a': {'c': 1}}::map(string, object)
            """
        )
        await cur.execute(sql)
        for metadata in cur.description:
            assert metadata.type_code == 9  # same as a regular object
        for metadata in await cur.describe(sql):
            assert metadata.type_code == 9
