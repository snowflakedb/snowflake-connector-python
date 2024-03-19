#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations

from textwrap import dedent

import pytest
try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from ..randomize import random_string

pytestmark = pytest.mark.skipolddriver  # old test driver tests won't run this module


def test_structured_array_types(conn_cnx):
    with conn_cnx() as cnx:
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
        cur.execute(sql)
        for metadata in cur.description:
            assert metadata.type_code == 10  # same as a regular array
        for metadata in cur.describe(sql):
            assert metadata.type_code == 10


def test_structured_map_types(conn_cnx):
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        sql = dedent(
            """select
            {'a': 1}::map(string, int),
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
        cur.execute(sql)
        for metadata in cur.description:
            assert metadata.type_code == 9  # same as a regular object
        for metadata in cur.describe(sql):
            assert metadata.type_code == 9


def test_structured_array_types_iceberg(conn_cnx):
    with conn_cnx() as cnx:
        cur = cnx.cursor()

        table_name = f"iceberg_test_array_{random_string(5)}"
        # Geography and geometry are not supported in an array
        # [TO_GEOGRAPHY('POINT(-122.35 37.55)'), TO_GEOGRAPHY('POINT(-123.35 37.55)')]::array(GEOGRAPHY),
        # [TO_GEOMETRY('POINT(1820.12 890.56)'), TO_GEOMETRY('POINT(1820.12 890.56)')]::array(GEOMETRY),
        cur.execute(f"""create iceberg table if not exists {table_name} (
            c1 array(int),
            c2 array(float),
            -- c3 array(string not null),
            c4 array(timestamp),
            c5 array(timestamp_ltz),
            -- c6 array(timestamp_tz),
            c7 array(timestamp_ntz),
            c8 array(date),
            c9 array(time),
            c10 array(boolean)
            -- c11 array(variant not null),
            -- c12 array(object)
            ) 
            CATALOG = 'SNOWFLAKE'
            EXTERNAL_VOLUME = 'python_connector_iceberg_exvol'
            BASE_LOCATION = 'python_connector_merge_gate';
        """)
        sql = f"select * from {table_name}"
        try:
            cur.execute(sql)
            for metadata in cur.description:
                assert metadata.type_code == 10  # same as a regular array
            for metadata in cur.describe(sql):
                assert metadata.type_code == 10
        finally:
            cur.execute(f"drop iceberg table if exists {table_name}")


def test_structured_map_types_iceberg(conn_cnx):
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        table_name = f"iceberg_test_array_{random_string(5)}"
        # Geography and geometry are not supported in an array
        # [TO_GEOGRAPHY('POINT(-122.35 37.55)'), TO_GEOGRAPHY('POINT(-123.35 37.55)')]::array(GEOGRAPHY),
        # [TO_GEOMETRY('POINT(1820.12 890.56)'), TO_GEOMETRY('POINT(1820.12 890.56)')]::array(GEOMETRY),
        cur.execute(f"""create iceberg table if not exists {table_name} (
            c1 map(string, int),
            c2 map(string, float),
            -- c3 map(string, string not null),
            c4 map(string, timestamp),
            c5 map(string, timestamp_ltz),
            c6 map(string, timestamp_ntz),
            -- c7 map(string, timestamp_tz),
            c8 map(string, date),
            c9 map(string, time),
            c10 map(string, boolean)
            -- c11 map(string, variant not null),
            -- c12 map(string, object)
            )
            CATALOG = 'SNOWFLAKE'
            EXTERNAL_VOLUME = 'python_connector_iceberg_exvol'
            BASE_LOCATION = 'python_connector_merge_gate';
        """)
        sql = f"select * from {table_name}"
        try:
            cur.execute(sql)
            for metadata in cur.description:
                assert metadata.type_code == 9  # same as a regular object
            for metadata in cur.describe(sql):
                assert metadata.type_code == 9
        finally:
            cur.execute(f"drop iceberg table if exists {table_name}")
