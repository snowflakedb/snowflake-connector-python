#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import os

import pytest

from ..integ_helpers import drop_table
from ..randomize import random_string

pytestmark = pytest.mark.parallel


def test_load_bogus_file(tmpdir, conn_cnx, request):
    """SNOW-4525: Loads Bogus file and should fail."""
    table_name = random_string(3, prefix="test_load_bogus_file_")
    with conn_cnx() as cnx:
        cnx.cursor().execute(f"""
create table {table_name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(5,2))
""")
        request.addfinalizer(drop_table(conn_cnx, table_name))
        temp_file = str(tmpdir.join('bogus_files'))
        with open(temp_file, 'wb') as random_binary_file:
            random_binary_file.write(os.urandom(1024))
        cnx.cursor().execute(
            f"put file://{temp_file} @%{table_name}")

        with cnx.cursor() as c:
            c.execute(
                f"copy into {table_name} on_error='skip_file'")
            cnt = 0
            for _rec in c:
                cnt += 1
            assert _rec[1] == "LOAD_FAILED"


def test_load_bogus_json_file(tmpdir, conn_cnx, request):
    """SNOW-4525: Loads Bogus JSON file and should fail."""
    table_name = random_string(3, prefix="test_load_bogus_json_file_")
    with conn_cnx() as cnx:
        cnx.cursor().execute(
            f"create table {table_name} (v variant)")
        request.addfinalizer(drop_table(conn_cnx, table_name))

        temp_file = str(tmpdir.join('bogus_json_files'))
        with open(temp_file, 'wb') as random_binary_file:
            random_binary_file.write(os.urandom(1024))
        cnx.cursor().execute(
            f"put file://{temp_file} @%{table_name}")

        with cnx.cursor() as c:
            c.execute(
                f"copy into {table_name} on_error='skip_file' "
                "file_format=(type='json')")
            cnt = 0
            for _rec in c:
                cnt += 1
            assert _rec[1] == "LOAD_FAILED"
