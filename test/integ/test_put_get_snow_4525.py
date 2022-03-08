#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os
import pathlib


def test_load_bogus_file(tmp_path: pathlib.Path, conn_cnx, db_parameters):
    """SNOW-4525: Loads Bogus file and should fail."""
    with conn_cnx() as cnx:
        cnx.cursor().execute(
            f"""
create or replace table {db_parameters["name"]} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(5,2))
"""
        )
        temp_file = tmp_path / "bogus_files"
        with temp_file.open("wb") as random_binary_file:
            random_binary_file.write(os.urandom(1024))
        cnx.cursor().execute(f"put file://{temp_file} @%{db_parameters['name']}")

        with cnx.cursor() as c:
            c.execute(f"copy into {db_parameters['name']} on_error='skip_file'")
            cnt = 0
            for _rec in c:
                cnt += 1
            assert _rec[1] == "LOAD_FAILED"
        cnx.cursor().execute(f"drop table if exists {db_parameters['name']}")


def test_load_bogus_json_file(tmp_path: pathlib.Path, conn_cnx, db_parameters):
    """SNOW-4525: Loads Bogus JSON file and should fail."""
    with conn_cnx() as cnx:
        json_table = db_parameters["name"] + "_json"
        cnx.cursor().execute(f"create or replace table {json_table} (v variant)")

        temp_file = tmp_path / "bogus_json_files"
        temp_file.write_bytes(os.urandom(1024))
        cnx.cursor().execute(f"put file://{temp_file} @%{json_table}")

        with cnx.cursor() as c:
            c.execute(
                f"copy into {json_table} on_error='skip_file' "
                "file_format=(type='json')"
            )
            cnt = 0
            for _rec in c:
                cnt += 1
            assert _rec[1] == "LOAD_FAILED"
        cnx.cursor().execute(f"drop table if exists {json_table}")
