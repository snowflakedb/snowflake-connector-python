#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import os


def test_load_bogus_file(tmpdir, conn_cnx, db_parameters):
    """SNOW-4525: Loads Bogus file and should fail."""
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        cnx.cursor().execute(
            """
create or replace table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(5,2))
""".format(
                name=db_parameters["name"]
            )
        )
        temp_file = str(tmpdir.join("bogus_files"))
        with open(temp_file, "wb") as random_binary_file:
            random_binary_file.write(os.urandom(1024))
        cnx.cursor().execute(
            "put file://{file} @%{name}".format(
                file=temp_file, name=db_parameters["name"]
            )
        )

        with cnx.cursor() as c:
            c.execute(
                "copy into {name} on_error='skip_file'".format(
                    name=db_parameters["name"]
                )
            )
            cnt = 0
            for _rec in c:
                cnt += 1
            assert _rec[1] == "LOAD_FAILED"
        cnx.cursor().execute(
            "drop table if exists {name}".format(name=db_parameters["name"])
        )


def test_load_bogus_json_file(tmpdir, conn_cnx, db_parameters):
    """SNOW-4525: Loads Bogus JSON file and should fail."""
    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        json_table = db_parameters["name"] + "_json"
        cnx.cursor().execute(
            "create or replace table {name} (v variant)".format(name=json_table)
        )

        temp_file = str(tmpdir.join("bogus_json_files"))
        with open(temp_file, "wb") as random_binary_file:
            random_binary_file.write(os.urandom(1024))
        cnx.cursor().execute(
            "put file://{file} @%{name}".format(file=temp_file, name=json_table)
        )

        with cnx.cursor() as c:
            c.execute(
                "copy into {name} on_error='skip_file' "
                "file_format=(type='json')".format(name=json_table)
            )
            cnt = 0
            for _rec in c:
                cnt += 1
            assert _rec[1] == "LOAD_FAILED"
        cnx.cursor().execute("drop table if exists {name}".format(name=json_table))
