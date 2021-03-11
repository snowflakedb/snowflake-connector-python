#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import os

import pytest

from ..generate_test_files import generate_k_lines_of_n_files
from ..integ_helpers import drop_table
from ..randomize import random_string

pytestmark = pytest.mark.parallel


@pytest.mark.aws
def test_put_copy_large_files(tmpdir, conn_cnx, request):
    """[s3] Puts and Copies into large files."""
    # generates N files
    number_of_files = 2
    number_of_lines = 200000
    tmp_dir = generate_k_lines_of_n_files(number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir('data')))

    table_name = random_string(3, prefix="test_put_copy_large_files_")

    files = os.path.join(tmp_dir, 'file*')
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
ratio number(6,2))
""")
        request.addfinalizer(drop_table(conn_cnx, table_name))

    with conn_cnx() as cnx:
        files = files.replace('\\', '\\\\')
        cnx.cursor().execute(f"put 'file://{files}' @%{table_name}")
        with cnx.cursor() as c:
            c.execute(f"copy into {table_name}")
            cnt = 0
            for _ in c:
                cnt += 1
            assert cnt == number_of_files, 'Number of PUT files'

        with cnx.cursor() as c:
            c.execute(f"select count(*) from {table_name}")
            cnt = 0
            for rec in c:
                cnt += rec[0]
            assert cnt == number_of_files * number_of_lines, \
                "Number of rows"
