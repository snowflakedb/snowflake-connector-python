#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import os

import pytest


@pytest.mark.aws
@pytest.mark.flaky(reruns=3)
def test_put_copy_large_files(tmpdir, conn_cnx, db_parameters, test_files):
    """[s3] Puts and Copies into large files."""
    # generates N files
    number_of_files = 2
    number_of_lines = 200000
    tmp_dir = test_files(number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir('data')))

    files = os.path.join(tmp_dir, 'file*')
    with conn_cnx(
            user=db_parameters['user'],
            account=db_parameters['account'],
            password=db_parameters['password']) as cnx:
        cnx.cursor().execute("""
create table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(6,2))
""".format(name=db_parameters['name']))
    try:
        with conn_cnx(
                user=db_parameters['user'],
                account=db_parameters['account'],
                password=db_parameters['password']) as cnx:
            files = files.replace('\\', '\\\\')
            cnx.cursor().execute("put 'file://{file}' @%{name}".format(
                file=files, name=db_parameters['name']))
            c = cnx.cursor()
            try:
                c.execute("copy into {}".format(db_parameters['name']))
                cnt = 0
                for _ in c:
                    cnt += 1
                assert cnt == number_of_files, 'Number of PUT files'
            finally:
                c.close()

            c = cnx.cursor()
            try:
                c.execute("select count(*) from {name}".format(
                    name=db_parameters['name']))
                cnt = 0
                for rec in c:
                    cnt += rec[0]
                assert cnt == number_of_files * number_of_lines, \
                    "Number of rows"
            finally:
                c.close()
    finally:
        with conn_cnx(
                user=db_parameters['user'],
                account=db_parameters['account'],
                password=db_parameters['password']) as cnx:
            cnx.cursor().execute("drop table if exists {table}".format(
                table=db_parameters['name']))
