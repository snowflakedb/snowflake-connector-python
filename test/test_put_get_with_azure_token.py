#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#

import glob
import gzip
import os

import sys

import time

import pytest

from snowflake.connector.constants import UTF8

from logging import getLogger
from snowflake.connector.azure_util import SnowflakeAzureUtil

try:
    from parameters import (CONNECTION_PARAMETERS_ADMIN)
except:
    CONNECTION_PARAMETERS_ADMIN = {}

logger = getLogger(__name__)

@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_get_with_azure(tmpdir, conn_cnx, db_parameters):
    """
    [azure] Put and Get a small text using Azure
    """
    # create a data file
    fname = str(tmpdir.join('test_put_get_with_azure_token.txt.gz'))
    f = gzip.open(fname, 'wb')
    original_contents = "123,test1\n456,test2\n"
    f.write(original_contents.encode(UTF8))
    f.close()
    tmp_dir = str(tmpdir.mkdir('test_put_get_with_azure_token'))
    

    with conn_cnx(
            user=db_parameters['azure_user'],
            account=db_parameters['azure_account'],
            password=db_parameters['azure_password']) as cnx:
        cnx.cursor().execute("rm @~/snow32806")
        cnx.cursor().execute(
            "create or replace table snow32806 (a int, b string)")
    try:
        with conn_cnx(
                user=db_parameters['azure_user'],
                account=db_parameters['azure_account'],
                password=db_parameters['azure_password']) as cnx:
            with cnx.cursor() as csr:
                csr.execute(
                    "put file://{0} @%snow32806 auto_compress=true parallel=30".format(
                        fname))
                csr.execute("copy into snow32806")
                csr.execute(
                    "copy into @~/snow32806 from snow32806 "
                    "file_format=( format_name='common.public.csv' "
                    "compression='gzip')")
                csr.execute(
                    "get @~/snow32806 file://{0} pattern='snow32806.*'".format(
                        tmp_dir))
                rec = csr.fetchone()
                assert rec[0].startswith('snow32806'), 'A file downloaded by GET'
                assert rec[1] == 36, 'Return right file size'
                assert rec[2] == u'DOWNLOADED', 'Return DOWNLOADED status'
                assert rec[3] == u'', 'Return no error message'
    finally:
        with conn_cnx(
                user=db_parameters['azure_user'],
                account=db_parameters['azure_account'],
                password=db_parameters['azure_password']) as cnx:
            cnx.cursor().execute("drop table snow32806")
            cnx.cursor().execute("rm @~/snow32806")

    files = glob.glob(os.path.join(tmp_dir, 'snow32806*'))
    contents = ''
    fd = gzip.open(files[0], 'rb')
    for line in fd:
        contents += line.decode(UTF8)
    fd.close()
    assert original_contents == contents, (
        'Output is different from the original file')

@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_copy_many_files_azure(tmpdir, test_files, conn_cnx, db_parameters):
    """
    [azure] Put and Copy many files
    """
    # generates N files
    number_of_files = 10
    number_of_lines = 1000
    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files)

    files = os.path.join(tmp_dir, 'file*')

    def run(cnx, sql):
        sql = sql.format(
            files=files,
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
            user=db_parameters['azure_user'],
            account=db_parameters['azure_account'],
            password=db_parameters['azure_password']) as cnx:
        run(cnx, """
create or replace table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(6,2))
""")
    try:
        with conn_cnx(
                user=db_parameters['azure_user'],
                account=db_parameters['azure_account'],
                password=db_parameters['azure_password']) as cnx:
            run(cnx, "put file://{files} @%{name}")
            run(cnx, "copy into {name}")

            rows = 0
            for rec in run(cnx, "select count(*) from {name}"):
                rows += rec[0]
            assert rows == number_of_files * number_of_lines, \
                'Number of rows'
    finally:
        with conn_cnx(
                user=db_parameters['azure_user'],
                account=db_parameters['azure_account'],
                password=db_parameters['azure_password']) as cnx:
            run(cnx, "drop table if exists {name}")

@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_copy_duplicated_files_azure(tmpdir, test_files, conn_cnx,
                                      db_parameters):
    """
    [azure] Put and Copy duplicated files
    """
    # generates N files
    number_of_files = 5
    number_of_lines = 100
    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files)

    files = os.path.join(tmp_dir, 'file*')

    def run(cnx, sql):
        sql = sql.format(
            files=files,
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
            user=db_parameters['azure_user'],
            account=db_parameters['azure_account'],
            password=db_parameters['azure_password']) as cnx:
        run(cnx, """
create or replace table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(6,2))
""")

    try:
        with conn_cnx(
                user=db_parameters['azure_user'],
                account=db_parameters['azure_account'],
                password=db_parameters['azure_password']) as cnx:
            success_cnt = 0
            skipped_cnt = 0
            for rec in run(cnx, "put file://{files} @%{name}"):
                logger.info('rec=%s', rec)
                if rec[6] == 'UPLOADED':
                    success_cnt += 1
                elif rec[6] == 'SKIPPED':
                    skipped_cnt += 1
            assert success_cnt == number_of_files, 'uploaded files'
            assert skipped_cnt == 0, 'skipped files'

            deleted_cnt = 0
            run(cnx, "rm @%{name}/file0")
            deleted_cnt += 1
            run(cnx, "rm @%{name}/file1")
            deleted_cnt += 1
            run(cnx, "rm @%{name}/file2")
            deleted_cnt += 1

            success_cnt = 0
            skipped_cnt = 0
            for rec in run(cnx, "put file://{files} @%{name}"):
                logger.info('rec=%s', rec)
                if rec[6] == 'UPLOADED':
                    success_cnt += 1
                elif rec[6] == 'SKIPPED':
                    skipped_cnt += 1
            assert success_cnt == deleted_cnt, \
                'uploaded files in the second time'
            assert skipped_cnt == number_of_files - deleted_cnt, \
                'skipped files in the second time'

            run(cnx, "copy into {name}")
            rows = 0
            for rec in run(cnx, "select count(*) from {name}"):
                rows += rec[0]
            assert rows == number_of_files * number_of_lines, \
                'Number of rows'
    finally:
        with conn_cnx(
                user=db_parameters['azure_user'],
                account=db_parameters['azure_account'],
                password=db_parameters['azure_password']) as cnx:
            run(cnx, "drop table if exists {name}")

@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_get_large_files_azure(tmpdir, test_files, conn_cnx, db_parameters):
    """
    [azure] Put and Get Large files
    """
    number_of_files = 3
    number_of_lines = 200000
    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files)

    files = os.path.join(tmp_dir, 'file*')
    output_dir = os.path.join(tmp_dir, 'output_dir')
    os.makedirs(output_dir)

    class cb(object):
        def __init__(self, filename, filesize, output_stream=sys.stdout):
            pass

        def __call__(self, bytes_amount):
            pass

    def run(cnx, sql):
        return cnx.cursor().execute(
            sql.format(
                files=files,
                dir=db_parameters['name'],
                output_dir=output_dir),
            _put_callback_output_stream=sys.stdout,
            _get_callback_output_stream=sys.stdout,
            _get_callback=cb,
            _put_callback=cb).fetchall()

    with conn_cnx(
            user=db_parameters['azure_user'],
            account=db_parameters['azure_account'],
            password=db_parameters['azure_password']) as cnx:
        try:
            run(cnx, "PUT file://{files} @~/{dir}")
            # run(cnx, "PUT file://{files} @~/{dir}")  # retry
            for _ in range(100):
                all_recs = run(cnx, "LIST @~/{dir}")
                if len(all_recs) == number_of_files:
                    break
                time.sleep(1)
            else:
                pytest.fail(
                    'cannot list all files. Potentially '
                    'PUT command missed uploading Files: {0}'.format(all_recs))
            all_recs = run(cnx, "GET @~/{dir} file://{output_dir}");
            assert len(all_recs) == number_of_files
            assert all([rec[2] == 'DOWNLOADED' for rec in all_recs])
        finally:
            run(cnx, "RM @~/{dir}")