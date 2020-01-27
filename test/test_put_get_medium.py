#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import datetime
import gzip
import os
import random
import shutil
import string
import sys
import tempfile
import time
from logging import getLogger
from os import path

import pytest
import pytz

from snowflake.connector import ProgrammingError
from snowflake.connector.cursor import DictCursor

try:
    from parameters import (CONNECTION_PARAMETERS_ADMIN)
except:
    CONNECTION_PARAMETERS_ADMIN = {}

# Mark every test in this module as a putget test
pytestmark = pytest.mark.putget

import logging

for logger_name in ['test', 'snowflake.connector', 'botocore']:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(
        path.join(tempfile.gettempdir(), 'python_connector.log'))
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter(
        '%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s'))
    logger.addHandler(ch)

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
logger = getLogger(__name__)


def test_put_copy0(conn_cnx, db_parameters):
    """
    Put and Copy a file
    """
    data_file = os.path.join(THIS_DIR, "data", "put_get_1.txt")

    def run(cnx, sql):
        sql = sql.format(
            file=data_file.replace('\\', '\\\\'),
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    def run_with_cursor(cnx, sql):
        sql = sql.format(
            file=data_file.replace('\\', '\\\\'),
            name=db_parameters['name'])
        c = cnx.cursor(DictCursor)
        return c, c.execute(sql).fetchall()

    with conn_cnx() as cnx:
        run(cnx, """
create table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(5,2))
""")
        c, ret = run_with_cursor(cnx, "put 'file://{file}' @%{name}")
        assert c.is_file_transfer, "PUT"
        assert len(ret) == 1 and ret[0]['source'] == os.path.basename(
            data_file), "File name"

        c, ret = run_with_cursor(cnx, "copy into {name}")
        assert not c.is_file_transfer, "COPY"
        assert len(ret) == 1 and ret[0]['status'] == "LOADED", \
            "Failed to load data"

        assert ret[0]['rows_loaded'] == 3, "Failed to load 3 rows of data"

        run(cnx, 'drop table if exists {name}')


def test_put_copy_compressed(conn_cnx, db_parameters):
    """
    Put and Copy compressed files
    """
    data_file = os.path.join(THIS_DIR, "data", "gzip_sample.txt.gz")

    def run(cnx, sql):
        sql = sql.format(
            file=data_file.replace('\\', '\\\\'),
            name=db_parameters['name'])
        return cnx.cursor(DictCursor).execute(sql).fetchall()

    with conn_cnx() as cnx:
        run(cnx, "create or replace table {name} (value string)")
        file_size = os.stat(data_file).st_size
        ret = run(cnx, "put 'file://{file}' @%{name}")
        assert ret[0]['source'] == os.path.basename(data_file), "File name"
        assert ret[0]['source_size'] == file_size, "File size"
        assert ret[0]['status'] == 'UPLOADED'

        ret = run(cnx, "copy into {name}")
        assert len(ret) == 1 and ret[0]['status'] == "LOADED", \
            "Failed to load data"
        assert ret[0]['rows_loaded'] == 1, "Failed to load 1 rows of data"

        run(cnx, 'drop table if exists {name}')


@pytest.mark.skipif(
    True,
    reason="BZ2 is not detected in this test case. Need investigation"
)
def test_put_copy_bz2_compressed(conn_cnx, db_parameters):
    """
    Put and Copy bz2 compressed files
    """
    data_file = os.path.join(THIS_DIR, "data", "bzip2_sample.txt.bz2")

    def run(cnx, sql):
        sql = sql.format(
            file=data_file.replace('\\', '\\\\'),
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx() as cnx:
        run(cnx, "create or replace table {name} (value string)")
        for rec in run(cnx, "put 'file://{file}' @%{name}"):
            print(rec)
            assert rec[-2] == 'UPLOADED'
        for rec in run(cnx, "copy into {name}"):
            print(rec)
            assert rec[1] == 'LOADED'

        run(cnx, 'drop table if exists {name}')


def test_put_copy_brotli_compressed(conn_cnx, db_parameters):
    """
    Put and Copy brotli compressed files
    """
    data_file = os.path.join(THIS_DIR, "data", "brotli_sample.txt.br")

    def run(cnx, sql):
        sql = sql.format(
            file=data_file.replace('\\', '\\\\'),
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx() as cnx:
        run(cnx, "create or replace table {name} (value string)")
        for rec in run(cnx, "put 'file://{file}' @%{name}"):
            print(rec)
            assert rec[-2] == 'UPLOADED'
        for rec in run(
                cnx, "copy into {name} file_format=(compression='BROTLI')"):
            print(rec)
            assert rec[1] == 'LOADED'

        run(cnx, 'drop table if exists {name}')


def test_put_copy_zstd_compressed(conn_cnx, db_parameters):
    """
    Put and Copy zstd compressed files
    """
    data_file = os.path.join(THIS_DIR, "data", "zstd_sample.txt.zst")

    def run(cnx, sql):
        sql = sql.format(
            file=data_file.replace('\\', '\\\\'),
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx() as cnx:
        run(cnx, "create or replace table {name} (value string)")
        for rec in run(cnx, "put 'file://{file}' @%{name}"):
            print(rec)
            assert rec[-2] == 'UPLOADED'
        for rec in run(
                cnx, "copy into {name} file_format=(compression='ZSTD')"):
            print(rec)
            assert rec[1] == 'LOADED'

        run(cnx, 'drop table if exists {name}')


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_copy_parquet_compressed(conn_cnx, db_parameters):
    """
    Put and Copy parquet compressed files
    """
    data_file = os.path.join(
        THIS_DIR, "data", "nation.impala.parquet")

    def run(cnx, sql):
        sql = sql.format(
            file=data_file.replace('\\', '\\\\'),
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx() as cnx:
        run(cnx, "alter session set enable_parquet_filetype=true")
        run(cnx, """
create or replace table {name}
(value variant)
stage_file_format=(type='parquet')
""")
        for rec in run(cnx, "put 'file://{file}' @%{name}"):
            print(rec)
            assert rec[-2] == 'UPLOADED'
            assert rec[4] == 'PARQUET'
            assert rec[5] == 'PARQUET'
        for rec in run(cnx, "copy into {name}"):
            print(rec)
            assert rec[1] == 'LOADED'

        run(cnx, 'drop table if exists {name}')
        run(cnx, "alter session unset enable_parquet_filetype")


def test_put_copy_orc_compressed(conn_cnx, db_parameters):
    """
    Put and Copy ORC compressed files
    """
    data_file = os.path.join(THIS_DIR, "data", "TestOrcFile.test1.orc")

    def run(cnx, sql):
        sql = sql.format(
            file=data_file.replace('\\', '\\\\'),
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx() as cnx:
        run(cnx, """
create or replace table {name} (value variant) stage_file_format=(type='orc')
""")
        for rec in run(cnx, "put 'file://{file}' @%{name}"):
            print(rec)
            assert rec[-2] == 'UPLOADED'
            assert rec[4] == 'ORC'
            assert rec[5] == 'ORC'
        for rec in run(cnx, "copy into {name}"):
            print(rec)
            assert rec[1] == 'LOADED'

        run(cnx, 'drop table if exists {name}')


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_copy_get(tmpdir, conn_cnx, db_parameters):
    """
    Copy and Get a file
    """
    name_unload = db_parameters['name'] + "_unload"
    tmp_dir = str(tmpdir.mkdir('copy_get_stage'))
    tmp_dir_user = str(tmpdir.mkdir('user_get'))

    def run(cnx, sql):
        sql = sql.format(
            name_unload=name_unload,
            tmpdir=tmp_dir,
            tmp_dir_user=tmp_dir_user,
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx() as cnx:
        run(cnx,
            "alter session set DISABLE_PUT_AND_GET_ON_EXTERNAL_STAGE=false")
        run(cnx, """
create or replace table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(5,2))
""")
        run(cnx, """
create or replace stage {name_unload}
file_format = (
format_name = 'common.public.csv'
field_delimiter = '|'
error_on_column_count_mismatch=false);
""")
        current_time = datetime.datetime.utcnow()
        current_time = current_time.replace(
            tzinfo=pytz.timezone("America/Los_Angeles"))
        current_date = datetime.date.today()
        other_time = current_time.replace(tzinfo=pytz.timezone("Asia/Tokyo"))

        fmt = """
insert into {name}(aa, dt, tstz)
values(%(value)s,%(dt)s,%(tstz)s)
""".format(name=db_parameters['name'])
        cnx.cursor().executemany(fmt, [
            {'value': 6543, 'dt': current_date, 'tstz': other_time},
            {'value': 1234, 'dt': current_date, 'tstz': other_time},
        ])

        run(cnx, """
copy into @{name_unload}/data_
from {name}
file_format=(
format_name='common.public.csv'
compression='gzip')
max_file_size=10000000
""")
        ret = run(cnx, "get @{name_unload}/ file://{tmp_dir_user}/")

        assert ret[0][2] == 'DOWNLOADED', 'Failed to download'
        cnt = 0
        for _, _, _ in os.walk(tmp_dir_user):
            cnt += 1
        assert cnt > 0, 'No file was downloaded'

        run(cnx, "drop stage {name_unload}")
        run(cnx, "drop table if exists {name}")


def test_put_copy_many_files(tmpdir, test_files, conn_cnx, db_parameters):
    """
    Put and Copy many_files
    """
    # generates N files
    number_of_files = 100
    number_of_lines = 1000
    tmp_dir = test_files(number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir('data')))

    files = os.path.join(tmp_dir, 'file*')

    def run(cnx, sql):
        sql = sql.format(
            files=files.replace('\\', '\\\\'),
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx() as cnx:
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
        run(cnx, "put 'file://{files}' @%{name}")
        run(cnx, "copy into {name}")
        rows = 0
        for rec in run(cnx, "select count(*) from {name}"):
            rows += rec[0]
        assert rows == number_of_files * number_of_lines, 'Number of rows'

        run(cnx, "drop table if exists {name}")


def test_put_copy_many_files_s3(tmpdir, test_files, conn_cnx, db_parameters):
    """
    [s3] Put and Copy many files
    """
    # generates N files
    number_of_files = 10
    number_of_lines = 1000
    tmp_dir = test_files(number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir('data')))

    files = os.path.join(tmp_dir, 'file*')

    def run(cnx, sql):
        sql = sql.format(
            files=files.replace('\\', '\\\\'),
            name=db_parameters['name'])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
            user=db_parameters['s3_user'],
            account=db_parameters['s3_account'],
            password=db_parameters['s3_password']) as cnx:
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
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            run(cnx, "put 'file://{files}' @%{name}")
            run(cnx, "copy into {name}")

            rows = 0
            for rec in run(cnx, "select count(*) from {name}"):
                rows += rec[0]
            assert rows == number_of_files * number_of_lines, \
                'Number of rows'
    finally:
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            run(cnx, "drop table if exists {name}")


@pytest.mark.skipif(os.getenv("SNOWFLAKE_GCP") is not None, reason="PUT and GET is not supported for GCP yet")
def test_put_copy_duplicated_files_s3(tmpdir, test_files, conn_cnx,
                                      db_parameters):
    """
    [s3] Put and Copy duplicated files
    """
    # generates N files
    number_of_files = 5
    number_of_lines = 100
    tmp_dir = test_files(number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir('data')))

    files = os.path.join(tmp_dir, 'file*')

    def run(cnx, sql):
        sql = sql.format(
            files=files.replace('\\', '\\\\'),
            name=db_parameters['name'])
        return cnx.cursor().execute(sql, _raise_put_get_error=False).fetchall()

    with conn_cnx(
            user=db_parameters['s3_user'],
            account=db_parameters['s3_account'],
            password=db_parameters['s3_password']) as cnx:
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
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            success_cnt = 0
            skipped_cnt = 0
            for rec in run(cnx, "put 'file://{files}' @%{name}"):
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
            for rec in run(cnx, "put 'file://{files}' @%{name}"):
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
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            run(cnx, "drop table if exists {name}")


def test_put_collision(tmpdir, test_files, conn_cnx, db_parameters):
    """
    File name collision
    TODO: this should be updated once non gz file support is in
    """
    # generates N files
    number_of_files = 5
    number_of_lines = 10
    tmp_dir = test_files(number_of_lines, number_of_files, compress=True, tmp_dir=str(tmpdir.mkdir('data')))
    files = os.path.join(tmp_dir, 'file*')
    shutil.copy(os.path.join(tmp_dir, 'file0.gz'),
                os.path.join(tmp_dir, 'file0'))
    stage_name = "test_put_collision/{0}".format(db_parameters['name'])
    with conn_cnx(
            user=db_parameters['s3_user'],
            account=db_parameters['s3_account'],
            password=db_parameters['s3_password']) as cnx:
        cnx.cursor().execute("RM @~/{0}".format(stage_name))
        try:
            success_cnt = 0
            skipped_cnt = 0
            for rec in cnx.cursor().execute(
                    "PUT 'file://{file}' @~/{stage_name}".format(
                        file=files.replace('\\', '\\\\'),
                        stage_name=stage_name)):
                logger.info('rec=%s', rec)
                if rec[6] == 'UPLOADED':
                    success_cnt += 1
                elif rec[6] == 'SKIPPED':
                    skipped_cnt += 1
            assert success_cnt == number_of_files + 1
        finally:
            with conn_cnx(
                    user=db_parameters['s3_user'],
                    account=db_parameters['s3_account'],
                    password=db_parameters['s3_password']) as cnx:
                cnx.cursor().execute("RM @~/{0}".format(stage_name))


def _generate_huge_value_json(tmpdir, n=1, value_size=1):
    fname = str(tmpdir.join('test_put_get_huge_json'))
    f = gzip.open(fname, 'wb')
    for i in range(n):
        logger.debug("adding a value in {0}".format(i))
        f.write('{"k":"{0}"}'.format(
            ''.join(
                random.choice(string.ascii_uppercase + string.digits) for _ in
                range(value_size))))
    f.close()
    return fname


def _huge_value_json_upload(tmpdir, conn_cnx, db_parameters):
    """
    (WIP) Huge json value data
    """
    with conn_cnx() as cnx:
        json_table = db_parameters['name'] + "_json"
        cnx.cursor().execute(
            "create or replace table {table} (v variant)".format(
                table=json_table))

        rows = 2
        size = 2000
        tmp_file = _generate_huge_value_json(tmpdir, n=rows, value_size=size)
        try:
            c = cnx.cursor()
            try:
                c.execute(
                    "put 'file://{tmp_file}' @%{name}".format(
                        tmp_file=tmp_file.replace('\\', '\\\\'),
                        name=json_table))
                colmap = {}
                for index, item in enumerate(c.description):
                    colmap[item[0]] = index
                for rec in c:
                    source = rec[colmap['source']]
                    logger.debug(source)
            finally:
                c.close()

            c = cnx.cursor()
            try:
                c.execute(
                    "copy into {name} on_error='skip_file' file_format=(type='json')".format(
                        name=json_table))
                cnt = 0
                rec = []
                for rec in c:
                    logger.debug(rec)
                    cnt += 1
                assert rec[1] == 'LOAD_FAILED', \
                    "Loading huge value json should fail"
                assert cnt == 1, 'Number of PUT files'
            finally:
                c.close()

            c = cnx.cursor()
            try:
                c.execute(
                    "select count(*) from {name}".format(name=json_table))
                cnt = -1
                for rec in c:
                    cnt = rec[0]
                assert cnt == 0, "Number of copied rows"
            finally:
                c.close()

            cnx.cursor().execute(
                "drop table if exists {table}".format(table=json_table))
        finally:
            os.unlink(tmp_file)


@pytest.mark.skipif(
    os.getenv('TRAVIS') == 'true' or os.getenv('APPVEYOR'),
    reason="Flaky tests. Need further investigation"
)
def test_put_get_large_files_s3(tmpdir, test_files, conn_cnx, db_parameters):
    """
    [s3] Put and Get Large files
    """
    number_of_files = 3
    number_of_lines = 200000
    tmp_dir = test_files(number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir('data')))

    files = os.path.join(tmp_dir, 'file*')
    output_dir = os.path.join(tmp_dir, 'output_dir')
    os.makedirs(output_dir)

    class cb(object):
        def __init__(self, filename, filesize, **_):
            pass

        def __call__(self, bytes_amount):
            pass

    def run(cnx, sql):
        return cnx.cursor().execute(
            sql.format(
                files=files.replace('\\', '\\\\'),
                dir=db_parameters['name'],
                output_dir=output_dir.replace('\\', '\\\\')),
            _put_callback_output_stream=sys.stdout,
            _get_callback_output_stream=sys.stdout,
            _get_callback=cb,
            _put_callback=cb).fetchall()

    with conn_cnx(
            user=db_parameters['s3_user'],
            account=db_parameters['s3_account'],
            password=db_parameters['s3_password']) as cnx:
        try:
            run(cnx, "PUT 'file://{files}' @~/{dir}")
            # run(cnx, "PUT 'file://{files}' @~/{dir}")  # retry
            all_recs = []
            for _ in range(100):
                all_recs = run(cnx, "LIST @~/{dir}")
                if len(all_recs) == number_of_files:
                    break
                time.sleep(1)
            else:
                pytest.fail(
                    'cannot list all files. Potentially '
                    'PUT command missed uploading Files: {0}'.format(all_recs))
            all_recs = run(cnx, "GET @~/{dir} 'file://{output_dir}'")
            assert len(all_recs) == number_of_files
            assert all([rec[2] == 'DOWNLOADED' for rec in all_recs])
        finally:
            run(cnx, "RM @~/{dir}")


@pytest.mark.skipif(os.getenv("SNOWFLAKE_GCP") is not None, reason="PUT and GET  is not supportd for GCP yet")
def test_put_get_with_hint(tmpdir, conn_cnx, db_parameters):
    """
    SNOW-15153: PUT and GET with hint
    """
    tmp_dir = str(tmpdir.mkdir('put_get_with_hint'))
    data_file = os.path.join(THIS_DIR, "data", "put_get_1.txt")

    def run(cnx, sql, _is_put_get=None):
        return cnx.cursor().execute(
            sql.format(
                local_dir=tmp_dir.replace('\\', '\\\\'),
                file=data_file.replace('\\', '\\\\'),
                name=db_parameters['name']), _is_put_get=_is_put_get).fetchone()

    with conn_cnx() as cnx:
        # regular PUT case
        ret = run(cnx, "PUT 'file://{file}' @~/{name}")
        assert ret[0] == 'put_get_1.txt', 'PUT filename'

        # clean up a file
        ret = run(cnx, "RM @~/{name}")
        assert ret[0].endswith('put_get_1.txt.gz'), 'RM filename'

        # PUT detection failure
        with pytest.raises(ProgrammingError):
            run(cnx, """
-- test comments
PUT 'file://{file}' @~/{name}""")

        # PUT with hint
        ret = run(cnx, """
--- test comments
PUT 'file://{file}' @~/{name}""", _is_put_get=True)
        assert ret[0] == 'put_get_1.txt', 'PUT filename'

        # GET detection failure
        with pytest.raises(ProgrammingError):
            run(cnx, """
--- test comments
GET @~/{name} file://{local_dir}""")

        # GET with hint
        ret = run(cnx, """
--- test comments
GET @~/{name} 'file://{local_dir}'""", _is_put_get=True)
        assert ret[0] == 'put_get_1.txt.gz', "GET filename"
