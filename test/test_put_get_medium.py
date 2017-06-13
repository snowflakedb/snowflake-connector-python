#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import datetime
import gzip
import os
import random
import shutil
import string
from logging import getLogger

import pytest
import pytz

from snowflake.connector import ProgrammingError

try:
    from parameters import (CONNECTION_PARAMETERS_ADMIN)
except:
    CONNECTION_PARAMETERS_ADMIN = {}

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
logger = getLogger(__name__)


def test_put_copy(conn_cnx, db_parameters):
    """Put and Copy a file
    """
    with conn_cnx() as cnx:
        cnx.cursor().execute("""
create table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(5,2))
""".format(name=db_parameters['name']))
        data_file = os.path.join(THIS_DIR, "data", "put_get_1.txt")
        c = cnx.cursor()
        try:
            c.execute("""
put file://{file} @%{name}""".format(file=data_file,
                                     name=db_parameters['name']))
            assert c.is_file_transfer, "PUT"
            colmap = {}
            for index, item in enumerate(c.description):
                colmap[item[0]] = index
            for rec in c:
                source = rec[colmap['source']]
                source_size = rec[colmap['source_size']]

            assert source == os.path.basename(data_file), "File name"
        finally:
            c.close()

        c = cnx.cursor()
        try:
            c.execute("copy into {name}".format(name=db_parameters['name']))
            assert not c.is_file_transfer, "COPY"
            cnt = 0
            for rec in c:
                cnt += 1
            assert rec[1] == "LOADED", "Failed to load data"

        finally:
            c.close()

        cnx.cursor().execute(
            'drop table if exists {name}'.format(name=db_parameters['name']))


def test_put_copy_compressed(conn_cnx, db_parameters):
    """Put and Copy compressed files
    """
    with conn_cnx() as cnx:
        cnx.cursor().execute(
            "create or replace table {name} (value string)".format(
                name=db_parameters['name']))
        data_file = os.path.join(THIS_DIR, "data",
                                 "gzip_sample.txt.gz")
        file_size = os.stat(data_file).st_size
        c = cnx.cursor()
        try:
            c.execute("""
put file://{file} @%{name}""".format(file=data_file,
                                     name=db_parameters['name']))
            colmap = {}
            for index, item in enumerate(c.description):
                colmap[item[0]] = index
            for rec in c:
                source = rec[colmap['source']]
                source_size = rec[colmap['source_size']]

            assert source == os.path.basename(data_file), "File name"
            assert source_size == file_size, "File size"
        finally:
            c.close()

        c = cnx.cursor()
        try:
            c.execute("copy into {name}".format(name=db_parameters['name']))
            cnt = 0
            for rec in c:
                cnt += 1
            assert rec[1] == "LOADED", "Failed to load data"

        finally:
            c.close()

        cnx.cursor().execute(
            'drop table if exists {name}'.format(name=db_parameters['name']))


@pytest.mark.skipif(
    True,
    reason="BZ2 is not detected in this test case. Need investigation"
)
def test_put_copy_bz2_compressed(conn_cnx, db_parameters):
    """
    Put and Copy bz2 compressed files
    """
    with conn_cnx() as cnx:
        cnx.cursor().execute("""
create or replace table {name} (value string)
""".format(name=db_parameters['name']))
        data_file = os.path.join(
            THIS_DIR, "data", "bzip2_sample.txt.bz2")
        with cnx.cursor() as c:
            for rec in c.execute("""
put file://{file} @%{name}""".format(file=data_file,
                                     name=db_parameters['name'])):
                print(rec)
                assert rec[-2] == 'UPLOADED'
            for rec in c.execute(
                    "copy into {name}".format(name=db_parameters['name'])):
                print(rec)
                assert rec[1] == 'LOADED'

        cnx.cursor().execute(
            'drop table if exists {name}'.format(name=db_parameters['name']))


def test_put_copy_brotli_compressed(conn_cnx, db_parameters):
    """
    Put and Copy brotli compressed files
    """
    with conn_cnx() as cnx:
        cnx.cursor().execute("""
create or replace table {name} (value string)
""".format(name=db_parameters['name']))
        data_file = os.path.join(
            THIS_DIR, "data", "brotli_sample.txt.br")
        with cnx.cursor() as c:
            for rec in c.execute("""
put file://{file} @%{name}""".format(file=data_file,
                                     name=db_parameters['name'])):
                print(rec)
                assert rec[-2] == 'UPLOADED'
            for rec in c.execute(
                    "copy into {name} file_format=(compression='BROTLI')".format(name=db_parameters['name'])):
                print(rec)
                assert rec[1] == 'LOADED'

        cnx.cursor().execute(
            'drop table if exists {name}'.format(name=db_parameters['name']))


def test_put_copy_zstd_compressed(conn_cnx, db_parameters):
    """
    Put and Copy zstd compressed files
    """
    with conn_cnx() as cnx:
        cnx.cursor().execute("""
create or replace table {name} (value string)
""".format(name=db_parameters['name']))
        data_file = os.path.join(
            THIS_DIR, "data", "zstd_sample.txt.zst")
        with cnx.cursor() as c:
            for rec in c.execute("""
put file://{file} @%{name}""".format(file=data_file,
                                     name=db_parameters['name'])):
                print(rec)
                assert rec[-2] == 'UPLOADED'
            for rec in c.execute(
                    "copy into {name} file_format=(compression='ZSTD')".format(
                        name=db_parameters['name'])):
                print(rec)
                assert rec[1] == 'LOADED'

        cnx.cursor().execute(
            'drop table if exists {name}'.format(name=db_parameters['name']))


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_copy_parquet_compressed(conn_cnx, db_parameters):
    """
    Put and Copy parquet compressed files
    """
    with conn_cnx() as cnx:
        cnx.cursor().execute("alter session set enable_parquet_filetype=true")
        cnx.cursor().execute("""
create or replace table {name} (value variant) stage_file_format=(type='parquet')
""".format(name=db_parameters['name']))
        data_file = os.path.join(
            THIS_DIR, "data", "nation.impala.parquet")
        with cnx.cursor() as c:
            for rec in c.execute("""
put file://{file} @%{name}""".format(file=data_file,
                                     name=db_parameters['name'])):
                print(rec)
                assert rec[-2] == 'UPLOADED'
                assert rec[4] == 'PARQUET'
                assert rec[5] == 'PARQUET'
            for rec in c.execute(
                    "copy into {name}".format(name=db_parameters['name'])):
                print(rec)
                assert rec[1] == 'LOADED'

        cnx.cursor().execute(
            'drop table if exists {name}'.format(name=db_parameters['name']))

        cnx.cursor().execute("alter session unset enable_parquet_filetype")

def test_put_copy_orc_compressed(conn_cnx, db_parameters):
    """
    Put and Copy ORC compressed files
    """
    with conn_cnx() as cnx:
        cnx.cursor().execute("""
create or replace table {name} (value variant) stage_file_format=(type='orc')
""".format(name=db_parameters['name']))

        data_file = os.path.join(THIS_DIR, "data", "TestOrcFile.test1.orc")
        with cnx.cursor() as c:
            for rec in c.execute("""
put file://{file} @%{name}""".format(file=data_file,
                                     name=db_parameters['name'])):
                print(rec)
                assert rec[-2] == 'UPLOADED'
                assert rec[4] == 'ORC'
                assert rec[5] == 'ORC'
            for rec in c.execute(
                    "copy into {name}".format(name=db_parameters['name'])):
                print(rec)
                assert rec[1] == 'LOADED'

        cnx.cursor().execute(
            'drop table if exists {name}'.format(name=db_parameters['name']))

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
    with conn_cnx() as cnx:
        cnx.cursor().execute("""
create or replace table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(5,2))
""".format(name=db_parameters['name']))
        cnx.cursor().execute("""
create or replace stage {name_unload}
url='file://{tmpdir}/'
file_format = (
format_name = 'common.public.csv'
field_delimiter = '|'
error_on_column_count_mismatch=false);
""".format(name_unload=name_unload,
           tmpdir=tmp_dir))

        current_time = datetime.datetime.utcnow()
        current_time = current_time.replace(
            tzinfo=pytz.timezone("America/Los_Angeles"))
        current_date = datetime.date.today()
        other_time = current_time.replace(tzinfo=pytz.timezone("Asia/Tokyo"))

        c = cnx.cursor()
        try:
            fmt = """
insert into {name}(aa, dt, tstz)
values(%(value)s,%(dt)s,%(tstz)s)
""".format(name=db_parameters['name'])
            c.executemany(fmt, [
                {'value': 6543, 'dt': current_date, 'tstz': other_time},
                {'value': 1234, 'dt': current_date, 'tstz': other_time},
            ])
        finally:
            c.close()

        cnx.cursor().execute("""
copy into @{name_unload}/data_
from {name}
file_format=(
format_name='common.public.csv'
compression='gzip')
max_file_size=10000000
""".format(name_unload=name_unload,
           name=db_parameters['name']))

        tmp_dir_user = str(tmpdir.mkdir('user_get'))
        cnx.cursor().execute(
            "get @{name_unload}/ file://{tmp_dir_user}/".format(
                name_unload=name_unload,
                tmp_dir_user=tmp_dir_user))

        cnt = 0
        for (_, _, _) in os.walk(tmp_dir_user):
            cnt += 1

        assert cnt > 0, 'No file was downloaded'

        cnx.cursor().execute(
            "drop stage {name_unload}".format(name_unload=name_unload))
        cnx.cursor().execute(
            "drop table if exists {table}".format(table=db_parameters['name']))


def test_put_copy_many_files(tmpdir, test_files, conn_cnx, db_parameters):
    """
    Put and Copy many_files
    """
    # generates N files
    number_of_files = 100
    number_of_lines = 1000
    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files)

    files = os.path.join(tmp_dir, 'file*')
    with conn_cnx() as cnx:
        cnx.cursor().execute("""
create or replace table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(6,2))
""".format(name=db_parameters['name']))
        cnx.cursor().execute(
            "put file://{file} @%{name}".format(file=files,
                                                name=db_parameters['name']))
        cnx.cursor().execute(
            "copy into {name}".format(name=db_parameters['name']))
        c = cnx.cursor()
        try:
            c.execute("select count(*) from {name}".format(
                name=db_parameters['name']))
            rows = 0
            for rec in c:
                rows += rec[0]
            assert rows == number_of_files * number_of_lines, 'Number of rows'
        finally:
            c.close()

        cnx.cursor().execute(
            "drop table if exists {table}".format(table=db_parameters['name']))


def test_put_copy_many_files_s3(tmpdir, test_files, conn_cnx, db_parameters):
    """
    [s3] Put and Copy many files
    """
    # generates N files
    number_of_files = 10
    number_of_lines = 1000
    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files)

    files = os.path.join(tmp_dir, 'file*')
    with conn_cnx(
            user=db_parameters['s3_user'],
            account=db_parameters['s3_account'],
            password=db_parameters['s3_password']) as cnx:
        cnx.cursor().execute("""
create or replace table {name} (
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
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            cnx.cursor().execute(
                "put file://{file} @%{name}".format(file=files,
                                                    name=db_parameters['name']))
            cnx.cursor().execute(
                "copy into {name}".format(name=db_parameters['name']))
            c = cnx.cursor()
            try:
                c.execute("select count(*) from {name}".format(
                    name=db_parameters['name']))
                rows = 0
                for rec in c:
                    rows += rec[0]
                assert rows == number_of_files * number_of_lines, \
                    'Number of rows'
            finally:
                c.close()
    finally:
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            cnx.cursor().execute(
                "drop table if exists {table}".format(
                    table=db_parameters['name']))


def test_put_copy_duplicated_files_s3(tmpdir, test_files, conn_cnx,
                                      db_parameters):
    """
    [s3] Put and Copy duplicated files
    """
    # generates N files
    number_of_files = 5
    number_of_lines = 100
    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files)

    files = os.path.join(tmp_dir, 'file*')
    with conn_cnx(
            user=db_parameters['s3_user'],
            account=db_parameters['s3_account'],
            password=db_parameters['s3_password']) as cnx:
        cnx.cursor().execute("""
create or replace table {name} (
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
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            success_cnt = 0
            skipped_cnt = 0
            c = cnx.cursor()
            try:
                for rec in c.execute(
                        "put file://{file} @%{name}".format(
                            file=files, name=db_parameters['name'])):
                    logger.info('rec=%s', rec)
                    if rec[6] == 'UPLOADED':
                        success_cnt += 1
                    elif rec[6] == 'SKIPPED':
                        skipped_cnt += 1
            finally:
                c.close()
            assert success_cnt == number_of_files, 'uploaded files'
            assert skipped_cnt == 0, 'skipped files'

            deleted_cnt = 0
            cnx.cursor().execute(
                "rm @%{name}/file0".format(name=db_parameters['name']))
            deleted_cnt += 1
            cnx.cursor().execute(
                "rm @%{name}/file1".format(name=db_parameters['name']))
            deleted_cnt += 1
            cnx.cursor().execute(
                "rm @%{name}/file2".format(name=db_parameters['name']))
            deleted_cnt += 1

            success_cnt = 0
            skipped_cnt = 0
            c = cnx.cursor()
            try:
                for rec in c.execute(
                        "put file://{file} @%{name}".format(file=files,
                                                            name=db_parameters[
                                                                'name'])):
                    logger.info('rec=%s', rec)
                    if rec[6] == 'UPLOADED':
                        success_cnt += 1
                    elif rec[6] == 'SKIPPED':
                        skipped_cnt += 1
                assert success_cnt == deleted_cnt, \
                    'uploaded files in the second time'
                assert skipped_cnt == number_of_files - deleted_cnt, \
                    'skipped files in the second time'
            finally:
                c.close()

            cnx.cursor().execute(
                "copy into {name}".format(name=db_parameters['name']))
            c = cnx.cursor()
            try:
                rows = 0
                for rec in c.execute(
                        "select count(*) from {name}".format(
                            name=db_parameters['name'])):
                    rows += rec[0]
                assert rows == number_of_files * number_of_lines, \
                    'Number of rows'
            finally:
                c.close()
    finally:
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            cnx.cursor().execute(
                "drop table if exists {table}".format(
                    table=db_parameters['name']))


def test_put_collision(tmpdir, test_files, conn_cnx, db_parameters):
    """
    File name collision
    TODO: this should be updated once non gz file support is in
    """
    # generates N files
    number_of_files = 5
    number_of_lines = 10
    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files,
                         compress=True)
    files = os.path.join(tmp_dir, 'file*')
    shutil.copy(os.path.join(tmp_dir, 'file0.gz'),
                os.path.join(tmp_dir, 'file0'))
    with conn_cnx(
            user=db_parameters['s3_user'],
            account=db_parameters['s3_account'],
            password=db_parameters['s3_password']) as cnx:
        cnx.cursor().execute("""
RM @~/test_put_collision/;
""")
        try:
            success_cnt = 0
            skipped_cnt = 0
            for rec in cnx.cursor().execute(
                    "PUT file://{file} @~/test_put_collision/".format(
                        file=files, name=db_parameters['name'])):
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
                cnx.cursor().execute("""
RM @~;
""")


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
        size = 20000000
        tmp_file = _generate_huge_value_json(tmpdir, n=rows, value_size=size)
        try:
            c = cnx.cursor()
            try:
                c.execute(
                    "put file://{tmp_file} @%{name}".format(tmp_file=tmp_file,
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


def test_put_get_large_files_s3(tmpdir, test_files, conn_cnx, db_parameters):
    """
    [s3] Put and Get Large files
    """
    number_of_files = 3
    number_of_lines = 200000
    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files)

    files = os.path.join(tmp_dir, 'file*')
    output_dir = os.path.join(tmp_dir, 'output_dir')
    os.makedirs(output_dir)
    with conn_cnx(
            user=db_parameters['s3_user'],
            account=db_parameters['s3_account'],
            password=db_parameters['s3_password']) as cnx:
        try:
            cnx.cursor().execute("""
PUT file://{files} @~/{dir}
""".format(files=files, dir=db_parameters['name']))
            all_recs = cnx.cursor().execute("""
GET @~/{dir} file://{output_dir}
""".format(dir=db_parameters['name'], output_dir=output_dir)).fetchall()
            assert len(all_recs) == number_of_files
            assert all([rec[2] == 'DOWNLOADED' for rec in all_recs])
        finally:
            cnx.cursor().execute("""
RM @~/{dir}
""".format(dir=db_parameters['name']))


def test_put_get_with_hint(tmpdir, conn_cnx, db_parameters):
    """
    SNOW-15153: PUT and GET with hint
    """
    tmp_dir = str(tmpdir.mkdir('put_get_with_hint'))
    data_file = os.path.join(THIS_DIR, "data", "put_get_1.txt")
    with conn_cnx() as cnx:
        # regular case
        ret = cnx.cursor().execute("""
PUT file://{file} @~/{name}
""".format(file=data_file, name=db_parameters['name'])).fetchone()
        assert ret[0] == 'put_get_1.txt', 'PUT filename'

        ret = cnx.cursor().execute("""
RM @~/{name}
""".format(name=db_parameters['name'])).fetchone()
        assert ret[0].endswith('put_get_1.txt.gz'), 'RM filename'

        # PUT detection failure
        with pytest.raises(ProgrammingError):
            cnx.cursor().execute("""
-- test comments
PUT file://{file} @~/{name}
""".format(file=data_file, name=db_parameters['name']))

        # PUT with hint
        ret = cnx.cursor().execute("""
--- test comments
PUT file://{file} @~/{name}
        """.format(file=data_file, name=db_parameters['name']),
                                   _is_put_get=True).fetchone()
        assert ret[0] == 'put_get_1.txt', 'PUT filename'

        # GET detection failure
        with pytest.raises(ProgrammingError):
            ret = cnx.cursor().execute("""
--- test comments
GET @~/{name} file://{dir}
                """.format(dir=tmp_dir, name=db_parameters['name'])).fetchone()

        # GET with hint
        ret = cnx.cursor().execute("""
--- test comments
GET @~/{name} file://{dir}
        """.format(dir=tmp_dir, name=db_parameters['name']),
                                   _is_put_get=True).fetchone()
        assert ret[0] == 'put_get_1.txt.gz', "GET filename"
