#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import mimetypes
import os
import time
from getpass import getuser
from logging import getLogger

import pytest


@pytest.mark.skipif(
    'AWS_ACCESS_KEY_ID' not in os.environ,
    reason="Snowflake admin account is not accessible."
)
def test_put_get_small_data_via_user_stage(
        tmpdir, test_files, conn_cnx, db_parameters):
    """
    [s3] Put and Get Small Data via User Stage
    """
    _put_get_user_stage(tmpdir, test_files, conn_cnx, db_parameters,
                        number_of_files=5, number_of_lines=10)


@pytest.mark.skipif(
    'AWS_ACCESS_KEY_ID' not in os.environ,
    reason="Snowflake admin account is not accessible."
)
def test_put_get_large_data_via_user_stage(tmpdir, test_files, conn_cnx,
                                           db_parameters):
    """
    [s3] Put and Get Large Data via User Stage
    """
    _put_get_user_stage(tmpdir, test_files, conn_cnx, db_parameters,
                        number_of_files=2,
                        number_of_lines=200000)


def _put_get_user_stage(tmpdir, test_files, conn_cnx, db_parameters,
                        number_of_files=1,
                        number_of_lines=1):
    # sanity check
    assert 'AWS_ACCESS_KEY_ID' in os.environ, 'AWS_ACCESS_KEY_ID is missing'
    assert 'AWS_SECRET_ACCESS_KEY' in os.environ, \
        'AWS_SECRET_ACCESS_KEY is missing'

    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files)

    files = os.path.join(tmp_dir, 'file*')

    stage_name = db_parameters['name'] + '_stage_{0}_{1}'.format(
        number_of_files,
        number_of_lines)
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
        user_bucket = os.getenv('SF_AWS_USER_BUCKET',
                                "sfc-dev1-regression/{0}/reg".format(
                                    getuser()))
        cnx.cursor().execute("""
create or replace stage {stage_name}
url='s3://{user_bucket}/{stage_name}-{number_of_files}-{number_of_lines}'
credentials=(
 AWS_KEY_ID='{aws_key_id}'
 AWS_SECRET_KEY='{aws_secret_key}'
)
""".format(stage_name=stage_name, user_bucket=user_bucket,
           aws_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
           aws_secret_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
           number_of_files=number_of_files,
           number_of_lines=number_of_lines))
    try:
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            cnx.cursor().execute(
                "alter session set disable_put_and_get_on_external_stage = false")
            cnx.cursor().execute(
                "rm @{stage_name}".format(stage_name=stage_name))
            cnx.cursor().execute(
                "put file://{file} @{stage_name}".format(
                    file=files,
                    stage_name=stage_name))
            cnx.cursor().execute(
                "copy into {name} from @{stage_name}".format(
                    name=db_parameters['name'], stage_name=stage_name))
            c = cnx.cursor()
            try:
                c.execute(
                    "select count(*) from {name}".format(
                        name=db_parameters['name']))
                rows = 0
                for rec in c:
                    rows += rec[0]
                assert rows == number_of_files * number_of_lines, \
                    'Number of rows'
            finally:
                c.close()
            cnx.cursor().execute(
                "rm @{stage_name}".format(stage_name=stage_name))
            cnx.cursor().execute(
                "copy into @{stage_name} from {name}".format(
                    name=db_parameters['name'], stage_name=stage_name))
            tmp_dir_user = str(tmpdir.mkdir('put_get_stage'))
            cnx.cursor().execute(
                "get @{stage_name}/ file://{tmp_dir_user}/".format(
                    stage_name=stage_name,
                    tmp_dir_user=tmp_dir_user))
            for root, _, files in os.walk(tmp_dir_user):
                for file in files:
                    mimetypes.init()
                    _, encoding = mimetypes.guess_type(file)
                    assert encoding == 'gzip', "exported file type"
    finally:
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            cnx.cursor().execute(
                "rm @{stage_name}".format(stage_name=stage_name))
            cnx.cursor().execute(
                "drop stage if exists {stage_name}".format(
                    stage_name=stage_name))
            cnx.cursor().execute(
                "drop table if exists {name}".format(
                    name=db_parameters['name']))


@pytest.mark.skipif(
    'AWS_ACCESS_KEY_ID' not in os.environ,
    reason="Snowflake admin account is not accessible."
)
def test_put_get_duplicated_data_user_stage(tmpdir, test_files, conn_cnx,
                                            db_parameters,
                                            number_of_files=5,
                                            number_of_lines=100):
    """
    [s3] Put and Get Duplicated Data using User Stage
    """
    logger = getLogger(__name__)
    assert 'AWS_ACCESS_KEY_ID' in os.environ, 'AWS_ACCESS_KEY_ID is missing'
    assert 'AWS_SECRET_ACCESS_KEY' in os.environ, \
        'AWS_SECRET_ACCESS_KEY is missing'

    tmp_dir = test_files(tmpdir, number_of_lines, number_of_files)

    files = os.path.join(tmp_dir, 'file*')

    stage_name = db_parameters['name'] + '_stage'
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
        user_bucket = os.getenv('SF_AWS_USER_BUCKET',
                                "sfc-dev1-regression/{0}/reg".format(
                                    getuser()))
        cnx.cursor().execute("""
create or replace stage {stage_name}
url='s3://{user_bucket}/{stage_name}-{number_of_files}-{number_of_lines}'
credentials=(
 AWS_KEY_ID='{aws_key_id}'
 AWS_SECRET_KEY='{aws_secret_key}'
)
""".format(stage_name=stage_name, user_bucket=user_bucket,
           aws_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
           aws_secret_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
           number_of_files=number_of_files,
           number_of_lines=number_of_lines))
    try:
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            c = cnx.cursor()
            try:
                for rec in c.execute(
                        "rm @{stage_name}".format(stage_name=stage_name)):
                    logger.info('rec=%s', rec)
            finally:
                c.close()

            success_cnt = 0
            skipped_cnt = 0
            c = cnx.cursor()
            c.execute(
                "alter session set disable_put_and_get_on_external_stage = false")
            try:
                for rec in c.execute(
                        "put file://{file} @{stage_name}".format(
                            file=files, stage_name=stage_name)):
                    logger.info('rec=%s', rec)
                    if rec[6] == 'UPLOADED':
                        success_cnt += 1
                    elif rec[6] == 'SKIPPED':
                        skipped_cnt += 1
            finally:
                c.close()
            assert success_cnt == number_of_files, 'uploaded files'
            assert skipped_cnt == 0, 'skipped files'

            logger.info('deleting files in {stage_name}'.format(
                stage_name=stage_name))

            deleted_cnt = 0
            cnx.cursor().execute(
                "rm @{stage_name}/file0".format(stage_name=stage_name))
            deleted_cnt += 1
            cnx.cursor().execute(
                "rm @{stage_name}/file1".format(stage_name=stage_name))
            deleted_cnt += 1
            cnx.cursor().execute(
                "rm @{stage_name}/file2".format(stage_name=stage_name))
            deleted_cnt += 1

            success_cnt = 0
            skipped_cnt = 0
            c = cnx.cursor()
            try:
                for rec in c.execute(
                        "put file://{file} @{stage_name}".format(
                            file=files, stage_name=stage_name)):
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

            time.sleep(5)
            cnx.cursor().execute(
                "copy into {name} from @{stage_name}".format(
                    name=db_parameters['name'], stage_name=stage_name))
            c = cnx.cursor()
            try:
                c.execute(
                    "select count(*) from {name}".format(
                        name=db_parameters['name']))
                rows = 0
                for rec in c:
                    rows += rec[0]
                assert rows == number_of_files * number_of_lines, 'Number of rows'
            finally:
                c.close()
            cnx.cursor().execute(
                "rm @{stage_name}".format(stage_name=stage_name))
            cnx.cursor().execute(
                "copy into @{stage_name} from {name}".format(
                    name=db_parameters['name'], stage_name=stage_name))
            tmp_dir_user = str(tmpdir.mkdir('stage2'))
            cnx.cursor().execute(
                "get @{stage_name}/ file://{tmp_dir_user}/".format(
                    stage_name=stage_name,
                    tmp_dir_user=tmp_dir_user))
            for root, _, files in os.walk(tmp_dir_user):
                for file in files:
                    mimetypes.init()
                    _, encoding = mimetypes.guess_type(file)
                    assert encoding == 'gzip', "exported file type"

    finally:
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            cnx.cursor().execute(
                "drop stage if exists {stage_name}".format(
                    stage_name=stage_name))
            cnx.cursor().execute(
                "drop table if exists {name}".format(
                    name=db_parameters['name']))


@pytest.mark.skipif(
    'AWS_ACCESS_KEY_ID' not in os.environ,
    reason="Snowflake admin account is not accessible."
)
def test_get_data_user_stage(tmpdir, conn_cnx, db_parameters):
    """
    SNOW-20927: get failed with 404 error
    """
    assert 'AWS_ACCESS_KEY_ID' in os.environ, 'AWS_ACCESS_KEY_ID is missing'
    assert 'AWS_SECRET_ACCESS_KEY' in os.environ, \
        'AWS_SECRET_ACCESS_KEY is missing'

    default_s3bucket = os.getenv('SF_AWS_USER_BUCKET',
                                 "sfc-dev1-regression/{0}/reg".format(
                                     getuser()))
    test_data = [
        {
            's3location':
                '{0}/{1}'.format(
                    default_s3bucket, db_parameters['name'] + '_stage'),
            'stage_name': db_parameters['name'] + '_stage1',
            'data_file_name': 'data.txt',
        },
    ]
    for elem in test_data:
        _put_list_rm_files_in_stage(tmpdir, conn_cnx, db_parameters, elem)


def _put_list_rm_files_in_stage(tmpdir, conn_cnx, db_parameters, elem):
    s3location = elem['s3location']
    stage_name = elem['stage_name']
    data_file_name = elem['data_file_name']

    from io import open
    from snowflake.connector.compat import (UTF8, TO_UNICODE)
    tmp_dir = str(tmpdir.mkdir('data'))
    data_file = os.path.join(tmp_dir, data_file_name)
    with open(data_file, 'w', encoding=UTF8) as f:
        f.write(TO_UNICODE("123,456,string1\n"))
        f.write(TO_UNICODE("789,012,string2\n"))

    output_dir = str(tmpdir.mkdir('output'))
    with conn_cnx(
            user=db_parameters['s3_user'],
            account=db_parameters['s3_account'],
            password=db_parameters['s3_password']) as cnx:
        cnx.cursor().execute("""
create or replace stage {stage_name}
    url='s3://{s3location}'
    credentials=(
        AWS_KEY_ID='{aws_key_id}'
        AWS_SECRET_KEY='{aws_secret_key}'
    )
""".format(
            s3location=s3location,
            stage_name=stage_name,
            aws_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_key=os.getenv('AWS_SECRET_ACCESS_KEY')
        ))
    try:
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            cnx.cursor().execute("""
RM @{stage_name}
""".format(stage_name=stage_name))
            cnx.cursor().execute(
                "alter session set disable_put_and_get_on_external_stage = false")
            rec = cnx.cursor().execute("""
PUT file://{file} @{stage_name}
""".format(file=data_file, stage_name=stage_name)).fetchone()
            assert rec[0] == data_file_name
            assert rec[6] == 'UPLOADED'
            rec = cnx.cursor().execute("""
LIST @{stage_name}
            """.format(stage_name=stage_name, output_dir=output_dir)).fetchone()
            assert rec, 'LIST should return something'
            assert rec[0].startswith('s3://'), "The file location in S3"
            rec = cnx.cursor().execute("""
GET @{stage_name} file://{output_dir}
""".format(stage_name=stage_name, output_dir=output_dir)).fetchone()
            assert rec[0] == data_file_name + '.gz'
            assert rec[2] == 'DOWNLOADED'
    finally:
        with conn_cnx(
                user=db_parameters['s3_user'],
                account=db_parameters['s3_account'],
                password=db_parameters['s3_password']) as cnx:
            cnx.cursor().execute("""
RM @{stage_name}
""".format(stage_name=stage_name))
            cnx.cursor().execute(
                "drop stage if exists {stage_name}".format(
                    stage_name=stage_name))
