#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import glob
import gzip
import os
import sys
import time
from filecmp import cmp
from logging import getLogger

import mock
import pytest
import requests

from snowflake.connector.constants import UTF8
from snowflake.connector.file_transfer_agent import SnowflakeFileTransferAgent

try:
    from parameters import (CONNECTION_PARAMETERS_ADMIN)
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

logger = getLogger(__name__)

# Mark every test in this module as a putget test
pytestmark = pytest.mark.putget


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_get_with_gcp(tmpdir, conn_cnx, db_parameters):
    """
    [gcp] Put and Get a small text using gcp
    """
    # create a data file
    fname = str(tmpdir.join('test_put_get_with_gcp_token.txt.gz'))
    with gzip.open(fname, 'wb') as f:
        original_contents = "123,test1\n456,test2\n"
        f.write(original_contents.encode(UTF8))
    tmp_dir = str(tmpdir.mkdir('test_put_get_with_gcp_token'))

    with conn_cnx(
            user=db_parameters['gcp_user'],
            account=db_parameters['gcp_account'],
            password=db_parameters['gcp_password']) as cnx:
        with cnx.cursor() as csr:
            csr.execute("rm @~/snow32806")
            csr.execute(
                "create or replace table snow32806 (a int, b string)")
            try:

                csr.execute(
                    "put file://{} @%snow32806 auto_compress=true parallel=30".format(
                        fname))
                rec = csr.fetchone()
                assert rec[6] == u'UPLOADED'
                csr.execute("copy into snow32806")
                csr.execute(
                    "copy into @~/snow32806 from snow32806 "
                    "file_format=( format_name='common.public.csv' "
                    "compression='gzip')")
                csr.execute(
                    "get @~/snow32806 file://{} pattern='snow32806.*'".format(
                        tmp_dir))
                rec = csr.fetchone()
                assert rec[0].startswith(
                    'snow32806'), 'A file downloaded by GET'
                assert rec[1] == 36, 'Return right file size'
                assert rec[2] == u'DOWNLOADED', 'Return DOWNLOADED status'
                assert rec[3] == u'', 'Return no error message'
            finally:
                csr.execute("drop table snow32806")
                csr.execute("rm @~/snow32806")

    files = glob.glob(os.path.join(tmp_dir, 'snow32806*'))
    with gzip.open(files[0], 'rb') as fd:
        contents = fd.read().decode(UTF8)
    assert original_contents == contents, (
        'Output is different from the original file')


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_copy_many_files_gcp(tmpdir, test_files, conn_cnx, db_parameters):
    """
    [gcp] Put and Copy many files
    """
    # generates N files
    number_of_files = 10
    number_of_lines = 1000
    tmp_dir = test_files(number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir('data')))

    files = os.path.join(tmp_dir, 'file*')

    def run(csr, sql):
        sql = sql.format(
            files=files,
            name=db_parameters['name'])
        return csr.execute(sql).fetchall()

    with conn_cnx(
            user=db_parameters['gcp_user'],
            account=db_parameters['gcp_account'],
            password=db_parameters['gcp_password']) as cnx:
        with cnx.cursor() as csr:
            run(csr, """
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
                all_recs = run(csr, "put file://{files} @%{name}")
                assert all([rec[6] == u'UPLOADED' for rec in all_recs])
                run(csr, "copy into {name}")

                rows = sum([rec[0] for rec in run(csr, "select count(*) from "
                                                       "{name}")])
                assert rows == number_of_files * number_of_lines, \
                    'Number of rows'
            finally:
                run(csr, "drop table if exists {name}")


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_copy_duplicated_files_gcp(tmpdir, test_files, conn_cnx,
                                         db_parameters):
    """
    [gcp] Put and Copy duplicated files
    """
    # generates N files
    number_of_files = 5
    number_of_lines = 100
    tmp_dir = test_files(number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir('data')))

    files = os.path.join(tmp_dir, 'file*')

    def run(csr, sql):
        sql = sql.format(
            files=files,
            name=db_parameters['name'])
        return csr.execute(sql).fetchall()

    with conn_cnx(
            user=db_parameters['gcp_user'],
            account=db_parameters['gcp_account'],
            password=db_parameters['gcp_password']) as cnx:
        with cnx.cursor() as csr:
            run(csr, """
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
                success_cnt = 0
                skipped_cnt = 0
                for rec in run(csr, "put file://{files} @%{name}"):
                    logger.info('rec=%s', rec)
                    if rec[6] == 'UPLOADED':
                        success_cnt += 1
                    elif rec[6] == 'SKIPPED':
                        skipped_cnt += 1
                assert success_cnt == number_of_files, 'uploaded files'
                assert skipped_cnt == 0, 'skipped files'

                deleted_cnt = 0
                run(csr, "rm @%{name}/file0")
                deleted_cnt += 1
                run(csr, "rm @%{name}/file1")
                deleted_cnt += 1
                run(csr, "rm @%{name}/file2")
                deleted_cnt += 1

                success_cnt = 0
                skipped_cnt = 0
                for rec in run(csr, "put file://{files} @%{name}"):
                    logger.info('rec=%s', rec)
                    if rec[6] == 'UPLOADED':
                        success_cnt += 1
                    elif rec[6] == 'SKIPPED':
                        skipped_cnt += 1
                assert success_cnt == number_of_files, \
                    'uploaded files in the second time'
                assert skipped_cnt == 0, \
                    'skipped files in the second time'

                run(csr, "copy into {name}")
                rows = 0
                for rec in run(csr, "select count(*) from {name}"):
                    rows += rec[0]
                assert rows == number_of_files * number_of_lines, \
                    'Number of rows'
            finally:
                run(csr, "drop table if exists {name}")


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_get_large_files_gcp(tmpdir, test_files, conn_cnx, db_parameters):
    """
    [gcp] Put and Get Large files
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
                files=files,
                dir=db_parameters['name'],
                output_dir=output_dir),
            _put_callback_output_stream=sys.stdout,
            _get_callback_output_stream=sys.stdout,
            _get_callback=cb,
            _put_callback=cb).fetchall()

    with conn_cnx(
            user=db_parameters['gcp_user'],
            account=db_parameters['gcp_account'],
            password=db_parameters['gcp_password']) as cnx:
        try:
            all_recs = run(cnx, "PUT file://{files} @~/{dir}")
            assert all([rec[6] == u'UPLOADED' for rec in all_recs])

            for _ in range(60):
                for _ in range(100):
                    all_recs = run(cnx, "LIST @~/{dir}")
                    if len(all_recs) == number_of_files:
                        break
                    # you may not get the files right after PUT command
                    # due to the nature of gcs blob, which synchronizes
                    # data eventually.
                    time.sleep(1)
                else:
                    # wait for another second and retry.
                    # this could happen if the files are partially available
                    # but not all.
                    time.sleep(1)
                    continue
                break  # success
            else:
                pytest.fail(
                    'cannot list all files. Potentially '
                    'PUT command missed uploading Files: {}'.format(all_recs))
            all_recs = run(cnx, "GET @~/{dir} file://{output_dir}")
            assert len(all_recs) == number_of_files
            assert all([rec[2] == 'DOWNLOADED' for rec in all_recs])
        finally:
            run(cnx, "RM @~/{dir}")


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_get_gcp_file_object_http_400_error(tmpdir, conn_cnx, db_parameters):
    fname = str(tmpdir.join('test_put_get_with_gcp_token.txt.gz'))
    with gzip.open(fname, 'wb') as f:
        original_contents = "123,test1\n456,test2\n"
        f.write(original_contents.encode(UTF8))
    tmp_dir = str(tmpdir.mkdir('test_put_get_with_gcp_token'))

    with conn_cnx(
            user=db_parameters['gcp_user'],
            account=db_parameters['gcp_account'],
            password=db_parameters['gcp_password']) as cnx:
        with cnx.cursor() as csr:
            csr.execute("rm @~/snow32807")
            csr.execute(
                "create or replace table snow32807 (a int, b string)")
            try:
                from requests import put, get

                def mocked_put(*args, **kwargs):
                    if mocked_put.counter == 0:
                        mocked_put.counter += 1
                        exc = requests.exceptions.HTTPError(response=requests.Response())
                        exc.response.status_code = 400
                        raise exc
                    else:
                        return put(*args, **kwargs)
                mocked_put.counter = 0

                def mocked_file_agent(*args, **kwargs):
                    agent = SnowflakeFileTransferAgent(*args, **kwargs)
                    agent._update_file_metas_with_presigned_url = mock.MagicMock(
                        wraps=agent._update_file_metas_with_presigned_url
                    )
                    mocked_file_agent.agent = agent
                    return agent
                with mock.patch('snowflake.connector.cursor.SnowflakeFileTransferAgent',
                                side_effect=mocked_file_agent):
                    with mock.patch('requests.put', side_effect=mocked_put):
                        csr.execute(
                            "put file://{} @%snow32807 auto_compress=true parallel=30".format(
                                fname))
                    assert mocked_file_agent.agent._update_file_metas_with_presigned_url.call_count == 2
                rec = csr.fetchone()
                assert rec[6] == u'UPLOADED'
                csr.execute("copy into snow32807")
                csr.execute(
                    "copy into @~/snow32807 from snow32807 "
                    "file_format=( format_name='common.public.csv' "
                    "compression='gzip')")

                def mocked_get(*args, **kwargs):
                    if mocked_get.counter == 0:
                        mocked_get.counter += 1
                        exc = requests.exceptions.HTTPError(response=requests.Response())
                        exc.response.status_code = 400
                        raise exc
                    else:
                        return get(*args, **kwargs)
                mocked_get.counter = 0

                def mocked_file_agent(*args, **kwargs):
                    agent = SnowflakeFileTransferAgent(*args, **kwargs)
                    agent._update_file_metas_with_presigned_url = mock.MagicMock(
                        wraps=agent._update_file_metas_with_presigned_url
                    )
                    mocked_file_agent.agent = agent
                    return agent
                with mock.patch('snowflake.connector.cursor.SnowflakeFileTransferAgent',
                                side_effect=mocked_file_agent):
                    with mock.patch('requests.get', side_effect=mocked_get):
                        csr.execute(
                            "get @~/snow32807 file://{} pattern='snow32807.*'".format(
                                tmp_dir))
                    assert mocked_file_agent.agent._update_file_metas_with_presigned_url.call_count == 2
                rec = csr.fetchone()
                assert rec[0].startswith(
                    'snow32807'), 'A file downloaded by GET'
                assert rec[1] == 36, 'Return right file size'
                assert rec[2] == u'DOWNLOADED', 'Return DOWNLOADED status'
                assert rec[3] == u'', 'Return no error message'
            finally:
                csr.execute("drop table snow32807")
                csr.execute("rm @~/snow32807")

    files = glob.glob(os.path.join(tmp_dir, 'snow32807*'))
    with gzip.open(files[0], 'rb') as fd:
        contents = fd.read().decode(UTF8)
    assert original_contents == contents, (
        'Output is different from the original file')


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_auto_compress_off_gcp(tmpdir, conn_cnx, db_parameters):
    """
    [gcp] Put and Get a small text using gcp with no auto compression
    """
    fname = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'example.json'))
    with conn_cnx(
            user=db_parameters['gcp_user'],
            account=db_parameters['gcp_account'],
            password=db_parameters['gcp_password'],
    ) as cnx:
        with cnx.cursor() as cursor:
            try:
                cursor.execute("create or replace stage teststage")
                cursor.execute("put file://{} @teststage auto_compress=false".format(fname))
                cursor.execute("get @teststage file://{}".format(str(tmpdir)))
                downloaded_file = os.path.join(str(tmpdir), 'example.json')
                assert cmp(fname, downloaded_file)
            finally:
                cursor.execute("drop stage teststage")
