#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import glob
import gzip
import os

import boto3
import pytest

from snowflake.connector.constants import UTF8
from snowflake.connector.s3_util import SnowflakeS3Util

# Mark every test in this module as an aws test
pytestmark = pytest.mark.aws

try:
    from parameters import (CONNECTION_PARAMETERS_ADMIN)
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_get_with_aws(tmpdir, conn_cnx, db_parameters):
    """[s3] Puts and Gets a small text using AWS S3."""
    # create a data file
    fname = str(tmpdir.join('test_put_get_with_aws_token.txt.gz'))
    f = gzip.open(fname, 'wb')
    original_contents = "123,test1\n456,test2\n"
    f.write(original_contents.encode(UTF8))
    f.close()
    tmp_dir = str(tmpdir.mkdir('test_put_get_with_aws_token'))

    with conn_cnx(
            user=db_parameters['user'],
            account=db_parameters['account'],
            password=db_parameters['password']) as cnx:
        cnx.cursor().execute("rm @~/snow9144")
        cnx.cursor().execute(
            "create or replace table snow9144 (a int, b string)")
    try:
        with conn_cnx(
                user=db_parameters['user'],
                account=db_parameters['account'],
                password=db_parameters['password']) as cnx:
            cnx.cursor().execute(
                "put file://{} @%snow9144 auto_compress=true parallel=30".format(
                    fname))
            cnx.cursor().execute("copy into snow9144")
            cnx.cursor().execute(
                "copy into @~/snow9144 from snow9144 "
                "file_format=( format_name='common.public.csv' "
                "compression='gzip')")
            c = cnx.cursor()
            c.execute(
                "get @~/snow9144 file://{} pattern='snow9144.*'".format(
                    tmp_dir))
            rec = c.fetchone()
            assert rec[0].startswith('snow9144'), 'A file downloaded by GET'
            assert rec[1] == 36, 'Return right file size'
            assert rec[2] == 'DOWNLOADED', 'Return DOWNLOADED status'
            assert rec[3] == '', 'Return no error message'
            cnx.cursor().execute("rm @%snow9144")
            cnx.cursor().execute("rm @~/snow9144")
    finally:
        with conn_cnx(
                user=db_parameters['user'],
                account=db_parameters['account'],
                password=db_parameters['password']) as cnx:
            cnx.cursor().execute("drop table snow9144")

    files = glob.glob(os.path.join(tmp_dir, 'snow9144*'))
    contents = ''
    fd = gzip.open(files[0], 'rb')
    for line in fd:
        contents += line.decode(UTF8)
    fd.close()
    assert original_contents == contents, (
        'Output is different from the original file')


@pytest.mark.skipif(
    'AWS_ACCESS_KEY_ID' not in os.environ,
    reason="Snowflake admin account is not accessible."
)
def test_put_with_invalid_token(tmpdir, conn_cnx, db_parameters):
    """[s3] SNOW-6154: Uses invalid combination of AWS credential."""
    # create a data file
    fname = str(tmpdir.join('test_put_get_with_aws_token.txt.gz'))
    f = gzip.open(fname, 'wb')
    f.write("123,test1\n456,test2".encode(UTF8))
    f.close()

    with conn_cnx(
            user=db_parameters['user'],
            account=db_parameters['account'],
            password=db_parameters['password']) as cnx:
        cnx.cursor().execute(
            "create or replace table snow6154 (a int, b string)")
        ret = cnx.cursor()._execute_helper(
            "put file://{} @%snow6154".format(fname))
        stage_location = ret['data']['stageInfo']['location']
        stage_credentials = ret['data']['stageInfo']['creds']

        s3location = SnowflakeS3Util.extract_bucket_name_and_path(
            stage_location)

        s3path = s3location.s3path + os.path.basename(fname) + ".gz"

        # positive case
        client = boto3.resource(
            's3',
            aws_access_key_id=stage_credentials['AWS_ID'],
            aws_secret_access_key=stage_credentials['AWS_KEY'],
            aws_session_token=stage_credentials['AWS_TOKEN'])

        client.meta.client.upload_file(
            fname, s3location.bucket_name, s3path)

        # negative: wrong location, attempting to put the file in the
        # parent path
        parent_s3path = os.path.dirname(os.path.dirname(s3path)) + '/'

        with pytest.raises(Exception):
            client.meta.client.upload_file(
                fname, s3location.bucket_name, parent_s3path)

        # negative: missing AWS_TOKEN
        client = boto3.resource(
            's3',
            aws_access_key_id=stage_credentials['AWS_ID'],
            aws_secret_access_key=stage_credentials['AWS_KEY'])
        with pytest.raises(Exception):
            client.meta.client.upload_file(
                fname, s3location.bucket_name, s3path)


def _s3bucket_list(self, client, s3bucket):
    """Attempts to get the keys from the list. Must raise an exception."""
    s3bucket = client.Bucket(s3bucket)
    return [key for key in s3bucket.objects]


@pytest.mark.skipif(
    'AWS_ACCESS_KEY_ID' not in os.environ,
    reason="Snowflake admin account is not accessible."
)
def test_pretend_to_put_but_list(tmpdir, conn_cnx, db_parameters):
    """[s3] SNOW-6154: Pretends to PUT but LIST."""
    # create a data file
    fname = str(tmpdir.join('test_put_get_with_aws_token.txt'))
    f = gzip.open(fname, 'wb')
    f.write("123,test1\n456,test2".encode(UTF8))
    f.close()

    with conn_cnx(
            user=db_parameters['user'],
            account=db_parameters['account'],
            password=db_parameters['password']) as cnx:
        cnx.cursor().execute(
            "create or replace table snow6154 (a int, b string)")
        ret = cnx.cursor()._execute_helper(
            "put file://{} @%snow6154".format(fname))
        stage_location = ret['data']['stageInfo']['location']
        stage_credentials = ret['data']['stageInfo']['creds']

        s3location = SnowflakeS3Util.extract_bucket_name_and_path(
            stage_location)

        # listing
        client = boto3.resource(
            's3',
            aws_access_key_id=stage_credentials['AWS_ID'],
            aws_secret_access_key=stage_credentials['AWS_KEY'],
            aws_session_token=stage_credentials['AWS_TOKEN'])
        with pytest.raises(Exception):
            _s3bucket_list(client, s3location.bucket_name)
