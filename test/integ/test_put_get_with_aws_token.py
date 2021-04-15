#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import glob
import gzip
import os

import boto3
import pytest
from boto3.exceptions import S3UploadFailedError
from botocore.exceptions import ClientError

from snowflake.connector.constants import UTF8
from snowflake.connector.file_transfer_agent import SnowflakeS3ProgressPercentage
from snowflake.connector.s3_util import SnowflakeS3Util

from ..integ_helpers import put
from ..randomize import random_string

# Mark every test in this module as an aws test
pytestmark = pytest.mark.aws


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
def test_put_get_with_aws(tmpdir, conn_cnx, db_parameters, from_path):
    """[s3] Puts and Gets a small text using AWS S3."""
    # create a data file
    fname = str(tmpdir.join("test_put_get_with_aws_token.txt.gz"))
    original_contents = "123,test1\n456,test2\n"
    with gzip.open(fname, "wb") as f:
        f.write(original_contents.encode(UTF8))
    tmp_dir = str(tmpdir.mkdir("test_put_get_with_aws_token"))
    table_name = random_string(5, "snow9144_")

    with conn_cnx() as cnx:
        with cnx.cursor() as csr:
            try:
                csr.execute(
                    "create or replace table {} (a int, b string)".format(table_name)
                )
                file_stream = None if from_path else open(fname, "rb")
                put(
                    csr,
                    fname,
                    f"%{table_name}",
                    from_path,
                    sql_options=" auto_compress=true parallel=30",
                    _put_callback=SnowflakeS3ProgressPercentage,
                    _get_callback=SnowflakeS3ProgressPercentage,
                    file_stream=file_stream,
                )
                rec = csr.fetchone()
                assert rec[6] == "UPLOADED"
                csr.execute("copy into {}".format(table_name))
                csr.execute("rm @%{}".format(table_name))
                assert csr.execute("ls @%{}".format(table_name)).fetchall() == []
                csr.execute(
                    "copy into @%{table_name} from {table_name} "
                    "file_format=(type=csv compression='gzip')".format(
                        table_name=table_name
                    )
                )
                csr.execute(
                    "get @%{table_name} file://{}".format(
                        tmp_dir, table_name=table_name
                    ),
                    _put_callback=SnowflakeS3ProgressPercentage,
                    _get_callback=SnowflakeS3ProgressPercentage,
                )
                rec = csr.fetchone()
                assert rec[0].startswith("data_"), "A file downloaded by GET"
                assert rec[1] == 36, "Return right file size"
                assert rec[2] == "DOWNLOADED", "Return DOWNLOADED status"
                assert rec[3] == "", "Return no error message"
            finally:
                csr.execute("drop table {}".format(table_name))
                if file_stream:
                    file_stream.close()

    files = glob.glob(os.path.join(tmp_dir, "data_*"))
    with gzip.open(files[0], "rb") as fd:
        contents = fd.read().decode(UTF8)
    assert original_contents == contents, "Output is different from the original file"


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
def test_put_with_invalid_token(tmpdir, conn_cnx, db_parameters, from_path):
    """[s3] SNOW-6154: Uses invalid combination of AWS credential."""
    # create a data file
    fname = str(tmpdir.join("test_put_get_with_aws_token.txt.gz"))
    with gzip.open(fname, "wb") as f:
        f.write("123,test1\n456,test2".encode(UTF8))
    table_name = random_string(5, "snow6154_")

    with conn_cnx() as cnx:
        try:
            cnx.cursor().execute(
                "create or replace table {} (a int, b string)".format(table_name)
            )
            ret = cnx.cursor()._execute_helper(
                "put file://{} @%{}".format(fname, table_name)
            )
            stage_location = ret["data"]["stageInfo"]["location"]
            stage_credentials = ret["data"]["stageInfo"]["creds"]

            s3location = SnowflakeS3Util.extract_bucket_name_and_path(stage_location)

            s3path = s3location.s3path + os.path.basename(fname) + ".gz"

            # positive case
            client = boto3.resource(
                "s3",
                aws_access_key_id=stage_credentials["AWS_ID"],
                aws_secret_access_key=stage_credentials["AWS_KEY"],
                aws_session_token=stage_credentials["AWS_TOKEN"],
            )

            file_stream = None if from_path else open(fname, "rb")

            if from_path:
                client.meta.client.upload_file(fname, s3location.bucket_name, s3path)
            else:
                client.meta.client.upload_fileobj(
                    file_stream, s3location.bucket_name, s3path
                )

            # s3 closes stream
            file_stream = None if from_path else open(fname, "rb")

            # negative: wrong location, attempting to put the file in the
            # parent path
            parent_s3path = os.path.dirname(os.path.dirname(s3path)) + "/"

            with pytest.raises((S3UploadFailedError, ClientError)):
                if from_path:
                    client.meta.client.upload_file(
                        fname, s3location.bucket_name, parent_s3path
                    )
                else:
                    client.meta.client.upload_fileobj(
                        file_stream, s3location.bucket_name, parent_s3path
                    )

            # s3 closes stream
            file_stream = None if from_path else open(fname, "rb")

            # negative: missing AWS_TOKEN
            client = boto3.resource(
                "s3",
                aws_access_key_id=stage_credentials["AWS_ID"],
                aws_secret_access_key=stage_credentials["AWS_KEY"],
            )

            with pytest.raises((S3UploadFailedError, ClientError)):
                if from_path:
                    client.meta.client.upload_file(
                        fname, s3location.bucket_name, s3path
                    )
                else:
                    client.meta.client.upload_fileobj(
                        file_stream, s3location.bucket_name, s3path
                    )
        finally:
            if file_stream:
                file_stream.close()
            cnx.cursor().execute("drop table if exists {}".format(table_name))


def _s3bucket_list(client, s3bucket):
    """Attempts to get the keys from the list. Must raise an exception."""
    s3bucket = client.Bucket(s3bucket)
    return list(s3bucket.objects.iterator())  # list cast is to trigger lazy evaluation


def test_pretend_to_put_but_list(tmpdir, conn_cnx, db_parameters):
    """[s3] SNOW-6154: Pretends to PUT but LIST."""
    # create a data file
    fname = str(tmpdir.join("test_put_get_with_aws_token.txt"))
    with gzip.open(fname, "wb") as f:
        f.write("123,test1\n456,test2".encode(UTF8))
    table_name = random_string(5, "snow6154_list_")

    with conn_cnx() as cnx:
        cnx.cursor().execute(
            "create or replace table {} (a int, b string)".format(table_name)
        )
        ret = cnx.cursor()._execute_helper(
            "put file://{} @%{}".format(fname, table_name)
        )
        stage_location = ret["data"]["stageInfo"]["location"]
        stage_credentials = ret["data"]["stageInfo"]["creds"]

        s3location = SnowflakeS3Util.extract_bucket_name_and_path(stage_location)

        # listing
        client = boto3.resource(
            "s3",
            aws_access_key_id=stage_credentials["AWS_ID"],
            aws_secret_access_key=stage_credentials["AWS_KEY"],
            aws_session_token=stage_credentials["AWS_TOKEN"],
        )
        from botocore.exceptions import ClientError

        with pytest.raises(ClientError):
            _s3bucket_list(client, s3location.bucket_name)
