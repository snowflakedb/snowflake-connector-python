#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import glob
import gzip
import os

import pytest
from aiohttp import ClientResponseError

from snowflake.connector.constants import UTF8

try:  # pragma: no cover
    from snowflake.connector.aio._file_transfer_agent import SnowflakeFileMeta
    from snowflake.connector.aio._s3_storage_client import (
        S3Location,
        SnowflakeS3RestClient,
    )
    from snowflake.connector.file_transfer_agent import StorageCredential
except ImportError:
    pass

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from test.randomize import random_string

from test.integ_helpers import put_async

# Mark every test in this module as an aws test
pytestmark = [pytest.mark.asyncio, pytest.mark.aws]


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
async def test_put_get_with_aws(tmpdir, aio_connection, from_path):
    """[s3] Puts and Gets a small text using AWS S3."""
    # create a data file
    fname = str(tmpdir.join("test_put_get_with_aws_token.txt.gz"))
    original_contents = "123,test1\n456,test2\n"
    with gzip.open(fname, "wb") as f:
        f.write(original_contents.encode(UTF8))
    tmp_dir = str(tmpdir.mkdir("test_put_get_with_aws_token"))
    table_name = random_string(5, "snow9144_")

    await aio_connection.connect()
    csr = aio_connection.cursor()

    try:
        await csr.execute(f"create or replace table {table_name} (a int, b string)")
        file_stream = None if from_path else open(fname, "rb")
        await put_async(
            csr,
            fname,
            f"%{table_name}",
            from_path,
            sql_options=" auto_compress=true parallel=30",
            file_stream=file_stream,
        )
        rec = await csr.fetchone()
        assert rec[6] == "UPLOADED"
        await csr.execute(f"copy into {table_name}")
        await csr.execute(f"rm @%{table_name}")
        assert await (await csr.execute(f"ls @%{table_name}")).fetchall() == []
        await csr.execute(
            f"copy into @%{table_name} from {table_name} "
            "file_format=(type=csv compression='gzip')"
        )
        await csr.execute(f"get @%{table_name} file://{tmp_dir}")
        rec = await csr.fetchone()
        assert rec[0].startswith("data_"), "A file downloaded by GET"
        assert rec[1] == 36, "Return right file size"
        assert rec[2] == "DOWNLOADED", "Return DOWNLOADED status"
        assert rec[3] == "", "Return no error message"
    finally:
        await csr.execute(f"drop table {table_name}")
        if file_stream:
            file_stream.close()

    files = glob.glob(os.path.join(tmp_dir, "data_*"))
    with gzip.open(files[0], "rb") as fd:
        contents = fd.read().decode(UTF8)
    assert original_contents == contents, "Output is different from the original file"


@pytest.mark.skipolddriver
async def test_put_with_invalid_token(tmpdir, aio_connection):
    """[s3] SNOW-6154: Uses invalid combination of AWS credential."""
    # create a data file
    fname = str(tmpdir.join("test_put_get_with_aws_token.txt.gz"))
    with gzip.open(fname, "wb") as f:
        f.write("123,test1\n456,test2".encode(UTF8))
    table_name = random_string(5, "snow6154_")

    await aio_connection.connect()
    csr = aio_connection.cursor()

    try:
        await csr.execute(f"create or replace table {table_name} (a int, b string)")
        ret = await csr._execute_helper(f"put file://{fname} @%{table_name}")
        stage_info = ret["data"]["stageInfo"]
        stage_credentials = stage_info["creds"]
        creds = StorageCredential(stage_credentials, csr, "COMMAND WILL NOT BE USED")
        statinfo = os.stat(fname)
        meta = SnowflakeFileMeta(
            name=os.path.basename(fname),
            src_file_name=fname,
            src_file_size=statinfo.st_size,
            stage_location_type="S3",
            encryption_material=None,
            dst_file_name=os.path.basename(fname),
            sha256_digest="None",
        )

        client = SnowflakeS3RestClient(meta, creds, stage_info, 8388608)
        await client.get_file_header(meta.name)  # positive case

        # negative case, no aws token
        token = stage_info["creds"]["AWS_TOKEN"]
        del stage_info["creds"]["AWS_TOKEN"]
        with pytest.raises(ClientResponseError):
            await client.get_file_header(meta.name)

        # negative case, wrong location
        stage_info["creds"]["AWS_TOKEN"] = token
        s3path = client.s3location.path
        bad_path = os.path.dirname(os.path.dirname(s3path)) + "/"
        _s3location = S3Location(client.s3location.bucket_name, bad_path)
        client.s3location = _s3location
        client.chunks = [b"this is a chunk"]
        client.num_of_chunks = 1
        client.retry_count[0] = 0
        client.data_file = fname
        with pytest.raises(ClientResponseError):
            await client.upload_chunk(0)
    finally:
        await csr.execute(f"drop table if exists {table_name}")
