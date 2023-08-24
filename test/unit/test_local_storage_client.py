#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import os
import random
import shutil
import string
import tempfile

import pytest

try:
    from snowflake.connector.constants import LOCAL_FS
    from snowflake.connector.file_transfer_agent import SnowflakeFileMeta
    from snowflake.connector.local_storage_client import SnowflakeLocalStorageClient
except ImportError:
    LOCAL_FS = None
    SnowflakeFileMeta = None
    SnowflakeLocalStorageClient = None


@pytest.mark.parametrize("multipart_threshold", [0, 67108864])
def test_multi_chunk_upload(multipart_threshold):
    file_content = "".join(
        [random.choice(string.ascii_letters) for _ in range(300)]
    ).encode()
    file_name = "test_file"
    stage_dir = tempfile.mkdtemp()
    stage_file = os.path.join(stage_dir, file_name)
    local_dir = tempfile.mkdtemp()
    local_file = os.path.join(local_dir, file_name)

    try:
        with open(local_file, "wb+") as fd:
            fd.write(file_content)

        meta = SnowflakeFileMeta(
            name=file_name,
            src_file_name=local_file,
            stage_location_type=LOCAL_FS,
            dst_file_name=file_name,
            multipart_threshold=multipart_threshold,
        )
        client = SnowflakeLocalStorageClient(meta, {"location": stage_dir}, 10)
        client.prepare_upload()
        for chunk_id in range(client.num_of_chunks):
            client.upload_chunk(chunk_id)

        with open(stage_file, "rb") as fd:
            assert fd.read() == file_content
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)
        shutil.rmtree(local_dir, ignore_errors=True)


@pytest.mark.parametrize("multipart_threshold", [0, 67108864])
def test_multi_chunk_download(multipart_threshold):
    file_content = "".join(
        [random.choice(string.ascii_letters) for _ in range(300)]
    ).encode()
    file_name = "test_file"
    stage_dir = tempfile.mkdtemp()
    stage_file = os.path.join(stage_dir, file_name)
    local_dir = tempfile.mkdtemp()
    local_file = os.path.join(local_dir, file_name)

    try:
        with open(stage_file, "wb+") as fd:
            fd.write(file_content)

        meta = SnowflakeFileMeta(
            name=file_name,
            src_file_name=stage_file,
            stage_location_type=LOCAL_FS,
            dst_file_name=file_name,
            local_location=local_dir,
            multipart_threshold=multipart_threshold,
        )
        client = SnowflakeLocalStorageClient(meta, {"location": stage_dir}, 10)
        client.prepare_download()
        for chunk_id in range(client.num_of_chunks):
            client.download_chunk(chunk_id)
        client.finish_download()

        with open(local_file, "rb") as fd:
            assert fd.read() == file_content
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)
        shutil.rmtree(local_dir, ignore_errors=True)
