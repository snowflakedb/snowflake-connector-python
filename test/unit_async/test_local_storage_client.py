#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import random
import string
import tempfile
from pathlib import Path

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
    with tempfile.TemporaryDirectory() as stage_dir, tempfile.TemporaryDirectory() as local_dir:
        stage_file = Path(stage_dir) / file_name
        local_file = Path(local_dir) / file_name
        Path(local_file).write_bytes(file_content)

        meta = SnowflakeFileMeta(
            name=file_name,
            src_file_name=str(local_file),
            stage_location_type=LOCAL_FS,
            dst_file_name=file_name,
            multipart_threshold=multipart_threshold,
        )
        client = SnowflakeLocalStorageClient(meta, {"location": stage_dir}, 10)
        client.prepare_upload()
        for chunk_id in range(client.num_of_chunks):
            client.upload_chunk(chunk_id)

        assert Path(stage_file).read_bytes() == file_content


@pytest.mark.parametrize("multipart_threshold", [0, 67108864])
def test_multi_chunk_download(multipart_threshold):
    file_content = "".join(
        [random.choice(string.ascii_letters) for _ in range(300)]
    ).encode()
    file_name = "test_file"
    with tempfile.TemporaryDirectory() as stage_dir, tempfile.TemporaryDirectory() as local_dir:
        stage_file = Path(stage_dir) / file_name
        local_file = Path(local_dir) / file_name
        Path(stage_file).write_bytes(file_content)

        meta = SnowflakeFileMeta(
            name=file_name,
            src_file_name=str(stage_file),
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

        assert Path(local_file).read_bytes() == file_content
