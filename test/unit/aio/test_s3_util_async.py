#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import re
from os import path
from test.helpers import verify_log_tuple
from unittest import mock
from unittest.mock import MagicMock

import pytest

from snowflake.connector.aio import SnowflakeConnection
from snowflake.connector.aio._cursor import SnowflakeCursor
from snowflake.connector.aio._file_transfer_agent import SnowflakeFileTransferAgent
from snowflake.connector.constants import SHA256_DIGEST

try:
    from aiohttp import ClientResponse, ClientResponseError

    from snowflake.connector.aio._s3_storage_client import SnowflakeS3RestClient
    from snowflake.connector.constants import megabyte
    from snowflake.connector.errors import RequestExceedMaxRetryError
    from snowflake.connector.file_transfer_agent import (
        SnowflakeFileMeta,
        StorageCredential,
    )
    from snowflake.connector.s3_storage_client import ERRORNO_WSAECONNABORTED
    from snowflake.connector.vendored.requests import HTTPError
except ImportError:
    # Compatibility for olddriver tests
    from requests import HTTPError

    from snowflake.connector.s3_util import ERRORNO_WSAECONNABORTED  # NOQA

    SnowflakeFileMeta = dict
    SnowflakeS3RestClient = None
    RequestExceedMaxRetryError = None
    StorageCredential = None
    megabytes = 1024 * 1024
    DEFAULT_MAX_RETRY = 5

THIS_DIR = path.dirname(path.realpath(__file__))
MINIMAL_METADATA = SnowflakeFileMeta(
    name="file.txt",
    stage_location_type="S3",
    src_file_name="file.txt",
)


@pytest.mark.parametrize(
    "input, bucket_name, s3path",
    [
        ("sfc-eng-regression/test_sub_dir/", "sfc-eng-regression", "test_sub_dir/"),
        (
            "sfc-eng-regression/stakeda/test_stg/test_sub_dir/",
            "sfc-eng-regression",
            "stakeda/test_stg/test_sub_dir/",
        ),
        ("sfc-eng-regression/", "sfc-eng-regression", ""),
        ("sfc-eng-regression//", "sfc-eng-regression", "/"),
        ("sfc-eng-regression///", "sfc-eng-regression", "//"),
    ],
)
def test_extract_bucket_name_and_path(input, bucket_name, s3path):
    """Extracts bucket name and S3 path."""
    s3_loc = SnowflakeS3RestClient._extract_bucket_name_and_path(input)
    assert s3_loc.bucket_name == bucket_name
    assert s3_loc.path == s3path


async def test_upload_file_with_s3_upload_failed_error(tmp_path):
    """Tests Upload file with S3UploadFailedError, which could indicate AWS token expires."""
    file1 = tmp_path / "file1"
    with file1.open("w") as f:
        f.write("test1")
    rest_client = SnowflakeFileTransferAgent(
        MagicMock(autospec=SnowflakeCursor),
        "PUT some_file.txt",
        {
            "data": {
                "command": "UPLOAD",
                "autoCompress": False,
                "src_locations": [file1],
                "sourceCompression": "none",
                "stageInfo": {
                    "creds": {
                        "AWS_SECRET_KEY": "secret key",
                        "AWS_KEY_ID": "secret id",
                        "AWS_TOKEN": "",
                    },
                    "location": "some_bucket",
                    "region": "no_region",
                    "locationType": "S3",
                    "path": "remote_loc",
                    "endPoint": "",
                },
            },
            "success": True,
        },
    )
    exc = Exception("Stop executing")

    async def mock_transfer_accelerate_config(
        self: SnowflakeS3RestClient,
        use_accelerate_endpoint: bool | None = None,
    ) -> bool:
        self.endpoint = f"https://{self.s3location.bucket_name}.s3.awsamazon.com"
        return False

    with mock.patch(
        "snowflake.connector.aio._s3_storage_client.SnowflakeS3RestClient._has_expired_token",
        return_value=True,
    ):
        with mock.patch(
            "snowflake.connector.aio._s3_storage_client.SnowflakeS3RestClient.transfer_accelerate_config",
            mock_transfer_accelerate_config,
        ):
            with mock.patch(
                "snowflake.connector.file_transfer_agent.StorageCredential.update",
                side_effect=exc,
            ) as mock_update:
                await rest_client.execute()
                assert mock_update.called
                assert rest_client._results[0].error_details is exc


async def test_get_header_expiry_error():
    """Tests whether token expiry error is handled as expected when getting header."""
    meta_info = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "put_callback": None,
        "put_callback_output_stream": None,
        SHA256_DIGEST: "123456789abcdef",
        "dst_file_name": "data1.txt.gz",
        "src_file_name": path.join(THIS_DIR, "../data", "put_get_1.txt"),
        "overwrite": True,
    }
    meta = SnowflakeFileMeta(**meta_info)
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": "", "AWS_TOKEN": ""}
    rest_client = SnowflakeS3RestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "PUT file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        8 * megabyte,
    )
    await rest_client.transfer_accelerate_config(None)

    with mock.patch(
        "snowflake.connector.aio._s3_storage_client.SnowflakeS3RestClient._has_expired_token",
        return_value=True,
    ):
        exc = Exception("stop execution")
        with mock.patch.object(rest_client.credentials, "update", side_effect=exc):
            with pytest.raises(Exception) as caught_exc:
                await rest_client.get_file_header("file.txt")
            assert caught_exc.value is exc


async def test_get_header_unknown_error(caplog):
    """Tests whether unexpected errors are handled as expected when getting header."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    meta_info = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "put_callback": None,
        "put_callback_output_stream": None,
        SHA256_DIGEST: "123456789abcdef",
        "dst_file_name": "data1.txt.gz",
        "src_file_name": path.join(THIS_DIR, "../data", "put_get_1.txt"),
        "overwrite": True,
    }
    meta = SnowflakeFileMeta(**meta_info)
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": "", "AWS_TOKEN": ""}
    rest_client = SnowflakeS3RestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "PUT file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        8 * megabyte,
    )
    exc = HTTPError("555 Server Error")
    with mock.patch.object(rest_client, "get_file_header", side_effect=exc):
        with pytest.raises(HTTPError, match="555 Server Error"):
            await rest_client.get_file_header("file.txt")


async def test_upload_expiry_error():
    """Tests whether token expiry error is handled as expected when uploading."""
    meta_info = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "put_callback": None,
        "put_callback_output_stream": None,
        SHA256_DIGEST: "123456789abcdef",
        "dst_file_name": "data1.txt.gz",
        "src_file_name": path.join(THIS_DIR, "../../data", "put_get_1.txt"),
        "overwrite": True,
    }
    meta = SnowflakeFileMeta(**meta_info)
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": "", "AWS_TOKEN": ""}
    rest_client = SnowflakeS3RestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "PUT file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        8 * megabyte,
    )
    await rest_client.transfer_accelerate_config(None)

    with mock.patch(
        "snowflake.connector.aio._s3_storage_client.SnowflakeS3RestClient._has_expired_token",
        return_value=True,
    ):
        exc = Exception("stop execution")
        with mock.patch.object(rest_client.credentials, "update", side_effect=exc):
            with mock.patch(
                "snowflake.connector.aio._storage_client.SnowflakeStorageClient.preprocess"
            ):
                await rest_client.prepare_upload()
            with pytest.raises(Exception) as caught_exc:
                await rest_client.upload_chunk(0)
            assert caught_exc.value is exc


async def test_upload_unknown_error():
    """Tests whether unknown errors are handled as expected when uploading."""
    meta_info = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "put_callback": None,
        "put_callback_output_stream": None,
        SHA256_DIGEST: "123456789abcdef",
        "dst_file_name": "data1.txt.gz",
        "src_file_name": path.join(THIS_DIR, "../../data", "put_get_1.txt"),
        "overwrite": True,
    }
    meta = SnowflakeFileMeta(**meta_info)
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": "", "AWS_TOKEN": ""}
    rest_client = SnowflakeS3RestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "PUT file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        8 * megabyte,
    )

    exc = Exception("stop execution")
    with mock.patch.object(rest_client.credentials, "update", side_effect=exc):
        with mock.patch(
            "snowflake.connector.aio._storage_client.SnowflakeStorageClient.preprocess"
        ):
            await rest_client.prepare_upload()
        with pytest.raises(HTTPError, match="555 Server Error"):
            e = HTTPError("555 Server Error")
            with mock.patch.object(rest_client, "_upload_chunk", side_effect=e):
                await rest_client.upload_chunk(0)


async def test_download_expiry_error():
    """Tests whether token expiry error is handled as expected when downloading."""
    meta_info = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "put_callback": None,
        "put_callback_output_stream": None,
        SHA256_DIGEST: "123456789abcdef",
        "dst_file_name": "data1.txt.gz",
        "src_file_name": "path/to/put_get_1.txt",
        "overwrite": True,
    }
    meta = SnowflakeFileMeta(**meta_info)
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": "", "AWS_TOKEN": ""}
    rest_client = SnowflakeS3RestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "GET file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        8 * megabyte,
    )
    await rest_client.transfer_accelerate_config(None)

    with mock.patch(
        "snowflake.connector.aio._s3_storage_client.SnowflakeS3RestClient._has_expired_token",
        return_value=True,
    ):
        exc = Exception("stop execution")
        with mock.patch.object(rest_client.credentials, "update", side_effect=exc):
            with pytest.raises(Exception) as caught_exc:
                await rest_client.download_chunk(0)
            assert caught_exc.value is exc


async def test_download_unknown_error(caplog):
    """Tests whether an unknown error is handled as expected when downloading."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    agent = SnowflakeFileTransferAgent(
        MagicMock(),
        "get @~/f /tmp",
        {
            "data": {
                "command": "DOWNLOAD",
                "src_locations": ["/tmp/a"],
                "stageInfo": {
                    "locationType": "S3",
                    "location": "",
                    "creds": {"AWS_SECRET_KEY": "", "AWS_KEY_ID": "", "AWS_TOKEN": ""},
                    "region": "",
                    "endPoint": None,
                },
                "localLocation": "/tmp",
            }
        },
    )

    error = ClientResponseError(
        mock.AsyncMock(),
        mock.AsyncMock(spec=ClientResponse),
        status=400,
        message="No, just chuck testing...",
        headers={},
    )

    async def mock_transfer_accelerate_config(
        self: SnowflakeS3RestClient,
        use_accelerate_endpoint: bool | None = None,
    ) -> bool:
        self.endpoint = f"https://{self.s3location.bucket_name}.s3.awsamazon.com"
        return False

    with mock.patch(
        "snowflake.connector.aio._s3_storage_client.SnowflakeS3RestClient._send_request_with_authentication_and_retry",
        side_effect=error,
    ), mock.patch(
        "snowflake.connector.aio._file_transfer_agent.SnowflakeFileTransferAgent._transfer_accelerate_config",
        side_effect=None,
    ), mock.patch(
        "snowflake.connector.aio._s3_storage_client.SnowflakeS3RestClient.transfer_accelerate_config",
        mock_transfer_accelerate_config,
    ):
        await agent.execute()
    assert agent._file_metadata[0].error_details.status == 400
    assert agent._file_metadata[0].error_details.message == "No, just chuck testing..."
    assert verify_log_tuple(
        "snowflake.connector.aio._storage_client",
        logging.ERROR,
        re.compile("Failed to download a file: .*a"),
        caplog.record_tuples,
    )


async def test_download_retry_exceeded_error():
    """Tests whether a retry exceeded error is handled as expected when downloading."""
    meta_info = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "put_callback": None,
        "put_callback_output_stream": None,
        SHA256_DIGEST: "123456789abcdef",
        "dst_file_name": "data1.txt.gz",
        "src_file_name": "path/to/put_get_1.txt",
        "overwrite": True,
    }
    meta = SnowflakeFileMeta(**meta_info)
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": "", "AWS_TOKEN": ""}
    rest_client = SnowflakeS3RestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "GET file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        8 * megabyte,
    )
    await rest_client.transfer_accelerate_config()
    rest_client.SLEEP_UNIT = 0

    with mock.patch(
        "aiohttp.ClientSession.request",
        side_effect=ConnectionError("transit error"),
    ):
        with mock.patch.object(rest_client.credentials, "update"):
            with pytest.raises(
                RequestExceedMaxRetryError,
                match=r"GET with url .* failed for exceeding maximum retries",
            ):
                await rest_client.download_chunk(0)


async def test_accelerate_in_china_endpoint():
    meta_info = {
        "name": "data1.txt.gz",
        "stage_location_type": "S3",
        "no_sleeping_time": True,
        "put_callback": None,
        "put_callback_output_stream": None,
        SHA256_DIGEST: "123456789abcdef",
        "dst_file_name": "data1.txt.gz",
        "src_file_name": "path/to/put_get_1.txt",
        "overwrite": True,
    }
    meta = SnowflakeFileMeta(**meta_info)
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": "", "AWS_TOKEN": ""}
    rest_client = SnowflakeS3RestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "GET file:/tmp/file.txt @~",
        ),
        {
            "locationType": "S3China",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        8 * megabyte,
    )
    assert not await rest_client.transfer_accelerate_config()

    rest_client = SnowflakeS3RestClient(
        meta,
        StorageCredential(
            creds,
            MagicMock(autospec=SnowflakeConnection),
            "GET file:/tmp/file.txt @~",
        ),
        {
            "locationType": "S3",
            "location": "bucket/path",
            "creds": creds,
            "region": "cn-north-1",
            "endPoint": None,
        },
        8 * megabyte,
    )
    assert not await rest_client.transfer_accelerate_config()
