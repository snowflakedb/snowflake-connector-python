#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import logging
from os import path
from unittest import mock
from unittest.mock import AsyncMock, Mock

import pytest
from aiohttp import ClientResponse

from snowflake.connector.aio import SnowflakeConnection
from snowflake.connector.constants import SHA256_DIGEST

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from test.randomize import random_string

from snowflake.connector.aio._file_transfer_agent import (
    SnowflakeFileMeta,
    SnowflakeFileTransferAgent,
)
from snowflake.connector.errors import RequestExceedMaxRetryError
from snowflake.connector.file_transfer_agent import StorageCredential
from snowflake.connector.vendored.requests import HTTPError

try:  # pragma: no cover
    from snowflake.connector.aio._gcs_storage_client import SnowflakeGCSRestClient
except ImportError:
    SnowflakeGCSRestClient = None


from snowflake.connector.vendored import requests

vendored_request = True


THIS_DIR = path.dirname(path.realpath(__file__))


@pytest.mark.parametrize("errno", [408, 429, 500, 503])
async def test_upload_retry_errors(errno, tmpdir):
    """Tests whether retryable errors are handled correctly when upploading."""
    error = AsyncMock()
    error.status = errno
    f_name = str(tmpdir.join("some_file.txt"))
    meta = SnowflakeFileMeta(
        name=f_name,
        src_file_name=f_name,
        stage_location_type="GCS",
        presigned_url="some_url",
        sha256_digest="asd",
    )
    if RequestExceedMaxRetryError is not None:
        mock_connection = mock.create_autospec(SnowflakeConnection)
        client = SnowflakeGCSRestClient(
            meta,
            StorageCredential({}, mock_connection, ""),
            {},
            mock_connection,
            "",
        )
    with open(f_name, "w") as f:
        f.write(random_string(15))
    client.data_file = f_name

    with mock.patch(
        "aiohttp.ClientSession.request",
        new_callable=AsyncMock,
    ) as m:
        m.return_value = error
        with pytest.raises(RequestExceedMaxRetryError):
            # Retry quickly during unit tests
            client.SLEEP_UNIT = 0.0
            await client.upload_chunk(0)


async def test_upload_uncaught_exception(tmpdir):
    """Tests whether non-retryable errors are handled correctly when uploading."""
    f_name = str(tmpdir.join("some_file.txt"))
    exc = HTTPError("501 Server Error")
    with open(f_name, "w") as f:
        f.write(random_string(15))
    agent = SnowflakeFileTransferAgent(
        mock.MagicMock(),
        f"put {f_name} @~",
        {
            "data": {
                "command": "UPLOAD",
                "src_locations": [f_name],
                "stageInfo": {
                    "locationType": "GCS",
                    "location": "",
                    "creds": {"AWS_SECRET_KEY": "", "AWS_KEY_ID": ""},
                    "region": "test",
                    "endPoint": None,
                },
                "localLocation": "/tmp",
            }
        },
    )
    with mock.patch(
        "snowflake.connector.aio._gcs_storage_client.SnowflakeGCSRestClient.get_file_header",
    ), mock.patch(
        "snowflake.connector.aio._gcs_storage_client.SnowflakeGCSRestClient._upload_chunk",
        side_effect=exc,
    ):
        await agent.execute()
    assert agent._file_metadata[0].error_details is exc


@pytest.mark.parametrize("errno", [403, 408, 429, 500, 503])
async def test_download_retry_errors(errno, tmp_path):
    """Tests whether retryable errors are handled correctly when downloading."""
    error = AsyncMock()
    error.status = errno
    if errno == 403:
        pytest.skip("This behavior has changed in the move from SDKs")
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
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": ""}
    cnx = mock.MagicMock(autospec=SnowflakeConnection)
    rest_client = SnowflakeGCSRestClient(
        meta,
        StorageCredential(
            creds,
            cnx,
            "GET file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        cnx,
        "GET file:///tmp/file.txt @~",
    )

    rest_client.SLEEP_UNIT = 0
    with mock.patch(
        "aiohttp.ClientSession.request",
        new_callable=AsyncMock,
    ) as m:
        m.return_value = error
        with pytest.raises(
            RequestExceedMaxRetryError,
            match="GET with url .* failed for exceeding maximum retries",
        ):
            await rest_client.download_chunk(0)


@pytest.mark.parametrize("errno", (501, 403))
async def test_download_uncaught_exception(tmp_path, errno):
    """Tests whether non-retryable errors are handled correctly when downloading."""
    error = AsyncMock(spec=ClientResponse)
    error.status = errno
    error.raise_for_status.return_value = None
    error.raise_for_status.side_effect = HTTPError("Fake exceptiom")
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
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": ""}
    cnx = mock.MagicMock(autospec=SnowflakeConnection)
    rest_client = SnowflakeGCSRestClient(
        meta,
        StorageCredential(
            creds,
            cnx,
            "GET file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        cnx,
        "GET file:///tmp/file.txt @~",
    )

    rest_client.SLEEP_UNIT = 0
    with mock.patch(
        "aiohttp.ClientSession.request",
        new_callable=AsyncMock,
    ) as m:
        m.return_value = error
        with pytest.raises(
            requests.exceptions.HTTPError,
        ):
            await rest_client.download_chunk(0)


async def test_upload_put_timeout(tmp_path, caplog):
    """Tests whether timeout error is handled correctly when uploading."""
    caplog.set_level(logging.DEBUG, "snowflake.connector")
    f_name = str(tmp_path / "some_file.txt")
    with open(f_name, "w") as f:
        f.write(random_string(15))
    agent = SnowflakeFileTransferAgent(
        mock.Mock(autospec=SnowflakeConnection, connection=None),
        f"put {f_name} @~",
        {
            "data": {
                "command": "UPLOAD",
                "src_locations": [f_name],
                "stageInfo": {
                    "locationType": "GCS",
                    "location": "",
                    "creds": {"AWS_SECRET_KEY": "", "AWS_KEY_ID": ""},
                    "region": "test",
                    "endPoint": None,
                },
                "localLocation": "/tmp",
            }
        },
    )

    async def custom_side_effect(method, url, **kwargs):
        if method in ["PUT"]:
            raise asyncio.TimeoutError()
        return AsyncMock(spec=ClientResponse)

    SnowflakeGCSRestClient.SLEEP_UNIT = 0

    with mock.patch(
        "aiohttp.ClientSession.request",
        AsyncMock(side_effect=custom_side_effect),
    ):
        await agent.execute()
    assert (
        "snowflake.connector.aio._storage_client",
        logging.WARNING,
        "PUT with url https://storage.googleapis.com//some_file.txt.gz failed for transient error: ",
    ) in caplog.record_tuples
    assert (
        "snowflake.connector.aio._file_transfer_agent",
        logging.DEBUG,
        "Chunk 0 of file some_file.txt failed to transfer for unexpected exception PUT with url https://storage.googleapis.com//some_file.txt.gz failed for exceeding maximum retries.",
    ) in caplog.record_tuples


async def test_download_timeout(tmp_path, caplog):
    """Tests whether timeout error is handled correctly when downloading."""
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
    creds = {"AWS_SECRET_KEY": "", "AWS_KEY_ID": ""}
    cnx = mock.MagicMock(autospec=SnowflakeConnection)
    rest_client = SnowflakeGCSRestClient(
        meta,
        StorageCredential(
            creds,
            cnx,
            "GET file:/tmp/file.txt @~",
        ),
        {
            "locationType": "AWS",
            "location": "bucket/path",
            "creds": creds,
            "region": "test",
            "endPoint": None,
        },
        cnx,
        "GET file:///tmp/file.txt @~",
    )

    rest_client.SLEEP_UNIT = 0

    async def custom_side_effect(method, url, **kwargs):
        if method in ["GET"]:
            raise asyncio.TimeoutError()
        return AsyncMock(spec=ClientResponse)

    SnowflakeGCSRestClient.SLEEP_UNIT = 0

    with mock.patch(
        "aiohttp.ClientSession.request",
        AsyncMock(side_effect=custom_side_effect),
    ):
        exc = Exception("stop execution")
        with mock.patch.object(rest_client.credentials, "update", side_effect=exc):
            with pytest.raises(RequestExceedMaxRetryError):
                await rest_client.download_chunk(0)


async def test_get_file_header_none_with_presigned_url(tmp_path):
    """Tests whether default file handle created by get_file_header is as expected."""
    meta = SnowflakeFileMeta(
        name=str(tmp_path / "some_file"),
        src_file_name=str(tmp_path / "some_file"),
        stage_location_type="GCS",
        presigned_url="www.example.com",
    )
    storage_credentials = Mock()
    storage_credentials.creds = {}
    stage_info = Mock()
    connection = Mock()
    client = SnowflakeGCSRestClient(
        meta, storage_credentials, stage_info, connection, ""
    )
    if not client.security_token:
        await client._update_presigned_url()
    file_header = await client.get_file_header(meta.name)
    assert file_header is None
