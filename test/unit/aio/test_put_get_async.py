#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os
from os import chmod, path
from unittest import mock

import pytest

from snowflake.connector import OperationalError
from snowflake.connector.aio._cursor import SnowflakeCursor
from snowflake.connector.aio._file_transfer_agent import SnowflakeFileTransferAgent
from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.errors import Error

pytestmark = pytest.mark.asyncio
CLOUD = os.getenv("cloud_provider", "dev")


@pytest.mark.skip
@pytest.mark.skipif(IS_WINDOWS, reason="permission model is different")
async def test_put_error(tmpdir):
    """Tests for raise_put_get_error flag (now turned on by default) in SnowflakeFileTransferAgent."""
    tmp_dir = str(tmpdir.mkdir("putfiledir"))
    file1 = path.join(tmp_dir, "file1")
    remote_location = path.join(tmp_dir, "remote_loc")
    with open(file1, "w") as f:
        f.write("test1")

    con = mock.AsyncMock()
    cursor = await con.cursor()
    cursor.errorhandler = Error.default_errorhandler
    query = "PUT something"
    ret = {
        "data": {
            "command": "UPLOAD",
            "autoCompress": False,
            "src_locations": [file1],
            "sourceCompression": "none",
            "stageInfo": {
                "creds": {},
                "location": remote_location,
                "locationType": "LOCAL_FS",
                "path": "remote_loc",
            },
        },
        "success": True,
    }

    agent_class = SnowflakeFileTransferAgent

    # no error is raised
    sf_file_transfer_agent = agent_class(cursor, query, ret, raise_put_get_error=False)
    await sf_file_transfer_agent.execute()
    sf_file_transfer_agent.result()

    # nobody can read now.
    chmod(file1, 0o000)
    # Permission error should be raised
    sf_file_transfer_agent = agent_class(cursor, query, ret, raise_put_get_error=True)
    await sf_file_transfer_agent.execute()
    with pytest.raises(OperationalError, match="PermissionError"):
        sf_file_transfer_agent.result()

    # unspecified, should fail because flag is on by default now
    sf_file_transfer_agent = agent_class(cursor, query, ret)
    await sf_file_transfer_agent.execute()
    with pytest.raises(OperationalError, match="PermissionError"):
        sf_file_transfer_agent.result()

    chmod(file1, 0o700)


async def test_get_empty_file(tmpdir):
    """Tests for error message when retrieving missing file."""
    tmp_dir = str(tmpdir.mkdir("getfiledir"))

    con = mock.AsyncMock()
    cursor = await con.cursor()
    cursor.errorhandler = Error.default_errorhandler
    query = f"GET something file:\\{tmp_dir}"
    ret = {
        "data": {
            "localLocation": tmp_dir,
            "command": "DOWNLOAD",
            "autoCompress": False,
            "src_locations": [],
            "sourceCompression": "none",
            "stageInfo": {
                "creds": {},
                "location": "",
                "locationType": "S3",
                "path": "remote_loc",
            },
        },
        "success": True,
    }

    sf_file_transfer_agent = SnowflakeFileTransferAgent(
        cursor, query, ret, raise_put_get_error=True
    )
    with pytest.raises(OperationalError, match=".*the file does not exist.*$"):
        await sf_file_transfer_agent.execute()
    assert not sf_file_transfer_agent.result()["rowset"]


@pytest.mark.skipolddriver
async def test_upload_file_with_azure_upload_failed_error(tmp_path):
    """Tests Upload file with expired Azure storage token."""
    file1 = tmp_path / "file1"
    with file1.open("w") as f:
        f.write("test1")
    rest_client = SnowflakeFileTransferAgent(
        mock.MagicMock(autospec=SnowflakeCursor),
        "PUT some_file.txt",
        {
            "data": {
                "command": "UPLOAD",
                "src_locations": [file1],
                "sourceCompression": "none",
                "stageInfo": {
                    "creds": {
                        "AZURE_SAS_TOKEN": "sas_token",
                    },
                    "location": "some_bucket",
                    "region": "no_region",
                    "locationType": "AZURE",
                    "path": "remote_loc",
                    "endPoint": "",
                    "storageAccount": "storage_account",
                },
            },
            "success": True,
        },
    )
    exc = Exception("Stop executing")
    with mock.patch(
        "snowflake.connector.aio._azure_storage_client.SnowflakeAzureRestClient._has_expired_token",
        return_value=True,
    ):
        with mock.patch(
            "snowflake.connector.file_transfer_agent.StorageCredential.update",
            side_effect=exc,
        ) as mock_update:
            await rest_client.execute()
            assert mock_update.called
            assert rest_client._results[0].error_details is exc
