#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import os
from os import chmod, path
from unittest import mock
from unittest.mock import patch

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


def test_strip_stage_prefix_from_dst_file_name_for_download():
    """Verifies that _strip_stage_prefix_from_dst_file_name_for_download is called when initializing file meta.

    Workloads like sproc will need to monkeypatch _strip_stage_prefix_from_dst_file_name_for_download on the server side
    to maintain its behavior. So we add this unit test to make sure that we do not accidentally refactor this method and
    break sproc workloads.
    """
    file = "test.txt"
    agent = SnowflakeFileTransferAgent(
        mock.MagicMock(autospec=SnowflakeCursor),
        "GET @stage_foo/test.txt file:///tmp",
        {
            "data": {
                "localLocation": "/tmp",
                "command": "DOWNLOAD",
                "autoCompress": False,
                "src_locations": [file],
                "sourceCompression": "none",
                "stageInfo": {
                    "creds": {},
                    "location": "",
                    "locationType": "S3",
                    "path": "remote_loc",
                },
            },
            "success": True,
        },
    )
    agent._parse_command()
    with patch.object(
        agent,
        "_strip_stage_prefix_from_dst_file_name_for_download",
        return_value="mock value",
    ):
        agent._init_file_metadata()
        agent._strip_stage_prefix_from_dst_file_name_for_download.assert_called_with(
            file
        )


def _setup_test_for_reraise_file_transfer_work_fn_error(tmp_path, reraise_param_value):
    """Helper to set up common test infrastructure for async error propagation tests.

    Returns:
        tuple: (agent, test_exception, mock_client, mock_create_client)
    """

    file1 = tmp_path / "file1"
    file1.write_text("test content")

    # Mock cursor
    mock_cursor = mock.MagicMock(autospec=SnowflakeCursor)
    mock_cursor.connection._reraise_error_in_file_transfer_work_function = (
        reraise_param_value
    )

    # Create file transfer agent
    agent = SnowflakeFileTransferAgent(
        mock_cursor,
        "PUT some_file.txt",
        {
            "data": {
                "command": "UPLOAD",
                "src_locations": [str(file1)],
                "sourceCompression": "none",
                "parallel": 1,
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
        reraise_error_in_file_transfer_work_function=reraise_param_value,
    )

    # Ensure flag is set on the agent
    assert (
        agent._reraise_error_in_file_transfer_work_function == reraise_param_value
    ), f"expected {reraise_param_value}, got {agent._reraise_error_in_file_transfer_work_function}"

    # Parse command and initialize file metadata
    agent._parse_command()
    agent._init_file_metadata()
    agent._process_file_compression_type()

    # Create a custom exception to be raised by the async work function
    test_exception = Exception("Test work function failure")

    async def mock_upload_chunk_with_delay(*args, **kwargs):
        await asyncio.sleep(0.05)
        raise test_exception

    # Set up mock client patch, which we will activate in each unit test case.
    mock_client = mock.AsyncMock()
    mock_client.upload_chunk.side_effect = mock_upload_chunk_with_delay

    # Set up mock client attributes needed for the transfer flow
    mock_client.meta = agent._file_metadata[0]
    mock_client.num_of_chunks = 1
    mock_client.successful_transfers = 0
    mock_client.failed_transfers = 0
    mock_client.lock = mock.MagicMock()
    # Mock methods that would be called during cleanup
    mock_client.finish_upload = mock.AsyncMock()
    mock_client.delete_client_data = mock.MagicMock()

    # Patch async client factory to return our async mock client
    mock_create_client = mock.patch.object(
        agent,
        "_create_file_transfer_client",
        new=mock.AsyncMock(return_value=mock_client),
    )

    return agent, test_exception, mock_client, mock_create_client


# Skip for old drivers because the connection config of
# reraise_error_in_file_transfer_work_function is newly introduced.
@pytest.mark.skipolddriver
async def test_python_reraise_file_transfer_work_fn_error_as_is(tmp_path):
    """When reraise_error_in_file_transfer_work_function is True, exceptions are reraised immediately."""
    agent, test_exception, mock_client, mock_create_client_patch = (
        _setup_test_for_reraise_file_transfer_work_fn_error(tmp_path, True)
    )

    with mock_create_client_patch as mock_create_client:
        mock_create_client.return_value = mock_client

        # Test that with the connection config
        # reraise_error_in_file_transfer_work_function is True, the
        # exception is reraised immediately in main thread of transfer.
        with pytest.raises(Exception) as exc_info:
            await agent.transfer(agent._file_metadata)

        # Verify it's the same exception we injected
        assert exc_info.value is test_exception

        # Verify that prepare_upload was called (showing the work function was executed)
        mock_client.prepare_upload.assert_awaited_once()


@pytest.mark.skipolddriver
async def test_python_not_reraise_file_transfer_work_fn_error_as_is(tmp_path):
    """When reraise_error_in_file_transfer_work_function is False, errors are stored and execution continues."""
    agent, test_exception, mock_client, mock_create_client_patch = (
        _setup_test_for_reraise_file_transfer_work_fn_error(tmp_path, False)
    )

    with mock_create_client_patch as mock_create_client:
        mock_create_client.return_value = mock_client

        # Verify that with the connection config
        # reraise_error_in_file_transfer_work_function is False, the
        # exception is not reraised (but instead stored in file metadata).
        await agent.transfer(agent._file_metadata)

        # Verify that the error was stored in the file metadata
        assert agent._file_metadata[0].error_details is test_exception

        # Verify that prepare_upload was called
        mock_client.prepare_upload.assert_awaited_once()
