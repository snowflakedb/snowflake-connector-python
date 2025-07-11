#!/usr/bin/env python
from __future__ import annotations

from os import chmod, path
from unittest import mock
from unittest.mock import patch

import pytest

from snowflake.connector import OperationalError
from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.cursor import SnowflakeCursor
from snowflake.connector.errors import Error
from snowflake.connector.file_transfer_agent import (
    SnowflakeAzureProgressPercentage,
    SnowflakeFileTransferAgent,
    SnowflakeS3ProgressPercentage,
)


@pytest.mark.skipif(IS_WINDOWS, reason="permission model is different")
def test_put_error(tmpdir):
    """Tests for raise_put_get_error flag (now turned on by default) in SnowflakeFileTransferAgent."""
    tmp_dir = str(tmpdir.mkdir("putfiledir"))
    file1 = path.join(tmp_dir, "file1")
    remote_location = path.join(tmp_dir, "remote_loc")
    with open(file1, "w") as f:
        f.write("test1")

    con = mock.MagicMock()
    cursor = con.cursor()
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
    sf_file_transfer_agent.execute()
    sf_file_transfer_agent.result()

    # nobody can read now.
    chmod(file1, 0o000)
    # Permission error should be raised
    sf_file_transfer_agent = agent_class(cursor, query, ret, raise_put_get_error=True)
    sf_file_transfer_agent.execute()
    with pytest.raises(OperationalError, match="PermissionError"):
        sf_file_transfer_agent.result()

    # unspecified, should fail because flag is on by default now
    sf_file_transfer_agent = agent_class(cursor, query, ret)
    sf_file_transfer_agent.execute()
    with pytest.raises(OperationalError, match="PermissionError"):
        sf_file_transfer_agent.result()

    chmod(file1, 0o700)


def test_get_empty_file(tmpdir):
    """Tests for error message when retrieving missing file."""
    tmp_dir = str(tmpdir.mkdir("getfiledir"))

    con = mock.MagicMock()
    cursor = con.cursor()
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
        sf_file_transfer_agent.execute()
    assert not sf_file_transfer_agent.result()["rowset"]


@pytest.mark.skipolddriver
def test_percentage(tmp_path):
    """Tests for ProgressPercentage classes."""
    from snowflake.connector.file_transfer_agent import percent

    assert 1.0 == percent(0, 0)
    assert 1.0 == percent(20, 0)
    assert 1.0 == percent(40, 20)
    assert 0.5 == percent(14, 28)

    file_path = tmp_path / "zero_file1"
    file_path.touch()
    func_callback = SnowflakeS3ProgressPercentage(str(file_path), 0)
    func_callback(1)
    func_callback = SnowflakeAzureProgressPercentage(str(file_path), 0)
    func_callback(1)


def test_upload_file_with_azure_upload_failed_error(tmp_path):
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
        "snowflake.connector.azure_storage_client.SnowflakeAzureRestClient._has_expired_token",
        return_value=True,
    ):
        with mock.patch(
            "snowflake.connector.file_transfer_agent.StorageCredential.update",
            side_effect=exc,
        ) as mock_update:
            rest_client.execute()
            assert mock_update.called
            assert rest_client._results[0].error_details is exc


def test_iobound_limit(tmp_path):
    file1 = tmp_path / "file1"
    file2 = tmp_path / "file2"
    file3 = tmp_path / "file3"
    file1.touch()
    file2.touch()
    file3.touch()
    # Positive case
    rest_client = SnowflakeFileTransferAgent(
        mock.MagicMock(autospec=SnowflakeCursor),
        "PUT some_file.txt",
        {
            "data": {
                "command": "UPLOAD",
                "src_locations": [file1, file2, file3],
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
    with mock.patch(
        "snowflake.connector.file_transfer_agent.ThreadPoolExecutor"
    ) as tpe:
        with mock.patch("snowflake.connector.file_transfer_agent.threading.Condition"):
            with mock.patch(
                "snowflake.connector.file_transfer_agent.TransferMetadata",
                return_value=mock.Mock(
                    num_files_started=0,
                    num_files_completed=3,
                ),
            ):
                try:
                    rest_client.execute()
                except AttributeError:
                    pass
    # 2 IObound TPEs should be created for 3 files unlimited
    rest_client = SnowflakeFileTransferAgent(
        mock.MagicMock(autospec=SnowflakeCursor),
        "PUT some_file.txt",
        {
            "data": {
                "command": "UPLOAD",
                "src_locations": [file1, file2, file3],
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
        iobound_tpe_limit=2,
    )
    assert len(list(filter(lambda e: e.args == (3,), tpe.call_args_list))) == 2
    with mock.patch(
        "snowflake.connector.file_transfer_agent.ThreadPoolExecutor"
    ) as tpe:
        with mock.patch("snowflake.connector.file_transfer_agent.threading.Condition"):
            with mock.patch(
                "snowflake.connector.file_transfer_agent.TransferMetadata",
                return_value=mock.Mock(
                    num_files_started=0,
                    num_files_completed=3,
                ),
            ):
                try:
                    rest_client.execute()
                except AttributeError:
                    pass
    # 2 IObound TPEs should be created for 3 files limited to 2
    assert len(list(filter(lambda e: e.args == (2,), tpe.call_args_list))) == 2


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


# The server DoP cap is newly introduced and therefore should not be tested in
# old drivers.
@pytest.mark.skipolddriver
def test_server_dop_cap(tmp_path):
    file1 = tmp_path / "file1"
    file2 = tmp_path / "file2"
    file1.touch()
    file2.touch()
    # Positive case
    rest_client = SnowflakeFileTransferAgent(
        mock.MagicMock(autospec=SnowflakeCursor),
        "PUT some_file.txt",
        {
            "data": {
                "command": "UPLOAD",
                "src_locations": [file1, file2],
                "sourceCompression": "none",
                "parallel": 8,
                "stageInfo": {
                    "creds": {},
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
        snowflake_server_dop_cap_for_file_transfer=1,
    )
    with mock.patch(
        "snowflake.connector.file_transfer_agent.ThreadPoolExecutor"
    ) as tpe:
        with mock.patch("snowflake.connector.file_transfer_agent.threading.Condition"):
            with mock.patch(
                "snowflake.connector.file_transfer_agent.TransferMetadata",
                return_value=mock.Mock(
                    num_files_started=0,
                    num_files_completed=3,
                ),
            ):
                try:
                    rest_client.execute()
                except AttributeError:
                    pass

    # We expect 3 thread pool executors to be created with thread count as 1,
    # because we will create executors for network, preprocess and postprocess,
    # and due to the server DoP cap, each of them will have a thread count
    # of 1.
    assert len(list(filter(lambda e: e.args == (1,), tpe.call_args_list))) == 3
