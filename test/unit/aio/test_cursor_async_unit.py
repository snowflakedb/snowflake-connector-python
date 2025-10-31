#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import unittest.mock
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from snowflake.connector.aio import SnowflakeConnection, SnowflakeCursor
from snowflake.connector.errors import ServiceUnavailableError

try:
    from snowflake.connector.constants import FileTransferType
except ImportError:
    from enum import Enum

    class FileTransferType(Enum):
        GET = "get"
        PUT = "put"


class FakeConnection(SnowflakeConnection):
    def __init__(self):
        self._log_max_query_length = 0
        self._reuse_results = None
        self._reraise_error_in_file_transfer_work_function = False
        self._enable_stage_s3_privatelink_for_us_east_1 = False
        self._unsafe_file_write = False


@pytest.mark.parametrize(
    "sql,_type",
    (
        ("", None),
        ("select 1;", None),
        ("PUT file:///tmp/data/mydata.csv @my_int_stage;", FileTransferType.PUT),
        ("GET @%mytable file:///tmp/data/;", FileTransferType.GET),
        ("/**/PUT file:///tmp/data/mydata.csv @my_int_stage;", FileTransferType.PUT),
        ("/**/ GET @%mytable file:///tmp/data/;", FileTransferType.GET),
        pytest.param(
            "/**/\n"
            + "\t/*/get\t*/\t/**/\n" * 10000
            + "\t*/get @~/test.csv file:///tmp\n",
            None,
            id="long_incorrect",
        ),
        pytest.param(
            "/**/\n" + "\t/*/put\t*/\t/**/\n" * 10000 + "put file:///tmp/data.csv @~",
            FileTransferType.PUT,
            id="long_correct",
        ),
    ),
)
def test_get_filetransfer_type(sql, _type):
    assert SnowflakeCursor.get_file_transfer_type(sql) == _type


def test_cursor_attribute():
    fake_conn = FakeConnection()
    cursor = SnowflakeCursor(fake_conn)
    assert cursor.lastrowid is None


async def test_query_can_be_empty_with_dataframe_ast():
    def mock_is_closed(*args, **kwargs):
        return False

    fake_conn = FakeConnection()
    fake_conn.is_closed = mock_is_closed
    cursor = SnowflakeCursor(fake_conn)
    # when `dataframe_ast` is not presented, the execute function return None
    assert await cursor.execute("") is None
    # when `dataframe_ast` is presented, it should not return `None`
    # but raise `AttributeError` since `_paramstyle` is not set in FakeConnection.
    with pytest.raises(AttributeError):
        await cursor.execute("", _dataframe_ast="ABCD")


@patch("snowflake.connector.aio._cursor.SnowflakeCursor._SnowflakeCursor__cancel_query")
async def test_cursor_execute_timeout(mockCancelQuery):
    async def mock_cmd_query(*args, **kwargs):
        await asyncio.sleep(10)
        raise ServiceUnavailableError()

    fake_conn = FakeConnection()
    fake_conn.cmd_query = mock_cmd_query
    fake_conn._rest = unittest.mock.AsyncMock()
    fake_conn._paramstyle = MagicMock()
    fake_conn._next_sequence_counter = unittest.mock.AsyncMock()

    cursor = SnowflakeCursor(fake_conn)

    with pytest.raises(ServiceUnavailableError):
        await cursor.execute(
            command="SELECT * FROM nonexistent",
            timeout=1,
        )

    # query cancel request should be sent upon timeout
    assert mockCancelQuery.called


# The _upload/_download/_upload_stream/_download_stream are newly introduced
# and therefore should not be tested in old drivers.
@pytest.mark.skipolddriver
class TestUploadDownloadMethods(IsolatedAsyncioTestCase):
    """Test the _upload/_download/_upload_stream/_download_stream methods."""

    @patch("snowflake.connector.aio._file_transfer_agent.SnowflakeFileTransferAgent")
    async def test_download(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _download method
        await cursor._download("@st", "/tmp/test.txt", {})

        # In the process of _download execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - execute in SnowflakeFileTransferAgent
        # And we do not expect this method to be involved
        #   - download_as_stream of connection._stream_downloader
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_not_called()
        MockFileTransferAgent.assert_called_once()
        assert MockFileTransferAgent.call_args.kwargs.get("use_s3_regional_url", False)
        mock_file_transfer_agent_instance.execute.assert_called_once()

    @patch("snowflake.connector.aio._file_transfer_agent.SnowflakeFileTransferAgent")
    async def test_upload(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _upload method
        await cursor._upload("/tmp/test.txt", "@st", {})

        # In the process of _upload execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - execute in SnowflakeFileTransferAgent
        # And we do not expect this method to be involved
        #   - download_as_stream of connection._stream_downloader
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_not_called()
        MockFileTransferAgent.assert_called_once()
        assert MockFileTransferAgent.call_args.kwargs.get("use_s3_regional_url", False)
        mock_file_transfer_agent_instance.execute.assert_called_once()

    @patch("snowflake.connector.aio._file_transfer_agent.SnowflakeFileTransferAgent")
    async def test_download_stream(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _download_stream method
        await cursor._download_stream("@st/test.txt", decompress=True)

        # In the process of _download_stream execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - download_as_stream of connection._stream_downloader
        # And we do not expect this method to be involved
        #   - execute in SnowflakeFileTransferAgent
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_called_once()
        MockFileTransferAgent.assert_not_called()
        mock_file_transfer_agent_instance.execute.assert_not_called()

    @patch("snowflake.connector.aio._file_transfer_agent.SnowflakeFileTransferAgent")
    async def test_upload_stream(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _upload_stream method
        fd = MagicMock()
        await cursor._upload_stream(fd, "@st/test.txt", {})

        # In the process of _upload_stream execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - execute in SnowflakeFileTransferAgent
        # And we do not expect this method to be involved
        #   - download_as_stream of connection._stream_downloader
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_not_called()
        MockFileTransferAgent.assert_called_once()
        assert MockFileTransferAgent.call_args.kwargs.get("use_s3_regional_url", False)
        mock_file_transfer_agent_instance.execute.assert_called_once()

    def _setup_mocks(self, MockFileTransferAgent):
        mock_file_transfer_agent_instance = MockFileTransferAgent.return_value
        mock_file_transfer_agent_instance.execute = AsyncMock(return_value=None)

        fake_conn = FakeConnection()
        fake_conn._file_operation_parser = MagicMock()
        fake_conn._file_operation_parser.parse_file_operation = AsyncMock()
        fake_conn._stream_downloader = MagicMock()
        fake_conn._stream_downloader.download_as_stream = AsyncMock()
        # this should be true on all new AWS deployments to use regional endpoints for staging operations
        fake_conn._enable_stage_s3_privatelink_for_us_east_1 = True
        fake_conn._unsafe_file_write = False

        cursor = SnowflakeCursor(fake_conn)
        cursor.reset = MagicMock()
        cursor._init_result_and_meta = AsyncMock()
        return cursor, fake_conn, mock_file_transfer_agent_instance
