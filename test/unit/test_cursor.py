from __future__ import annotations

import time
from unittest import TestCase
from unittest.mock import MagicMock, patch

import pytest

from snowflake.connector.connection import SnowflakeConnection
from snowflake.connector.cursor import SnowflakeCursor
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


def test_query_can_be_empty_with_dataframe_ast():
    def mock_is_closed(*args, **kwargs):
        return False

    fake_conn = FakeConnection()
    fake_conn.is_closed = mock_is_closed
    cursor = SnowflakeCursor(fake_conn)
    # when `dataframe_ast` is not presented, the execute function return None
    assert cursor.execute("") is None
    # when `dataframe_ast` is presented, it should not return `None`
    # but raise `AttributeError` since `_paramstyle` is not set in FakeConnection.
    with pytest.raises(AttributeError):
        cursor.execute("", _dataframe_ast="ABCD")


@patch("snowflake.connector.cursor.SnowflakeCursor._SnowflakeCursor__cancel_query")
def test_cursor_execute_timeout(mockCancelQuery):
    def mock_cmd_query(*args, **kwargs):
        time.sleep(10)
        raise ServiceUnavailableError()

    fake_conn = FakeConnection()
    fake_conn.cmd_query = mock_cmd_query
    fake_conn._rest = MagicMock()
    fake_conn._paramstyle = MagicMock()
    fake_conn._next_sequence_counter = MagicMock()

    cursor = SnowflakeCursor(fake_conn)

    with pytest.raises(ServiceUnavailableError):
        cursor.execute(
            command="SELECT * FROM nonexistent",
            timeout=1,
        )

    # query cancel request should be sent upon timeout
    assert mockCancelQuery.called


# The _upload/_download/_upload_stream/_download_stream are newly introduced
# and therefore should not be tested in old drivers.
@pytest.mark.skipolddriver
class TestUploadDownloadMethods(TestCase):
    """Test the _upload/_download/_upload_stream/_download_stream methods."""

    @patch("snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent")
    def test_download(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _download method
        cursor._download("@st", "/tmp/test.txt", {})

        # In the process of _download execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - execute in SnowflakeFileTransferAgent
        # And we do not expect this method to be involved
        #   - download_as_stream of connection._stream_downloader
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_not_called()
        mock_file_transfer_agent_instance.execute.assert_called_once()

    @patch("snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent")
    def test_upload(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _upload method
        cursor._upload("/tmp/test.txt", "@st", {})

        # In the process of _upload execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - execute in SnowflakeFileTransferAgent
        # And we do not expect this method to be involved
        #   - download_as_stream of connection._stream_downloader
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_not_called()
        mock_file_transfer_agent_instance.execute.assert_called_once()

    @patch("snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent")
    def test_download_stream(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _download_stream method
        cursor._download_stream("@st/test.txt", decompress=True)

        # In the process of _download_stream execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - download_as_stream of connection._stream_downloader
        # And we do not expect this method to be involved
        #   - execute in SnowflakeFileTransferAgent
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_called_once()
        mock_file_transfer_agent_instance.execute.assert_not_called()

    @patch("snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent")
    def test_upload_stream(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _upload_stream method
        fd = MagicMock()
        cursor._upload_stream(fd, "@st/test.txt", {})

        # In the process of _upload_stream execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - execute in SnowflakeFileTransferAgent
        # And we do not expect this method to be involved
        #   - download_as_stream of connection._stream_downloader
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_not_called()
        mock_file_transfer_agent_instance.execute.assert_called_once()

    def _setup_mocks(self, MockFileTransferAgent):
        mock_file_transfer_agent_instance = MockFileTransferAgent.return_value
        mock_file_transfer_agent_instance.execute.return_value = None

        fake_conn = FakeConnection()
        fake_conn._file_operation_parser = MagicMock()
        fake_conn._stream_downloader = MagicMock()

        cursor = SnowflakeCursor(fake_conn)
        cursor.reset = MagicMock()
        cursor._init_result_and_meta = MagicMock()
        return cursor, fake_conn, mock_file_transfer_agent_instance
