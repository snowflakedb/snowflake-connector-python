#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import time
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
