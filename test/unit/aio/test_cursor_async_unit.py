#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import unittest.mock
from unittest.mock import MagicMock, patch

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
