#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations

import pytest

from snowflake.connector.cursor import SnowflakeCursor

try:
    from snowflake.connector.constants import FileTransferType
except ImportError:
    from enum import Enum

    class FileTransferType(Enum):
        GET = "get"
        PUT = "put"


@pytest.mark.parametrize(
    "sql,_type",
    (
        ("PUT file:///tmp/data/mydata.csv @my_int_stage;", FileTransferType.PUT),
        ("GET @%mytable file:///tmp/data/;", FileTransferType.GET),
        ("select 1;", None),
    ),
)
def test_get_filetransfer_type(sql, _type):
    assert SnowflakeCursor.get_file_transfer_type(sql) == _type
