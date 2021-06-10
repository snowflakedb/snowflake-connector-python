#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
import pytest

from snowflake.connector.constants import FileTransferType
from snowflake.connector.cursor import SnowflakeCursor


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
