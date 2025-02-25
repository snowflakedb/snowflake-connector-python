#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from typing import Union
from unittest.mock import MagicMock

import pandas as pd
import pytest

from snowflake.connector import pandas_tools

from .mock_utils import mock_connection


@pytest.mark.parametrize(
    ("use_vectorized_scanner", "expected_file_format"),
    [
        (None, "FILE_FORMAT=(TYPE=PARQUET COMPRESSION=auto)"),
        (
            True,
            "FILE_FORMAT=(TYPE=PARQUET COMPRESSION=auto USE_VECTORIZED_SCANNER=TRUE)",
        ),
        (
            False,
            "FILE_FORMAT=(TYPE=PARQUET COMPRESSION=auto USE_VECTORIZED_SCANNER=FALSE)",
        ),
    ],
)
def test_write_pandas_use_vectorized_scanner(
    use_vectorized_scanner: Union[bool, None], expected_file_format: str
):
    # Setup Mocks
    df = pd.DataFrame({"col1": [1, 2, 3]})

    mock_conn = mock_connection()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    # Execute Function
    pandas_tools.write_pandas(
        conn=mock_conn,
        df=df,
        table_name="test_table",
        schema="test_schema",
        database="test_database",
        use_vectorized_scanner=use_vectorized_scanner,
    )

    executed_sql_statements = [
        call[0][0] for call in mock_cursor.execute.call_args_list
    ]

    assert any(
        "COPY INTO" in sql and expected_file_format in sql
        for sql in executed_sql_statements
    )
