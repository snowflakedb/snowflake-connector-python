from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from snowflake.connector.options import pandas

# Fake COPY INTO result row: (file, status, rows_parsed, rows_loaded, ...)
_COPY_RESULT = [("file0.txt", "LOADED", 1, 1, 0, 0, None, None, None, None)]
# Fake infer_schema result
_INFER_SCHEMA_RESULT = [("name", "VARCHAR"), ("points", "NUMBER")]


@pytest.fixture
def mock_connection():
    conn = MagicMock()
    conn._session_parameters = {}
    return conn


@pytest.fixture
def mock_cursor(mock_connection):
    cursor = AsyncMock()
    mock_connection.cursor.return_value = cursor

    async def _execute_side_effect(sql, *args, **kwargs):
        result = AsyncMock()
        if "infer_schema" in sql:
            result.fetchall.return_value = _INFER_SCHEMA_RESULT
        elif "COPY INTO" in sql:
            result.fetchall.return_value = _COPY_RESULT
        return result

    cursor.execute = AsyncMock(side_effect=_execute_side_effect)
    return cursor


def _get_executed_sqls(mock_cursor):
    """Extract the SQL strings from all cursor.execute calls."""
    return [c.args[0] for c in mock_cursor.execute.call_args_list]


class TestWritePandasAsyncOverwriteWithoutAutoCreate:
    """Tests for SNOW-1184290: async write_pandas() with auto_create_table=False and
    overwrite=True should NOT execute CREATE TABLE IF NOT EXISTS."""

    @pytest.mark.asyncio
    @patch(
        "snowflake.connector.aio._pandas_tools._create_temp_stage",
        new_callable=AsyncMock,
        return_value="tmp_stage",
    )
    @patch(
        "snowflake.connector.aio._pandas_tools._create_temp_file_format",
        new_callable=AsyncMock,
        return_value="tmp_fmt",
    )
    async def test_overwrite_without_auto_create_does_not_create_table(
        self, mock_file_format, mock_stage, mock_connection, mock_cursor
    ):
        from snowflake.connector.aio._pandas_tools import write_pandas

        df = pandas.DataFrame([("Mark", 10)], columns=["name", "points"])

        await write_pandas(
            mock_connection,
            df,
            "test_table",
            auto_create_table=False,
            overwrite=True,
        )

        executed_sqls = _get_executed_sqls(mock_cursor)
        assert not any(
            "CREATE" in sql and "TABLE IF NOT EXISTS" in sql for sql in executed_sqls
        ), "Should not CREATE TABLE when auto_create_table=False"
        assert any(
            "TRUNCATE" in sql for sql in executed_sqls
        ), "Expected TRUNCATE TABLE when overwrite=True and auto_create_table=False"

    @pytest.mark.asyncio
    @patch(
        "snowflake.connector.aio._pandas_tools._create_temp_stage",
        new_callable=AsyncMock,
        return_value="tmp_stage",
    )
    @patch(
        "snowflake.connector.aio._pandas_tools._create_temp_file_format",
        new_callable=AsyncMock,
        return_value="tmp_fmt",
    )
    async def test_overwrite_with_auto_create_does_create_table(
        self, mock_file_format, mock_stage, mock_connection, mock_cursor
    ):
        from snowflake.connector.aio._pandas_tools import write_pandas

        df = pandas.DataFrame([("Mark", 10)], columns=["name", "points"])

        await write_pandas(
            mock_connection,
            df,
            "test_table",
            auto_create_table=True,
            overwrite=True,
        )

        executed_sqls = _get_executed_sqls(mock_cursor)
        assert any(
            "CREATE" in sql and "TABLE IF NOT EXISTS" in sql for sql in executed_sqls
        ), "Expected CREATE TABLE when auto_create_table=True"
        assert not any(
            "TRUNCATE" in sql for sql in executed_sqls
        ), "Should not TRUNCATE when auto_create_table=True (uses drop+rename instead)"

    @pytest.mark.asyncio
    @patch(
        "snowflake.connector.aio._pandas_tools._create_temp_stage",
        new_callable=AsyncMock,
        return_value="tmp_stage",
    )
    async def test_no_overwrite_no_auto_create_no_create_table(
        self, mock_stage, mock_connection, mock_cursor
    ):
        from snowflake.connector.aio._pandas_tools import write_pandas

        df = pandas.DataFrame([("Mark", 10)], columns=["name", "points"])

        await write_pandas(
            mock_connection,
            df,
            "test_table",
            auto_create_table=False,
            overwrite=False,
        )

        executed_sqls = _get_executed_sqls(mock_cursor)
        assert not any(
            "CREATE" in sql and "TABLE IF NOT EXISTS" in sql for sql in executed_sqls
        ), "Should not CREATE TABLE when auto_create_table=False"
        assert not any(
            "TRUNCATE" in sql for sql in executed_sqls
        ), "Should not TRUNCATE when overwrite=False"
