from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

pandas = pytest.importorskip("pandas")

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
    cursor = MagicMock()
    mock_connection.cursor.return_value = cursor

    def _execute_side_effect(sql, *args, **kwargs):
        result = MagicMock()
        if "infer_schema" in sql:
            result.fetchall.return_value = _INFER_SCHEMA_RESULT
        elif "COPY INTO" in sql:
            result.fetchall.return_value = _COPY_RESULT
        return result

    cursor.execute.side_effect = _execute_side_effect
    return cursor


def _get_executed_sqls(mock_cursor):
    """Extract the SQL strings from all cursor.execute calls."""
    return [c.args[0] for c in mock_cursor.execute.call_args_list]


@pytest.mark.pandas
@pytest.mark.unit
class TestWritePandasOverwriteWithoutAutoCreate:
    """Tests for SNOW-1184290: write_pandas() with auto_create_table=False and
    overwrite=True should NOT execute CREATE TABLE IF NOT EXISTS."""

    @patch(
        "snowflake.connector.pandas_tools._create_temp_stage", return_value="tmp_stage"
    )
    @patch(
        "snowflake.connector.pandas_tools._create_temp_file_format",
        return_value="tmp_fmt",
    )
    def test_overwrite_without_auto_create_does_not_create_table(
        self, mock_file_format, mock_stage, mock_connection, mock_cursor
    ):
        from snowflake.connector.pandas_tools import write_pandas

        df = pandas.DataFrame([("Mark", 10)], columns=["name", "points"])

        write_pandas(
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

    @patch(
        "snowflake.connector.pandas_tools._create_temp_stage", return_value="tmp_stage"
    )
    @patch(
        "snowflake.connector.pandas_tools._create_temp_file_format",
        return_value="tmp_fmt",
    )
    def test_overwrite_with_auto_create_does_create_table(
        self, mock_file_format, mock_stage, mock_connection, mock_cursor
    ):
        from snowflake.connector.pandas_tools import write_pandas

        df = pandas.DataFrame([("Mark", 10)], columns=["name", "points"])

        write_pandas(
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

    @patch(
        "snowflake.connector.pandas_tools._create_temp_stage", return_value="tmp_stage"
    )
    def test_no_overwrite_no_auto_create_no_create_table(
        self, mock_stage, mock_connection, mock_cursor
    ):
        from snowflake.connector.pandas_tools import write_pandas

        df = pandas.DataFrame([("Mark", 10)], columns=["name", "points"])

        write_pandas(
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


@pytest.mark.pandas
@pytest.mark.unit
class TestTempObjectNameUniqueness:
    """Tests for SNOW-3481510: random_name_for_temp_object must use
    cryptographically secure randomness to prevent collisions in forked
    processes and high-frequency usage."""

    def test_random_names_are_unique_across_many_calls(self):
        """Generate a large batch of names and verify no collisions."""
        from snowflake.connector._utils import (
            TempObjectType,
            random_name_for_temp_object,
        )

        names = [
            random_name_for_temp_object(TempObjectType.STAGE) for _ in range(10_000)
        ]
        assert len(set(names)) == len(names), "Detected duplicate temp object names"

    def test_random_names_unique_for_all_object_types(self):
        """Verify uniqueness holds across different temp object types."""
        from snowflake.connector._utils import (
            TempObjectType,
            random_name_for_temp_object,
        )

        names = []
        for obj_type in [
            TempObjectType.STAGE,
            TempObjectType.FILE_FORMAT,
            TempObjectType.TABLE,
        ]:
            names.extend(random_name_for_temp_object(obj_type) for _ in range(1_000))
        assert len(set(names)) == len(names)

    def test_random_name_format_preserved(self):
        """Ensure the name format is still SNOWPARK_TEMP_<TYPE>_<ALPHANUMERIC>."""
        import re

        from snowflake.connector._utils import (
            TempObjectType,
            random_name_for_temp_object,
        )

        name = random_name_for_temp_object(TempObjectType.STAGE)
        assert re.match(r"^SNOWPARK_TEMP_STAGE_[A-Z0-9]{10}$", name)
