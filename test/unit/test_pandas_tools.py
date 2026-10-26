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


@pytest.mark.pandas
@pytest.mark.unit
class TestWritePandasSqlQuoting:
    """SNOW-3833768 / SNOW-4063884: column names and iceberg options must not
    be interpolated as raw SQL."""

    def test_unquoted_identifier_rejects_sql_metacharacters(self):
        from snowflake.connector import ProgrammingError
        from snowflake.connector.pandas_tools import _sql_column_identifier

        with pytest.raises(ProgrammingError, match="Invalid unquoted identifier"):
            _sql_column_identifier("x INT) AS SELECT 1 --", quote_identifiers=False)
        with pytest.raises(ProgrammingError, match="Invalid unquoted identifier"):
            _sql_column_identifier('a"b', quote_identifiers=False)
        assert _sql_column_identifier("ok_col$1", quote_identifiers=False) == "ok_col$1"

    def test_quoted_identifier_escapes_internal_quotes(self):
        from snowflake.connector.pandas_tools import _sql_column_identifier

        assert _sql_column_identifier('a"b', quote_identifiers=True) == '"a""b"'
        assert (
            _sql_column_identifier("x INT) AS SELECT 1 --", quote_identifiers=True)
            == '"x INT) AS SELECT 1 --"'
        )

    def test_iceberg_option_always_one_literal(self):
        from snowflake.connector.pandas_tools import _convert_value_to_sql_option

        assert _convert_value_to_sql_option("vol") == "'vol'"
        assert _convert_value_to_sql_option("'my_volume'") == "'''my_volume'''"
        assert _convert_value_to_sql_option("it's") == "'it''s'"
        assert _convert_value_to_sql_option("vol\\") == "'vol\\\\'"
        assert _convert_value_to_sql_option("vol\\'") == "'vol\\\\'''"
        value = "'x' CATALOG='evil'"
        assert (
            _convert_value_to_sql_option(value) == "'" + value.replace("'", "''") + "'"
        )

    @patch(
        "snowflake.connector.pandas_tools._create_temp_stage", return_value="tmp_stage"
    )
    def test_copy_sql_quotes_parquet_path_with_internal_quotes(
        self, mock_stage, mock_connection, mock_cursor
    ):
        from snowflake.connector.pandas_tools import write_pandas

        df = pandas.DataFrame([(1,)], columns=['a"b'])
        write_pandas(mock_connection, df, "test_table", quote_identifiers=True)

        copy_sql = next(s for s in _get_executed_sqls(mock_cursor) if "COPY INTO" in s)
        assert '$1:"a""b"' in copy_sql
        assert '$1:"a"b"' not in copy_sql
        assert '("a""b")' in copy_sql

    @patch(
        "snowflake.connector.pandas_tools._create_temp_stage", return_value="tmp_stage"
    )
    def test_copy_sql_always_quotes_parquet_path_when_unquoted_aliases(
        self, mock_stage, mock_connection, mock_cursor
    ):
        from snowflake.connector.pandas_tools import write_pandas

        df = pandas.DataFrame([(1,)], columns=["ab"])
        write_pandas(mock_connection, df, "test_table", quote_identifiers=False)

        copy_sql = next(s for s in _get_executed_sqls(mock_cursor) if "COPY INTO" in s)
        assert '$1:"ab"' in copy_sql
        assert "(ab)" in copy_sql
        assert '("ab")' not in copy_sql

    @patch(
        "snowflake.connector.pandas_tools._create_temp_stage", return_value="tmp_stage"
    )
    def test_quote_identifiers_false_rejects_injection_column_before_execute(
        self, mock_stage, mock_connection, mock_cursor
    ):
        from snowflake.connector import ProgrammingError
        from snowflake.connector.pandas_tools import write_pandas

        df = pandas.DataFrame([(1,)], columns=["x INT) AS SELECT * FROM secrets --"])
        with pytest.raises(ProgrammingError, match="Invalid unquoted identifier"):
            write_pandas(
                mock_connection,
                df,
                "test_table",
                quote_identifiers=False,
                auto_create_table=True,
            )
        assert _get_executed_sqls(mock_cursor) == []
