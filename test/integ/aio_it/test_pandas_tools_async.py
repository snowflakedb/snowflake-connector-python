#!/usr/bin/env python
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Callable, Generator
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

import numpy.random
import pytest

from snowflake.connector import ProgrammingError
from snowflake.connector.aio import DictCursor, SnowflakeCursor

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from ...randomize import random_string

from ...lazy_var import LazyVar

try:
    from snowflake.connector.aio._pandas_tools import write_pandas
    from snowflake.connector.options import pandas
except ImportError:
    pandas = None
    write_pandas = None

if TYPE_CHECKING:
    from snowflake.connector.aio import SnowflakeConnection

sf_connector_version_data = [
    ("snowflake-connector-python", "1.2.23"),
    ("snowflake-sqlalchemy", "1.1.1"),
    ("snowflake-connector-go", "0.0.1"),
    ("snowflake-go", "1.0.1"),
    ("snowflake-odbc", "3.12.3"),
]

sf_connector_version_df = LazyVar(
    lambda: pandas.DataFrame(
        sf_connector_version_data, columns=["name", "newest_version"]
    )
)


async def assert_result_equals(
    cnx: SnowflakeConnection,
    num_of_chunks: int,
    sql: str,
    expected_data: list[tuple[Any, ...]],
):
    if num_of_chunks == 1:
        # Note: since we used one chunk order is conserved
        assert await (await cnx.cursor().execute(sql)).fetchall() == expected_data
    else:
        # Note: since we used more than one chunk order is NOT conserved
        assert set(await (await cnx.cursor().execute(sql)).fetchall()) == set(
            expected_data
        )


async def test_fix_snow_746341(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
):
    cat = '"cat"'
    df = pandas.DataFrame([[1], [2]], columns=[f"col_'{cat}'"])
    table_name = random_string(5, "snow746341_")
    async with conn_cnx() as conn:
        await write_pandas(
            conn, df, table_name, auto_create_table=True, table_type="temporary"
        )
        assert await (
            await conn.cursor().execute(f'select * from "{table_name}"')
        ).fetchall() == [
            (1,),
            (2,),
        ]


@pytest.mark.parametrize("quote_identifiers", [True, False])
@pytest.mark.parametrize("auto_create_table", [True, False])
@pytest.mark.parametrize("index", [False])
async def test_write_pandas_with_overwrite(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    quote_identifiers: bool,
    auto_create_table: bool,
    index: bool,
):
    """Tests whether overwriting table using a Pandas DataFrame works as expected."""
    random_table_name = random_string(5, "userspoints_")
    df1_data = [("John", 10), ("Jane", 20)]
    df1 = pandas.DataFrame(df1_data, columns=["name", "points"])
    df2_data = [("Dash", 50)]
    df2 = pandas.DataFrame(df2_data, columns=["name", "points"])
    df3_data = [(2022, "Jan", 10000), (2022, "Feb", 10220)]
    df3 = pandas.DataFrame(df3_data, columns=["year", "month", "revenue"])
    df4_data = [("Frank", 100)]
    df4 = pandas.DataFrame(df4_data, columns=["name%", "points"])

    if quote_identifiers:
        table_name = '"' + random_table_name + '"'
        col_id = '"id"'
        col_name = '"name"'
        col_points = '"points"'
    else:
        table_name = random_table_name
        col_id = "id"
        col_name = "name"
        col_points = "points"

    create_sql = (
        f"CREATE OR REPLACE TABLE {table_name}"
        f"({col_name} STRING, {col_points} INT, {col_id} INT AUTOINCREMENT)"
    )

    select_sql = f"SELECT * FROM {table_name}"
    select_count_sql = f"SELECT count(*) FROM {table_name}"
    drop_sql = f"DROP TABLE IF EXISTS {table_name}"
    async with conn_cnx() as cnx:  # type: SnowflakeConnection
        await cnx.execute_string(create_sql)
        try:
            # Write dataframe with 2 rows
            await write_pandas(
                cnx,
                df1,
                random_table_name,
                quote_identifiers=quote_identifiers,
                auto_create_table=auto_create_table,
                overwrite=True,
                index=index,
            )
            # Write dataframe with 1 row
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                df2,
                random_table_name,
                quote_identifiers=quote_identifiers,
                auto_create_table=auto_create_table,
                overwrite=True,
                index=index,
            )
            # Check write_pandas output
            assert success
            assert nchunks == 1
            result = await (
                await cnx.cursor(DictCursor).execute(select_count_sql)
            ).fetchone()
            # Check number of rows
            assert result["COUNT(*)"] == 1

            # Write dataframe with a different schema
            if auto_create_table:
                # Should drop table and SUCCEED because the new table will be created with new schema of df3
                success, nchunks, nrows, _ = await write_pandas(
                    cnx,
                    df3,
                    random_table_name,
                    quote_identifiers=quote_identifiers,
                    auto_create_table=auto_create_table,
                    overwrite=True,
                    index=index,
                )
                # Check write_pandas output
                assert success
                assert nchunks == 1
                result = await cnx.execute_string(select_sql)
                # Check column names
                assert (
                    "year"
                    if quote_identifiers
                    else "YEAR" in [col.name for col in result[0].description]
                )
            else:
                # Should fail because the table will be truncated and df3 schema doesn't match
                # (since df3 should at least have a subset of the columns of the target table)
                with pytest.raises(ProgrammingError, match="invalid identifier"):
                    await write_pandas(
                        cnx,
                        df3,
                        random_table_name,
                        quote_identifiers=quote_identifiers,
                        auto_create_table=auto_create_table,
                        overwrite=True,
                        index=index,
                    )

                # Check that we have truncated the table but not dropped it in case or error.
                result = await (
                    await cnx.cursor(DictCursor).execute(select_count_sql)
                ).fetchone()
                assert result["COUNT(*)"] == 0

            if not quote_identifiers:
                original_result = await (
                    await cnx.cursor(DictCursor).execute(select_count_sql)
                ).fetchone()
                # the column name contains special char which should fail
                with pytest.raises(ProgrammingError, match="unexpected '%'"):
                    await write_pandas(
                        cnx,
                        df4,
                        random_table_name,
                        quote_identifiers=quote_identifiers,
                        auto_create_table=auto_create_table,
                        overwrite=True,
                        index=index,
                    )
                # the original table shouldn't have any change
                assert (
                    original_result
                    == await (
                        await cnx.cursor(DictCursor).execute(select_count_sql)
                    ).fetchone()
                )

        finally:
            await cnx.execute_string(drop_sql)


@pytest.mark.parametrize("chunk_size", [5, 1])
@pytest.mark.parametrize(
    "compression",
    [
        "gzip",
    ],
)
@pytest.mark.parametrize("quote_identifiers", [True, False])
@pytest.mark.parametrize("auto_create_table", [True, False])
@pytest.mark.parametrize("table_type", ["temp", ""])
@pytest.mark.parametrize("index", [False])
async def test_write_pandas(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    db_parameters: dict[str, str],
    compression: str,
    chunk_size: int,
    quote_identifiers: bool,
    auto_create_table: bool,
    table_type: str,
    index: bool,
):
    num_of_chunks = math.ceil(len(sf_connector_version_data) / chunk_size)

    async with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
    ) as cnx:
        table_name = "driver_versions"

        if quote_identifiers:
            create_sql = 'CREATE OR REPLACE TABLE "{}" ("name" STRING, "newest_version" STRING)'.format(
                table_name
            )
            select_sql = f'SELECT * FROM "{table_name}"'
            drop_sql = f'DROP TABLE IF EXISTS "{table_name}"'
        else:
            create_sql = "CREATE OR REPLACE TABLE {} (name STRING, newest_version STRING)".format(
                table_name
            )
            select_sql = f"SELECT * FROM {table_name}"
            drop_sql = f"DROP TABLE IF EXISTS {table_name}"

        if not auto_create_table:
            await cnx.execute_string(create_sql)
        try:
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                sf_connector_version_df.get(),
                table_name,
                compression=compression,
                chunk_size=chunk_size,
                quote_identifiers=quote_identifiers,
                auto_create_table=auto_create_table,
                table_type=table_type,
                index=index,
            )

            await assert_result_equals(
                cnx, num_of_chunks, select_sql, sf_connector_version_data
            )

            # Make sure all files were loaded and no error occurred
            assert success
            # Make sure overall as many rows were ingested as we tried to insert
            assert nrows == len(sf_connector_version_data)
            # Make sure we uploaded in as many chunk as we wanted to
            assert nchunks == num_of_chunks
            # Check to see if this is a temporary or regular table if we auto-created this table
            if auto_create_table:
                table_info = await (
                    await cnx.cursor(DictCursor).execute(
                        f"show tables like '{table_name}'"
                    )
                ).fetchall()
                assert table_info[0]["kind"] == (
                    "TEMPORARY"
                    if table_type.lower() in ("temp", "temporary")
                    else "TABLE"
                )
        finally:
            await cnx.execute_string(drop_sql)


async def test_write_non_range_index_pandas(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    db_parameters: dict[str, str],
):
    compression = "gzip"
    chunk_size = 3
    quote_identifiers: bool = False
    auto_create_table: bool = True
    table_type: str = ""
    index: bool = False

    # use pandas dataframe with float index
    n_rows = 17
    pandas_df = pandas.DataFrame(
        pandas.DataFrame(
            numpy.random.normal(size=(n_rows, 4)),
            columns=["a", "b", "c", "d"],
            index=numpy.random.normal(size=n_rows),
        )
    )

    # convert to list of tuples to compare to received output
    pandas_df_data = [tuple(row) for row in list(pandas_df.values)]

    num_of_chunks = math.ceil(len(pandas_df_data) / chunk_size)

    async with conn_cnx() as cnx:
        table_name = "driver_versions"

        if quote_identifiers:
            create_sql = 'CREATE OR REPLACE TABLE "{}" ("name" STRING, "newest_version" STRING)'.format(
                table_name
            )
            select_sql = f'SELECT * FROM "{table_name}"'
            drop_sql = f'DROP TABLE IF EXISTS "{table_name}"'
        else:
            create_sql = "CREATE OR REPLACE TABLE {} (name STRING, newest_version STRING)".format(
                table_name
            )
            select_sql = f"SELECT * FROM {table_name}"
            drop_sql = f"DROP TABLE IF EXISTS {table_name}"

        if not auto_create_table:
            await cnx.execute_string(create_sql)
        try:
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                pandas_df,
                table_name,
                compression=compression,
                chunk_size=chunk_size,
                quote_identifiers=quote_identifiers,
                auto_create_table=auto_create_table,
                table_type=table_type,
                index=index,
            )

            await assert_result_equals(cnx, num_of_chunks, select_sql, pandas_df_data)

            # Make sure all files were loaded and no error occurred
            assert success
            # Make sure overall as many rows were ingested as we tried to insert
            assert nrows == len(pandas_df_data)
            # Make sure we uploaded in as many chunk as we wanted to
            assert nchunks == num_of_chunks
            # Check to see if this is a temporary or regular table if we auto-created this table
            if auto_create_table:
                table_info = await (
                    await cnx.cursor(DictCursor).execute(
                        f"show tables like '{table_name}'"
                    )
                ).fetchall()
                assert table_info[0]["kind"] == (
                    "TEMPORARY"
                    if table_type.lower() in ("temp", "temporary")
                    else "TABLE"
                )
        finally:
            await cnx.execute_string(drop_sql)


@pytest.mark.parametrize("table_type", ["", "temp", "temporary", "transient"])
async def test_write_pandas_table_type(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    table_type: str,
):
    async with conn_cnx() as cnx:
        table_name = random_string(5, "write_pandas_table_type_")
        drop_sql = f"DROP TABLE IF EXISTS {table_name}"
        try:
            success, _, _, _ = await write_pandas(
                cnx,
                sf_connector_version_df.get(),
                table_name,
                table_type=table_type,
                auto_create_table=True,
            )
            table_info = await (
                await cnx.cursor(DictCursor).execute(f"show tables like '{table_name}'")
            ).fetchall()
            assert success
            if not table_type:
                expected_table_kind = "TABLE"
            elif table_type == "temp":
                expected_table_kind = "TEMPORARY"
            else:
                expected_table_kind = table_type.upper()
            assert table_info[0]["kind"] == expected_table_kind
        finally:
            await cnx.execute_string(drop_sql)


@pytest.mark.parametrize("use_logical_type", [None, True, False])
async def test_write_pandas_use_logical_type(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    use_logical_type: bool | None,
):
    table_name = random_string(5, "USE_LOCAL_TYPE_").upper()
    col_name = "DT"
    create_sql = f"CREATE OR REPLACE TABLE {table_name} ({col_name} TIMESTAMP_TZ)"
    select_sql = f"SELECT * FROM {table_name}"
    drop_sql = f"DROP TABLE IF EXISTS {table_name}"
    timestamp = datetime(
        year=2020,
        month=1,
        day=2,
        hour=3,
        minute=4,
        second=5,
        microsecond=6,
        tzinfo=timezone(timedelta(hours=2)),
    )
    df_write = pandas.DataFrame({col_name: [timestamp]})

    async with conn_cnx() as cnx:  # type: SnowflakeConnection
        await (await cnx.cursor().execute(create_sql)).fetchall()

        write_pandas_kwargs = dict(
            conn=cnx,
            df=df_write,
            use_logical_type=use_logical_type,
            auto_create_table=False,
            table_name=table_name,
        )

        try:
            # When use_logical_type = True, datetimes with timestamps should be
            # correctly written to Snowflake.
            if use_logical_type:
                await write_pandas(**write_pandas_kwargs)
                df_read = await (
                    await cnx.cursor().execute(select_sql)
                ).fetch_pandas_all()
                assert all(df_write == df_read)
            # For other use_logical_type values, a UserWarning should be displayed.
            else:
                with pytest.warns(UserWarning, match="Dataframe contains a datetime.*"):
                    await write_pandas(**write_pandas_kwargs)
        finally:
            await cnx.execute_string(drop_sql)


async def test_invalid_table_type_write_pandas(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
):
    async with conn_cnx() as cnx:
        with pytest.raises(ValueError, match="Unsupported table type"):
            await write_pandas(
                cnx,
                sf_connector_version_df.get(),
                "invalid_table_type",
                table_type="invalid",
            )


async def test_empty_dataframe_write_pandas(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
):
    table_name = random_string(5, "empty_dataframe_")
    df = pandas.DataFrame([], columns=["name", "balance"])
    async with conn_cnx() as cnx:
        success, num_chunks, num_rows, _ = await write_pandas(
            cnx, df, table_name, auto_create_table=True, table_type="temp"
        )
        assert (
            success and num_chunks == 1 and num_rows == 0
        ), f"sucess: {success}, num_chunks: {num_chunks}, num_rows: {num_rows}"


@pytest.mark.parametrize(
    "database,schema,quote_identifiers,expected_location",
    [
        ("database", "schema", True, '"database"."schema"."table"'),
        ("database", "schema", False, "database.schema.table"),
        (None, "schema", True, '"schema"."table"'),
        (None, "schema", False, "schema.table"),
        (None, None, True, '"table"'),
        (None, None, False, "table"),
    ],
)
async def test_table_location_building(
    conn_cnx,
    database: str | None,
    schema: str | None,
    quote_identifiers: bool,
    expected_location: str,
):
    """This tests that write_pandas constructs table location correctly with database, schema, and table name."""

    async with conn_cnx() as cnx:

        async def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith("COPY INTO"):
                assert kwargs["params"][0] == expected_location
            cur = SnowflakeCursor(cnx)
            # Create a mock result iterator with fetch_all_data method
            mock_result = MagicMock()
            mock_result.fetch_all_data = AsyncMock(return_value=[])
            cur._result = mock_result
            return cur

        with mock.patch(
            "snowflake.connector.aio._cursor.SnowflakeCursor.execute",
            side_effect=mocked_execute,
        ) as m_execute, mock.patch(
            "snowflake.connector.aio._cursor.SnowflakeCursor._upload",
            side_effect=MagicMock(),
        ) as _:
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                sf_connector_version_df.get(),
                "table",
                database=database,
                schema=schema,
                quote_identifiers=quote_identifiers,
            )
            assert m_execute.called and any(
                map(lambda e: "COPY INTO" in str(e[0]), m_execute.call_args_list)
            )


@pytest.mark.parametrize(
    "database,schema,quote_identifiers,expected_db_schema",
    [
        ("database", "schema", True, '"database"."schema"'),
        ("database", "schema", False, "database.schema"),
        (None, "schema", True, '"schema"'),
        (None, "schema", False, "schema"),
        (None, None, True, ""),
        (None, None, False, ""),
        ("data'base", "schema", True, '"data\'base"."schema"'),
        ("data'base", "schema", False, '"data\'base".schema'),
    ],
)
async def test_stage_location_building(
    conn_cnx,
    database: str | None,
    schema: str | None,
    quote_identifiers: bool,
    expected_db_schema: str,
):
    """This tests that write_pandas constructs stage location correctly with database and schema."""

    async with conn_cnx() as cnx:

        async def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith("create temporary stage"):
                db_schema = ".".join(args[0].split(" ")[-1].split(".")[:-1])
                assert db_schema == expected_db_schema
            cur = SnowflakeCursor(cnx)
            # Create a mock result iterator with fetch_all_data method
            mock_result = MagicMock()
            mock_result.fetch_all_data = AsyncMock(return_value=[])
            cur._result = mock_result
            return cur

        with mock.patch(
            "snowflake.connector.aio._cursor.SnowflakeCursor.execute",
            side_effect=mocked_execute,
        ) as m_execute, mock.patch(
            "snowflake.connector.aio._cursor.SnowflakeCursor._upload",
            side_effect=MagicMock(),
        ) as _:
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                sf_connector_version_df.get(),
                "table",
                database=database,
                schema=schema,
                quote_identifiers=quote_identifiers,
            )
            assert m_execute.called and any(
                map(
                    lambda e: ("CREATE TEMP STAGE" in str(e[0])),
                    m_execute.call_args_list,
                )
            )


@pytest.mark.skip("scoped object isn't used yet.")
@pytest.mark.parametrize(
    "database,schema,quote_identifiers,expected_db_schema",
    [
        ("database", "schema", True, '"database"."schema"'),
        ("database", "schema", False, "database.schema"),
        (None, "schema", True, '"schema"'),
        (None, "schema", False, "schema"),
        (None, None, True, ""),
        (None, None, False, ""),
    ],
)
async def test_use_scoped_object(
    conn_cnx,
    database: str | None,
    schema: str | None,
    quote_identifiers: bool,
    expected_db_schema: str,
):
    """This tests that write_pandas constructs stage location correctly with database and schema."""

    async with conn_cnx() as cnx:

        async def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith("create temporary stage"):
                db_schema = ".".join(args[0].split(" ")[-1].split(".")[:-1])
                assert db_schema == expected_db_schema
            cur = SnowflakeCursor(cnx)
            # Create a mock result iterator with fetch_all_data method
            mock_result = MagicMock()
            mock_result.fetch_all_data = AsyncMock(return_value=[])
            cur._result = mock_result
            return cur

        with mock.patch(
            "snowflake.connector.aio._cursor.SnowflakeCursor.execute",
            side_effect=mocked_execute,
        ) as m_execute, mock.patch(
            "snowflake.connector.aio._cursor.SnowflakeCursor._upload",
            side_effect=MagicMock(),
        ) as _:
            await cnx._update_parameters(
                {"PYTHON_SNOWPARK_USE_SCOPED_TEMP_OBJECTS": True}
            )
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                sf_connector_version_df.get(),
                "table",
                database=database,
                schema=schema,
                quote_identifiers=quote_identifiers,
            )
            assert m_execute.called and any(
                map(
                    lambda e: ("CREATE SCOPED TEMPORARY STAGE" in str(e[0])),
                    m_execute.call_args_list,
                )
            )


@pytest.mark.parametrize(
    "database,schema,quote_identifiers,expected_db_schema",
    [
        ("database", "schema", True, '"database"."schema"'),
        ("database", "schema", False, "database.schema"),
        (None, "schema", True, '"schema"'),
        (None, "schema", False, "schema"),
        (None, None, True, ""),
        (None, None, False, ""),
    ],
)
async def test_file_format_location_building(
    conn_cnx,
    database: str | None,
    schema: str | None,
    quote_identifiers: bool,
    expected_db_schema: str,
):
    """This tests that write_pandas constructs file format location correctly with database and schema."""

    async with conn_cnx() as cnx:

        async def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith("CREATE FILE FORMAT"):
                db_schema = ".".join(args[0].split(" ")[3].split(".")[:-1])
                assert db_schema == expected_db_schema
            cur = SnowflakeCursor(cnx)
            mock_result = MagicMock()
            if args[0].startswith("SELECT"):
                cur._rownumber = 0
                # Create a mock result iterator with fetch_all_data method
                mock_result.fetch_all_data = AsyncMock(
                    return_value=[
                        (col, "") for col in sf_connector_version_df.get().columns
                    ]
                )
            else:
                mock_result.fetch_all_data = AsyncMock(return_value=[])
            cur._result = mock_result
            return cur

        with mock.patch(
            "snowflake.connector.aio._cursor.SnowflakeCursor.execute",
            side_effect=mocked_execute,
        ) as m_execute, mock.patch(
            "snowflake.connector.aio._cursor.SnowflakeCursor._upload",
            side_effect=MagicMock(),
        ) as _:
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                sf_connector_version_df.get(),
                "table",
                database=database,
                schema=schema,
                quote_identifiers=quote_identifiers,
                auto_create_table=True,
            )
            assert m_execute.called and any(
                map(
                    lambda e: ("CREATE TEMP FILE FORMAT" in str(e[0])),
                    m_execute.call_args_list,
                )
            )


@pytest.mark.parametrize("quote_identifiers", [True, False])
async def test_default_value_insertion(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    quote_identifiers: bool,
):
    """Tests whether default values can be successfully inserted with the pandas writeback."""
    table_name = "users"
    df_data = [("Mark", 10), ("Luke", 20)]

    # Create a DataFrame containing data about customers
    df = pandas.DataFrame(df_data, columns=["name", "balance"])
    # Assume quote_identifiers is true in string and if not remove " from strings
    create_sql = """CREATE OR REPLACE TABLE "{}"
                 ("name" STRING, "balance" INT,
                 "id" varchar(36) default uuid_string(),
                 "ts" timestamp_ltz default current_timestamp)""".format(
        table_name
    )
    select_sql = f'SELECT * FROM "{table_name}"'
    drop_sql = f'DROP TABLE IF EXISTS "{table_name}"'
    if not quote_identifiers:
        create_sql = create_sql.replace('"', "")
        select_sql = select_sql.replace('"', "")
        drop_sql = drop_sql.replace('"', "")
    async with conn_cnx() as cnx:  # type: SnowflakeConnection
        await cnx.execute_string(create_sql)
        try:
            success, nchunks, nrows, _ = await write_pandas(
                cnx, df, table_name, quote_identifiers=quote_identifiers
            )

            # Check write_pandas output
            assert success
            assert nrows == len(df_data)
            assert nchunks == 1
            # Check table's contents
            result = await (await cnx.cursor(DictCursor).execute(select_sql)).fetchall()
            for row in result:
                assert (
                    row["id" if quote_identifiers else "ID"] is not None
                )  # ID (UUID String)
                assert len(row["id" if quote_identifiers else "ID"]) == 36
                assert (
                    row["ts" if quote_identifiers else "TS"] is not None
                )  # TS (Current Timestamp)
                assert isinstance(row["ts" if quote_identifiers else "TS"], datetime)
                assert (
                    row["name" if quote_identifiers else "NAME"],
                    row["balance" if quote_identifiers else "BALANCE"],
                ) in df_data
        finally:
            await cnx.execute_string(drop_sql)


@pytest.mark.parametrize("quote_identifiers", [True, False])
async def test_autoincrement_insertion(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    quote_identifiers: bool,
):
    """Tests whether default values can be successfully inserted with the pandas writeback."""
    table_name = "users"
    df_data = [("Mark", 10), ("Luke", 20)]

    # Create a DataFrame containing data about customers
    df = pandas.DataFrame(df_data, columns=["name", "balance"])
    # Assume quote_identifiers is true in string and if not remove " from strings
    create_sql = (
        'CREATE OR REPLACE TABLE "{}"'
        '("name" STRING, "balance" INT, "id" INT AUTOINCREMENT)'
    ).format(table_name)
    select_sql = f'SELECT * FROM "{table_name}"'
    drop_sql = f'DROP TABLE IF EXISTS "{table_name}"'
    if not quote_identifiers:
        create_sql = create_sql.replace('"', "")
        select_sql = select_sql.replace('"', "")
        drop_sql = drop_sql.replace('"', "")
    async with conn_cnx() as cnx:  # type: SnowflakeConnection
        await cnx.execute_string(create_sql)
        try:
            success, nchunks, nrows, _ = await write_pandas(
                cnx, df, table_name, quote_identifiers=quote_identifiers
            )

            # Check write_pandas output
            assert success
            assert nrows == len(df_data)
            assert nchunks == 1
            # Check table's contents
            result = await (await cnx.cursor(DictCursor).execute(select_sql)).fetchall()
            for row in result:
                assert row["id" if quote_identifiers else "ID"] in (1, 2)
                assert (
                    row["name" if quote_identifiers else "NAME"],
                    row["balance" if quote_identifiers else "BALANCE"],
                ) in df_data
        finally:
            await cnx.execute_string(drop_sql)


@pytest.mark.parametrize("auto_create_table", [True, False])
@pytest.mark.parametrize(
    "column_names",
    [
        ["00 name", "bAl_ance"],
        ['c""ol', '"col"'],
        ["c''ol", "'col'"],
        ["チリヌル", "熊猫"],
    ],
)
async def test_special_name_quoting(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    auto_create_table: bool,
    column_names: list[str],
):
    """Tests whether special column names get quoted as expected."""
    table_name = "users"
    df_data = [("Mark", 10), ("Luke", 20)]

    df = pandas.DataFrame(df_data, columns=column_names)
    snowflake_column_names = [c.replace('"', '""') for c in column_names]
    create_sql = (
        f'CREATE OR REPLACE TABLE "{table_name}"'
        f'("{snowflake_column_names[0]}" STRING, "{snowflake_column_names[1]}" INT, "id" INT AUTOINCREMENT)'
    )
    select_sql = f'SELECT * FROM "{table_name}"'
    drop_sql = f'DROP TABLE IF EXISTS "{table_name}"'
    async with conn_cnx() as cnx:  # type: SnowflakeConnection
        if not auto_create_table:
            await cnx.execute_string(create_sql)
        try:
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                df,
                table_name,
                quote_identifiers=True,
                auto_create_table=auto_create_table,
            )

            # Check write_pandas output
            assert success
            assert nrows == len(df_data)
            assert nchunks == 1
            # Check table's contents
            result = await (await cnx.cursor(DictCursor).execute(select_sql)).fetchall()
            for row in result:
                # The auto create table functionality does not auto-create an incrementing ID
                if not auto_create_table:
                    assert row["id"] in (1, 2)
                assert (
                    row[column_names[0]],
                    row[column_names[1]],
                ) in df_data
        finally:
            await cnx.execute_string(drop_sql)


async def test_auto_create_table_similar_column_names(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
):
    """Tests whether similar names do not cause issues when auto-creating a table as expected."""
    table_name = random_string(5, "numbas_")
    df_data = [(10, 11), (20, 21)]

    df = pandas.DataFrame(df_data, columns=["number", "Number"])
    select_sql = f'SELECT * FROM "{table_name}"'
    drop_sql = f'DROP TABLE IF EXISTS "{table_name}"'
    async with conn_cnx() as cnx:
        try:
            success, nchunks, nrows, _ = await write_pandas(
                cnx, df, table_name, quote_identifiers=True, auto_create_table=True
            )

            # Check write_pandas output
            assert success
            assert nrows == len(df_data)
            assert nchunks == 1
            # Check table's contents
            result = await (await cnx.cursor(DictCursor).execute(select_sql)).fetchall()
            for row in result:
                assert (
                    row["number"],
                    row["Number"],
                ) in df_data
        finally:
            await cnx.execute_string(drop_sql)


async def test_all_pandas_types(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
):
    table_name = random_string(5, "all_types_")
    datetime_with_tz = datetime(1997, 6, 3, 14, 21, 32, 00, tzinfo=timezone.utc)
    datetime_with_ntz = datetime(1997, 6, 3, 14, 21, 32, 00)
    df_data = [
        [
            1,
            1.1,
            "1string1",
            True,
            datetime_with_tz,
            datetime_with_ntz,
            datetime_with_tz.date(),
            datetime_with_tz.time(),
            bytes("a", "utf-8"),
        ],
        [
            2,
            2.2,
            "2string2",
            False,
            datetime_with_tz,
            datetime_with_ntz,
            datetime_with_tz.date(),
            datetime_with_tz.time(),
            bytes("b", "utf-16"),
        ],
    ]
    columns = [
        "int",
        "float",
        "string",
        "bool",
        "timestamp_tz",
        "timestamp_ntz",
        "date",
        "time",
        "binary",
    ]

    df = pandas.DataFrame(
        df_data,
        columns=columns,
    )

    select_sql = f'SELECT * FROM "{table_name}"'
    drop_sql = f'DROP TABLE IF EXISTS "{table_name}"'
    async with conn_cnx() as cnx:
        try:
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                df,
                table_name,
                quote_identifiers=True,
                auto_create_table=True,
                use_logical_type=True,
            )

            # Check write_pandas output
            assert success
            assert nrows == len(df_data)
            assert nchunks == 1
            # Check table's contents
            cur = await cnx.cursor(DictCursor).execute(select_sql)
            result = await cur.fetchall()
            for row, data in zip(result, df_data):
                for c in columns:
                    # TODO: check values of timestamp data after SNOW-667350 is fixed
                    if "timestamp" in c:
                        assert row[c] is not None
                    else:
                        assert row[c] in data
        finally:
            await cnx.execute_string(drop_sql)


@pytest.mark.parametrize("object_type", ["STAGE", "FILE FORMAT"])
async def test_no_create_internal_object_privilege_in_target_schema(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    caplog,
    object_type,
):
    source_schema = random_string(5, "source_schema_")
    target_schema = random_string(5, "target_schema_no_create_")
    table = random_string(5, "table_")
    select_sql = f"select * from {target_schema}.{table}"

    async with conn_cnx() as cnx:
        try:
            await cnx.execute_string(f"create or replace schema {source_schema}")
            await cnx.execute_string(f"create or replace schema {target_schema}")
            original_execute = SnowflakeCursor.execute

            async def mock_execute(*args, **kwargs):
                if (
                    f"CREATE TEMP {object_type}" in args[0]
                    and "target_schema_no_create_" in kwargs["params"][0]
                ):
                    raise ProgrammingError("Cannot create temp object in target schema")
                cursor = cnx.cursor()
                await original_execute(cursor, *args, **kwargs)
                return cursor

            with mock.patch(
                "snowflake.connector.aio._cursor.SnowflakeCursor.execute",
                side_effect=mock_execute,
            ):
                with caplog.at_level("DEBUG"):
                    success, num_of_chunks, _, _ = await write_pandas(
                        cnx,
                        sf_connector_version_df.get(),
                        table,
                        database=cnx.database,
                        schema=target_schema,
                        auto_create_table=True,
                        quote_identifiers=False,
                    )

            assert "Fall back to use current schema" in caplog.text
            assert success
            await assert_result_equals(
                cnx, num_of_chunks, select_sql, sf_connector_version_data
            )
        finally:
            await cnx.execute_string(f"drop schema if exists {source_schema}")
            await cnx.execute_string(f"drop schema if exists {target_schema}")


async def test_write_pandas_with_on_error(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
):
    """Tests whether overwriting table using a Pandas DataFrame works as expected."""
    random_table_name = random_string(5, "userspoints_")
    df_data = [("Dash", 50)]
    df = pandas.DataFrame(df_data, columns=["name", "points"])

    table_name = random_table_name
    col_id = "id"
    col_name = "name"
    col_points = "points"

    create_sql = (
        f"CREATE OR REPLACE TABLE {table_name}"
        f"({col_name} STRING, {col_points} INT, {col_id} INT AUTOINCREMENT)"
    )

    select_count_sql = f"SELECT count(*) FROM {table_name}"
    drop_sql = f"DROP TABLE IF EXISTS {table_name}"
    async with conn_cnx() as cnx:  # type: SnowflakeConnection
        await cnx.execute_string(create_sql)
        try:
            # Write dataframe with 1 row
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                df,
                random_table_name,
                quote_identifiers=False,
                auto_create_table=False,
                overwrite=True,
                index=True,
                on_error="continue",
            )
            # Check write_pandas output
            assert success
            assert nchunks == 1
            assert nrows == 1
            result = await (
                await cnx.cursor(DictCursor).execute(select_count_sql)
            ).fetchone()
            # Check number of rows
            assert result["COUNT(*)"] == 1
        finally:
            await cnx.execute_string(drop_sql)


async def test_pandas_with_single_quote(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
):
    random_table_name = random_string(5, "test'table")
    table_name = f'"{random_table_name}"'
    create_sql = f"CREATE OR REPLACE TABLE {table_name}(A INT)"
    df_data = [[1]]
    df = pandas.DataFrame(df_data, columns=["a"])
    async with conn_cnx() as cnx:  # type: SnowflakeConnection
        try:
            await cnx.execute_string(create_sql)
            await write_pandas(
                cnx,
                df,
                table_name,
                quote_identifiers=False,
                auto_create_table=False,
                index=False,
            )
        finally:
            await cnx.execute_string(f"drop table if exists {table_name}")


@pytest.mark.parametrize("bulk_upload_chunks", [True, False])
async def test_write_pandas_bulk_chunks_upload(conn_cnx, bulk_upload_chunks):
    """Tests whether overwriting table using a Pandas DataFrame works as expected."""
    random_table_name = random_string(5, "userspoints_")
    df_data = [("Dash", 50), ("Luke", 20), ("Mark", 10), ("John", 30)]
    df = pandas.DataFrame(df_data, columns=["name", "points"])

    table_name = random_table_name
    col_id = "id"
    col_name = "name"
    col_points = "points"

    create_sql = (
        f"CREATE OR REPLACE TABLE {table_name}"
        f"({col_name} STRING, {col_points} INT, {col_id} INT AUTOINCREMENT)"
    )

    select_count_sql = f"SELECT count(*) FROM {table_name}"
    drop_sql = f"DROP TABLE IF EXISTS {table_name}"
    async with conn_cnx() as cnx:  # type: SnowflakeConnection
        await cnx.execute_string(create_sql)
        try:
            # Write dataframe with 1 row
            success, nchunks, nrows, _ = await write_pandas(
                cnx,
                df,
                random_table_name,
                quote_identifiers=False,
                auto_create_table=False,
                overwrite=True,
                index=True,
                on_error="continue",
                chunk_size=1,
                bulk_upload_chunks=bulk_upload_chunks,
            )
            # Check write_pandas output
            assert success
            assert nchunks == 4
            assert nrows == 4
            result = await (
                await cnx.cursor(DictCursor).execute(select_count_sql)
            ).fetchone()
            # Check number of rows
            assert result["COUNT(*)"] == 4
        finally:
            await cnx.execute_string(drop_sql)


@pytest.mark.parametrize(
    "use_vectorized_scanner",
    [
        True,
        False,
    ],
)
async def test_write_pandas_with_use_vectorized_scanner(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    use_vectorized_scanner,
    caplog,
):
    """Tests whether overwriting table using a Pandas DataFrame works as expected."""
    random_table_name = random_string(5, "userspoints_")
    df_data = [("Dash", 50)]
    df = pandas.DataFrame(df_data, columns=["name", "points"])

    table_name = random_table_name
    col_id = "id"
    col_name = "name"
    col_points = "points"

    create_sql = (
        f"CREATE OR REPLACE TABLE {table_name}"
        f"({col_name} STRING, {col_points} INT, {col_id} INT AUTOINCREMENT)"
    )

    drop_sql = f"DROP TABLE IF EXISTS {table_name}"
    async with conn_cnx() as cnx:  # type: SnowflakeConnection
        original_cur = cnx.cursor().execute

        async def fake_execute(query, params=None, *args, **kwargs):
            return await original_cur(query, params, *args, **kwargs)

        await cnx.execute_string(create_sql)
        try:
            with mock.patch(
                "snowflake.connector.aio._cursor.SnowflakeCursor.execute",
                side_effect=fake_execute,
            ) as execute:
                # Write dataframe with 1 row
                success, nchunks, nrows, _ = await write_pandas(
                    cnx,
                    df,
                    random_table_name,
                    quote_identifiers=False,
                    auto_create_table=False,
                    overwrite=True,
                    index=True,
                    use_vectorized_scanner=use_vectorized_scanner,
                )
                # Check write_pandas output
                assert success
                assert nchunks == 1
                assert nrows == 1

                for call in execute.call_args_list:
                    if call.args[0].startswith("COPY"):
                        assert (
                            f"USE_VECTORIZED_SCANNER={use_vectorized_scanner}"
                            in call.args[0]
                        )

        finally:
            await cnx.execute_string(drop_sql)
