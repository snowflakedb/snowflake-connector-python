#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Callable, Generator
from unittest import mock

import pytest

from snowflake.connector import DictCursor

from ...lazy_var import LazyVar
from ...randomize import random_string

try:
    from snowflake.connector.options import pandas
    from snowflake.connector.pandas_tools import write_pandas
except ImportError:
    pandas = None
    write_pandas = None


if TYPE_CHECKING:
    from snowflake.connector import SnowflakeConnection

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


@pytest.mark.parametrize("quote_identifiers", [True, False])
@pytest.mark.parametrize("auto_create_table", [True, False])
def test_write_pandas_with_overwrite(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
    quote_identifiers: bool,
    auto_create_table: bool,
):
    """Tests whether overwriting table using a Pandas DataFrame works as expected."""
    random_table_name = random_string(5, "userspoints_")
    df1_data = [("John", 10), ("Jane", 20)]
    df1 = pandas.DataFrame(df1_data, columns=["name", "points"])
    df2_data = [("Dash", 50)]
    df2 = pandas.DataFrame(df2_data, columns=["name", "points"])
    df3_data = [(2022, "Jan", 10000), (2022, "Feb", 10220)]
    df3 = pandas.DataFrame(df3_data, columns=["year", "month", "revenue"])

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
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        cnx.execute_string(create_sql)
        try:
            # Write dataframe with 2 rows
            write_pandas(
                cnx,
                df1,
                random_table_name,
                quote_identifiers=quote_identifiers,
                auto_create_table=auto_create_table,
                overwrite=True,
            )
            # Write dataframe with 1 row
            success, nchunks, nrows, _ = write_pandas(
                cnx,
                df2,
                random_table_name,
                quote_identifiers=quote_identifiers,
                auto_create_table=auto_create_table,
                overwrite=True,
            )
            # Check write_pandas output
            assert success
            assert nchunks == 1
            result = cnx.cursor(DictCursor).execute(select_count_sql).fetchone()
            # Check number of rows
            assert result["COUNT(*)"] == 1

            # Write dataframe with a different schema
            if auto_create_table:
                # Should drop table and SUCCEED because the new table will be created with new schema of df3
                success, nchunks, nrows, _ = write_pandas(
                    cnx,
                    df3,
                    random_table_name,
                    quote_identifiers=quote_identifiers,
                    auto_create_table=auto_create_table,
                    overwrite=True,
                )
                # Check write_pandas output
                assert success
                assert nchunks == 1
                result = cnx.execute_string(select_sql)
                # Check column names
                assert (
                    "year"
                    if quote_identifiers
                    else "YEAR" in [col.name for col in result[0].description]
                )

        finally:
            cnx.execute_string(drop_sql)


@pytest.mark.parametrize("chunk_size", [5, 1])
@pytest.mark.parametrize(
    "compression",
    [
        "gzip",
    ],
)
@pytest.mark.parametrize("quote_identifiers", [True, False])
@pytest.mark.parametrize("auto_create_table", [True, False])
@pytest.mark.parametrize("create_temp_table", [True, False])
def test_write_pandas(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
    db_parameters: dict[str, str],
    compression: str,
    chunk_size: int,
    quote_identifiers: bool,
    auto_create_table: bool,
    create_temp_table: bool,
):
    num_of_chunks = math.ceil(len(sf_connector_version_data) / chunk_size)

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
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
            cnx.execute_string(create_sql)
        try:
            success, nchunks, nrows, _ = write_pandas(
                cnx,
                sf_connector_version_df.get(),
                table_name,
                compression=compression,
                chunk_size=chunk_size,
                quote_identifiers=quote_identifiers,
                auto_create_table=auto_create_table,
                create_temp_table=create_temp_table,
            )

            if num_of_chunks == 1:
                # Note: since we used one chunk order is conserved
                assert (
                    cnx.cursor().execute(select_sql).fetchall()
                    == sf_connector_version_data
                )
            else:
                # Note: since we used more than one chunk order is NOT conserved
                assert set(cnx.cursor().execute(select_sql).fetchall()) == set(
                    sf_connector_version_data
                )

            # Make sure all files were loaded and no error occurred
            assert success
            # Make sure overall as many rows were ingested as we tried to insert
            assert nrows == len(sf_connector_version_data)
            # Make sure we uploaded in as many chunk as we wanted to
            assert nchunks == num_of_chunks
            # Check to see if this is a temporary or regular table if we auto-created this table
            if auto_create_table:
                table_info = (
                    cnx.cursor(DictCursor)
                    .execute(f"show tables like '{table_name}'")
                    .fetchall()
                )
                assert table_info[0]["kind"] == (
                    "TEMPORARY" if create_temp_table else "TABLE"
                )
        finally:
            cnx.execute_string(drop_sql)


@pytest.mark.parametrize("table_type", ["", "temp", "temporary", "transient"])
def test_write_pandas_table_type(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
    table_type: str,
):
    with conn_cnx() as cnx:
        table_name = f"driver_versions_{table_type}"
        drop_sql = f"DROP TABLE IF EXISTS {table_name}"
        try:
            success, _, _, _ = write_pandas(
                cnx,
                sf_connector_version_df.get(),
                table_name,
                table_type=table_type,
                auto_create_table=True,
            )
            table_info = (
                cnx.cursor(DictCursor)
                .execute(f"show tables like '{table_name}'")
                .fetchall()
            )
            assert success
            if not table_type:
                expected_table_kind = "TABLE"
            elif table_type == "temp":
                expected_table_kind = "TEMPORARY"
            else:
                expected_table_kind = table_type.upper()
            assert table_info[0]["kind"] == expected_table_kind
        finally:
            cnx.execute_string(drop_sql)


def test_write_pandas_create_temp_table_deprecation_warning(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
):
    with conn_cnx() as cnx:
        table_name = "driver_versions"
        drop_sql = f"DROP TABLE IF EXISTS {table_name}"
        try:
            with pytest.deprecated_call(match="create_temp_table is deprecated"):
                success, _, _, _ = write_pandas(
                    cnx,
                    sf_connector_version_df.get(),
                    table_name,
                    create_temp_table=True,
                    auto_create_table=True,
                )

            assert success
            table_info = (
                cnx.cursor(DictCursor)
                .execute(f"show tables like '{table_name}'")
                .fetchall()
            )
            assert table_info[0]["kind"] == "TEMPORARY"
        finally:
            cnx.execute_string(drop_sql)


def test_invalid_table_type_write_pandas(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
):
    with conn_cnx() as cnx:
        with pytest.raises(ValueError, match="Unsupported table type"):
            write_pandas(
                cnx,
                sf_connector_version_df.get(),
                "invalid_table_type",
                table_type="invalid",
            )


@pytest.mark.parametrize("quote_identifiers", [True, False])
def test_location_building_db_schema(conn_cnx, quote_identifiers: bool):
    """This tests that write_pandas constructs location correctly with database, schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor

    with conn_cnx() as cnx:

        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith("COPY INTO"):
                location = args[0].split(" ")[2]
                if quote_identifiers:
                    assert location == '"database"."schema"."table"'
                else:
                    assert location == "database.schema.table"
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur

        with mock.patch(
            "snowflake.connector.cursor.SnowflakeCursor.execute",
            side_effect=mocked_execute,
        ) as m_execute:
            success, nchunks, nrows, _ = write_pandas(
                cnx,
                sf_connector_version_df.get(),
                "table",
                database="database",
                schema="schema",
                quote_identifiers=quote_identifiers,
            )
            assert m_execute.called and any(
                map(lambda e: "COPY INTO" in str(e[0]), m_execute.call_args_list)
            )


@pytest.mark.parametrize("quote_identifiers", [True, False])
def test_location_building_schema(conn_cnx, quote_identifiers: bool):
    """This tests that write_pandas constructs location correctly with schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor

    with conn_cnx() as cnx:

        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith("COPY INTO"):
                location = args[0].split(" ")[2]
                if quote_identifiers:
                    assert location == '"schema"."table"'
                else:
                    assert location == "schema.table"
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur

        with mock.patch(
            "snowflake.connector.cursor.SnowflakeCursor.execute",
            side_effect=mocked_execute,
        ) as m_execute:
            success, nchunks, nrows, _ = write_pandas(
                cnx,
                sf_connector_version_df.get(),
                "table",
                schema="schema",
                quote_identifiers=quote_identifiers,
            )
            assert m_execute.called and any(
                map(lambda e: "COPY INTO" in str(e[0]), m_execute.call_args_list)
            )


@pytest.mark.parametrize("quote_identifiers", [True, False])
def test_location_building(conn_cnx, quote_identifiers: bool):
    """This tests that write_pandas constructs location correctly with schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor

    with conn_cnx() as cnx:

        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith("COPY INTO"):
                location = args[0].split(" ")[2]
                if quote_identifiers:
                    assert location == '"teble.table"'
                else:
                    assert location == "teble.table"
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur

        with mock.patch(
            "snowflake.connector.cursor.SnowflakeCursor.execute",
            side_effect=mocked_execute,
        ) as m_execute:
            success, nchunks, nrows, _ = write_pandas(
                cnx,
                sf_connector_version_df.get(),
                "teble.table",
                quote_identifiers=quote_identifiers,
            )
            assert m_execute.called and any(
                map(lambda e: "COPY INTO" in str(e[0]), m_execute.call_args_list)
            )


@pytest.mark.parametrize("quote_identifiers", [True, False])
def test_default_value_insertion(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
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
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        cnx.execute_string(create_sql)
        try:
            success, nchunks, nrows, _ = write_pandas(
                cnx, df, table_name, quote_identifiers=quote_identifiers
            )

            # Check write_pandas output
            assert success
            assert nrows == len(df_data)
            assert nchunks == 1
            # Check table's contents
            result = cnx.cursor(DictCursor).execute(select_sql).fetchall()
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
            cnx.execute_string(drop_sql)


@pytest.mark.parametrize("quote_identifiers", [True, False])
def test_autoincrement_insertion(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
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
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        cnx.execute_string(create_sql)
        try:
            success, nchunks, nrows, _ = write_pandas(
                cnx, df, table_name, quote_identifiers=quote_identifiers
            )

            # Check write_pandas output
            assert success
            assert nrows == len(df_data)
            assert nchunks == 1
            # Check table's contents
            result = cnx.cursor(DictCursor).execute(select_sql).fetchall()
            for row in result:
                assert row["id" if quote_identifiers else "ID"] in (1, 2)
                assert (
                    row["name" if quote_identifiers else "NAME"],
                    row["balance" if quote_identifiers else "BALANCE"],
                ) in df_data
        finally:
            cnx.execute_string(drop_sql)


@pytest.mark.parametrize("auto_create_table", [True, False])
def test_special_name_quoting(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
    auto_create_table: bool,
):
    """Tests whether special column names get quoted as expected."""
    table_name = "users"
    df_data = [("Mark", 10), ("Luke", 20)]

    df = pandas.DataFrame(df_data, columns=["00name", "bAlance"])
    create_sql = (
        f'CREATE OR REPLACE TABLE "{table_name}"'
        '("00name" STRING, "bAlance" INT, "id" INT AUTOINCREMENT)'
    )
    select_sql = f'SELECT * FROM "{table_name}"'
    drop_sql = f'DROP TABLE IF EXISTS "{table_name}"'
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        if not auto_create_table:
            cnx.execute_string(create_sql)
        try:
            success, nchunks, nrows, _ = write_pandas(
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
            result = cnx.cursor(DictCursor).execute(select_sql).fetchall()
            for row in result:
                # The auto create table functionality does not auto-create an incrementing ID
                if not auto_create_table:
                    assert row["id"] in (1, 2)
                assert (
                    row["00name"],
                    row["bAlance"],
                ) in df_data
        finally:
            cnx.execute_string(drop_sql)


def test_auto_create_table_similar_column_names(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]],
):
    """Tests whether similar names do not cause issues when auto-creating a table as expected."""
    table_name = random_string(5, "numbas_")
    df_data = [(10, 11), (20, 21)]

    df = pandas.DataFrame(df_data, columns=["number", "Number"])
    select_sql = f'SELECT * FROM "{table_name}"'
    drop_sql = f'DROP TABLE IF EXISTS "{table_name}"'
    with conn_cnx() as cnx:
        try:
            success, nchunks, nrows, _ = write_pandas(
                cnx, df, table_name, quote_identifiers=True, auto_create_table=True
            )

            # Check write_pandas output
            assert success
            assert nrows == len(df_data)
            assert nchunks == 1
            # Check table's contents
            result = cnx.cursor(DictCursor).execute(select_sql).fetchall()
            for row in result:
                assert (
                    row["number"],
                    row["Number"],
                ) in df_data
        finally:
            cnx.execute_string(drop_sql)


def test_all_pandas_types(
    conn_cnx: Callable[..., Generator[SnowflakeConnection, None, None]]
):
    table_name = random_string(5, "all_types_")
    datetime_with_tz = datetime(
        1997, 6, 3, 14, 21, 32, 00, tzinfo=timezone(timedelta(hours=+10))
    )
    datetime_with_ntz = datetime(1997, 6, 3, 14, 21, 32, 00)
    df_data = [
        (1, 1.1, "1string1", True, datetime_with_tz, datetime_with_ntz),
        (2, 2.2, "2string2", False, datetime_with_tz, datetime_with_ntz),
    ]
    df_data_no_timestamps = [
        (
            row[0],
            row[1],
            row[2],
            row[3],
        )
        for row in df_data
    ]

    df = pandas.DataFrame(
        df_data,
        columns=["int", "float", "string", "bool", "timestamp_tz", "timestamp_ntz"],
    )

    select_sql = f'SELECT * FROM "{table_name}"'
    drop_sql = f'DROP TABLE IF EXISTS "{table_name}"'
    with conn_cnx() as cnx:
        try:
            success, nchunks, nrows, _ = write_pandas(
                cnx, df, table_name, quote_identifiers=True, auto_create_table=True
            )

            # Check write_pandas output
            assert success
            assert nrows == len(df_data)
            assert nchunks == 1
            # Check table's contents
            result = cnx.cursor(DictCursor).execute(select_sql).fetchall()
            for row in result:
                assert (
                    row["int"],
                    row["float"],
                    row["string"],
                    row["bool"],
                ) in df_data_no_timestamps
                # TODO: Schema detection on the server-side has bugs dealing with timestamp_ntz and timestamp_tz.
                #  After the bugs are fixed, change the assertion to `data[0]["tm_tz"] == datetime_with_tz`
                #  and `data[0]["tm_ntz"] == datetime_with_ntz`,
                #  JIRA https://snowflakecomputing.atlassian.net/browse/SNOW-524865
                #  JIRA https://snowflakecomputing.atlassian.net/browse/SNOW-359205
                #  JIRA https://snowflakecomputing.atlassian.net/browse/SNOW-507644
                assert row["timestamp_tz"] is not None
                assert row["timestamp_ntz"] is not None
        finally:
            cnx.execute_string(drop_sql)
