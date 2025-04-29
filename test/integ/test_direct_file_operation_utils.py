#!/usr/bin/env python
from __future__ import annotations

import os
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Callable, Generator

import pytest

try:
    from snowflake.connector.options import pandas
    from snowflake.connector.pandas_tools import (
        _iceberg_config_statement_helper,
        write_pandas,
    )
except ImportError:
    pandas = None
    write_pandas = None
    _iceberg_config_statement_helper = None

if TYPE_CHECKING:
    from snowflake.connector import SnowflakeConnection, SnowflakeCursor


def _validate_upload_content(
    expected_content, cursor, stage_name, local_dir, base_file_name, is_compressed
):
    gz_suffix = ".gz"
    stage_path = f"@{stage_name}/{base_file_name}"
    local_path = f"{local_dir}/{base_file_name}"

    cursor.execute(
        f"GET ? 'file://{local_dir}'", params=[stage_path], _force_qmark_paramstyle=True
    )
    if is_compressed:
        stage_path += gz_suffix
        local_path += gz_suffix
        import gzip

        with gzip.open(local_path, "r") as f:
            read_content = f.read().decode("utf-8")
            assert read_content == expected_content, (read_content, expected_content)
    else:
        with open(local_path) as f:
            read_content = f.read()
    assert read_content == expected_content, (read_content, expected_content)


def _test_runner(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    task: Callable[[SnowflakeCursor, str, str, str], None],
    is_compressed: bool,
    special_stage_name: str = None,
    special_base_file_name: str = None,
):
    from snowflake.connector._utils import TempObjectType, random_name_for_temp_object

    with conn_cnx() as conn:
        cursor = conn.cursor()
        stage_name = special_stage_name or random_name_for_temp_object(
            TempObjectType.STAGE
        )
        cursor.execute(f"CREATE OR REPLACE SCOPED TEMP STAGE {stage_name}")
        expected_content = "hello, world"
        with TemporaryDirectory() as temp_dir:
            base_file_name = special_base_file_name or "test.txt"
            src_file_name = os.path.join(temp_dir, base_file_name)
            with open(src_file_name, "w") as f:
                f.write(expected_content)
            # Run the file operation
            task(cursor, stage_name, temp_dir, base_file_name)
            # Clean up before validation.
            os.remove(src_file_name)
            # Validate result.
            _validate_upload_content(
                expected_content,
                cursor,
                stage_name,
                temp_dir,
                base_file_name,
                is_compressed=is_compressed,
            )


@pytest.mark.skipolddriver
@pytest.mark.parametrize("is_compressed", [False, True])
def test_upload(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    is_compressed: bool,
):
    def upload_task(cursor, stage_name, temp_dir, base_file_name):
        cursor._upload(
            local_file_name=f"file://{temp_dir}/{base_file_name}",
            stage_location=f"@{stage_name}",
            options={"auto_compress": is_compressed},
        )

    _test_runner(conn_cnx, upload_task, is_compressed=is_compressed)


@pytest.mark.skipolddriver
@pytest.mark.parametrize("is_compressed", [False, True])
def test_upload_stream(
    conn_cnx: Callable[..., Generator[SnowflakeConnection]],
    is_compressed: bool,
):
    def upload_stream_task(cursor, stage_name, temp_dir, base_file_name):
        with open(f"{temp_dir}/{base_file_name}", "rb") as input_stream:
            cursor._upload_stream(
                input_stream=input_stream,
                stage_location=f"@{stage_name}/{base_file_name}",
                options={"auto_compress": is_compressed},
            )

    _test_runner(conn_cnx, upload_stream_task, is_compressed=is_compressed)
