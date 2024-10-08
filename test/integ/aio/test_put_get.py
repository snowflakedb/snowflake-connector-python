#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import filecmp
import logging
import os
from io import BytesIO
from logging import getLogger
from os import path
from unittest import mock

import pytest

from snowflake.connector import OperationalError

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from test.randomize import random_string

from test.generate_test_files import generate_k_lines_of_n_files

try:
    from ..parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

THIS_DIR = path.dirname(path.realpath(__file__))

logger = getLogger(__name__)

pytestmark = pytest.mark.asyncio
CLOUD = os.getenv("cloud_provider", "dev")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
async def test_utf8_filename(tmp_path, aio_connection):
    test_file = tmp_path / "utf卡豆.csv"
    test_file.write_text("1,2,3\n")
    stage_name = random_string(5, "test_utf8_filename_")
    await aio_connection.connect()
    cursor = aio_connection.cursor()
    await cursor.execute(f"create temporary stage {stage_name}")
    (
        await cursor.execute(
            "PUT 'file://{}' @{}".format(str(test_file).replace("\\", "/"), stage_name)
        )
    ).fetchall()
    await cursor.execute(f"select $1, $2, $3 from  @{stage_name}")
    assert await cursor.fetchone() == ("1", "2", "3")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
async def test_put_threshold(tmp_path, aio_connection, is_public_test):
    if is_public_test:
        pytest.xfail(
            reason="This feature hasn't been rolled out for public Snowflake deployments yet."
        )
    file_name = "test_put_get_with_aws_token.txt.gz"
    stage_name = random_string(5, "test_put_get_threshold_")
    file = tmp_path / file_name
    file.touch()
    await aio_connection.connect()
    cursor = aio_connection.cursor()
    await cursor.execute(f"create temporary stage {stage_name}")
    from snowflake.connector.file_transfer_agent import SnowflakeFileTransferAgent

    with mock.patch(
        "snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent",
        autospec=SnowflakeFileTransferAgent,
    ) as mock_agent:
        await cursor.execute(f"put file://{file} @{stage_name} threshold=156")
    assert mock_agent.call_args[1].get("multipart_threshold", -1) == 156


# Snowflake on GCP does not support multipart uploads
@pytest.mark.xfail(reason="multipart transfer is not merged yet")
# @pytest.mark.aws
# @pytest.mark.azure
@pytest.mark.parametrize("use_stream", [False, True])
async def test_multipart_put(aio_connection, tmp_path, use_stream):
    """This test does a multipart upload of a smaller file and then downloads it."""
    stage_name = random_string(5, "test_multipart_put_")
    chunk_size = 6967790
    # Generate about 12 MB
    generate_k_lines_of_n_files(100_000, 1, tmp_dir=str(tmp_path))
    get_dir = tmp_path / "get_dir"
    get_dir.mkdir()
    upload_file = tmp_path / "file0"
    await aio_connection.connect()
    cursor = aio_connection.cursor()
    await cursor.execute(f"create temporary stage {stage_name}")
    real_cmd_query = aio_connection.cmd_query

    async def fake_cmd_query(*a, **kw):
        """Create a mock function to inject some value into the returned JSON"""
        ret = await real_cmd_query(*a, **kw)
        ret["data"]["threshold"] = chunk_size
        return ret

    with mock.patch.object(aio_connection, "cmd_query", side_effect=fake_cmd_query):
        with mock.patch("snowflake.connector.constants.S3_CHUNK_SIZE", chunk_size):
            if use_stream:
                kw = {
                    "command": f"put file://file0 @{stage_name} AUTO_COMPRESS=FALSE",
                    "file_stream": BytesIO(upload_file.read_bytes()),
                }
            else:
                kw = {
                    "command": f"put file://{upload_file} @{stage_name} AUTO_COMPRESS=FALSE",
                }
            await cursor.execute(**kw)
            res = await cursor.execute(f"list @{stage_name}")
            print(await res.fetchall())
    await cursor.execute(f"get @{stage_name}/{upload_file.name} file://{get_dir}")
    downloaded_file = get_dir / upload_file.name
    assert downloaded_file.exists()
    assert filecmp.cmp(upload_file, downloaded_file)


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
async def test_put_special_file_name(tmp_path, aio_connection):
    test_file = tmp_path / "data~%23.csv"
    test_file.write_text("1,2,3\n")
    stage_name = random_string(5, "test_special_filename_")
    await aio_connection.connect()
    cursor = aio_connection.cursor()
    await cursor.execute(f"create temporary stage {stage_name}")
    filename_in_put = str(test_file).replace("\\", "/")
    (
        await cursor.execute(
            f"PUT 'file://{filename_in_put}' @{stage_name}",
        )
    ).fetchall()
    await cursor.execute(f"select $1, $2, $3 from  @{stage_name}")
    assert await cursor.fetchone() == ("1", "2", "3")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
async def test_get_empty_file(tmp_path, aio_connection):
    test_file = tmp_path / "data.csv"
    test_file.write_text("1,2,3\n")
    stage_name = random_string(5, "test_get_empty_file_")
    await aio_connection.connect()
    cur = aio_connection.cursor()
    await cur.execute(f"create temporary stage {stage_name}")
    filename_in_put = str(test_file).replace("\\", "/")
    await cur.execute(
        f"PUT 'file://{filename_in_put}' @{stage_name}",
    )
    empty_file = tmp_path / "foo.csv"
    with pytest.raises(OperationalError, match=".*the file does not exist.*$"):
        await cur.execute(f"GET @{stage_name}/foo.csv file://{tmp_path}")
    assert not empty_file.exists()


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
async def test_get_file_permission(tmp_path, aio_connection, caplog):
    test_file = tmp_path / "data.csv"
    test_file.write_text("1,2,3\n")
    stage_name = random_string(5, "test_get_empty_file_")
    await aio_connection.connect()
    cur = aio_connection.cursor()
    await cur.execute(f"create temporary stage {stage_name}")
    filename_in_put = str(test_file).replace("\\", "/")
    await cur.execute(
        f"PUT 'file://{filename_in_put}' @{stage_name}",
    )

    with caplog.at_level(logging.ERROR):
        await cur.execute(f"GET @{stage_name}/data.csv file://{tmp_path}")
    assert "FileNotFoundError" not in caplog.text

    # get the default mask, usually it is 0o022
    default_mask = os.umask(0)
    os.umask(default_mask)
    # files by default are given the permission 644 (Octal)
    # umask is for denial, we need to negate
    assert oct(os.stat(test_file).st_mode)[-3:] == oct(0o666 & ~default_mask)[-3:]


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
async def test_get_multiple_files_with_same_name(tmp_path, aio_connection, caplog):
    test_file = tmp_path / "data.csv"
    test_file.write_text("1,2,3\n")
    stage_name = random_string(5, "test_get_multiple_files_with_same_name_")
    await aio_connection.connect()
    cur = aio_connection.cursor()
    await cur.execute(f"create temporary stage {stage_name}")
    filename_in_put = str(test_file).replace("\\", "/")
    await cur.execute(
        f"PUT 'file://{filename_in_put}' @{stage_name}/data/1/",
    )
    await cur.execute(
        f"PUT 'file://{filename_in_put}' @{stage_name}/data/2/",
    )

    with caplog.at_level(logging.WARNING):
        try:
            await cur.execute(
                f"GET @{stage_name} file://{tmp_path} PATTERN='.*data.csv.gz'"
            )
        except OperationalError:
            # This is expected flakiness
            pass
    assert "Downloading multiple files with the same name" in caplog.text


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
async def test_transfer_error_message(tmp_path, aio_connection):
    test_file = tmp_path / "data.csv"
    test_file.write_text("1,2,3\n")
    stage_name = random_string(5, "test_utf8_filename_")
    await aio_connection.connect()
    cursor = aio_connection.cursor()
    await cursor.execute(f"create temporary stage {stage_name}")
    with mock.patch(
        "snowflake.connector.aio._storage_client.SnowflakeStorageClient.finish_upload",
        side_effect=ConnectionError,
    ):
        with pytest.raises(OperationalError):
            (
                await cursor.execute(
                    "PUT 'file://{}' @{}".format(
                        str(test_file).replace("\\", "/"), stage_name
                    )
                )
            ).fetchall()
