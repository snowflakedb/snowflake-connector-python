#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import glob
import gzip
import os
import sys
import time
from logging import getLogger

import pytest

from snowflake.connector.constants import UTF8
from snowflake.connector.file_transfer_agent import (
    SnowflakeAzureProgressPercentage,
    SnowflakeProgressPercentage,
)

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from test.randomize import random_string

from test.generate_test_files import generate_k_lines_of_n_files
from test.integ_helpers import put_async

logger = getLogger(__name__)

# Mark every test in this module as an azure and a putget test
pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
async def test_put_get_with_azure(tmpdir, aio_connection, from_path):
    """[azure] Puts and Gets a small text using Azure."""
    # create a data file
    fname = str(tmpdir.join("test_put_get_with_azure_token.txt.gz"))
    original_contents = "123,test1\n456,test2\n"
    with gzip.open(fname, "wb") as f:
        f.write(original_contents.encode(UTF8))
    tmp_dir = str(tmpdir.mkdir("test_put_get_with_azure_token"))
    table_name = random_string(5, "snow32806_")

    await aio_connection.connect()
    csr = aio_connection.cursor()

    await csr.execute(f"create or replace table {table_name} (a int, b string)")
    try:
        file_stream = None if from_path else open(fname, "rb")
        await put_async(
            csr,
            fname,
            f"%{table_name}",
            from_path,
            sql_options=" auto_compress=true parallel=30",
            _put_callback=SnowflakeAzureProgressPercentage,
            _get_callback=SnowflakeAzureProgressPercentage,
            file_stream=file_stream,
        )
        assert (await csr.fetchone())[6] == "UPLOADED"
        await csr.execute(f"copy into {table_name}")
        await csr.execute(f"rm @%{table_name}")
        assert await (await csr.execute(f"ls @%{table_name}")).fetchall() == []
        await csr.execute(
            f"copy into @%{table_name} from {table_name} "
            "file_format=(type=csv compression='gzip')"
        )
        await csr.execute(
            f"get @%{table_name} file://{tmp_dir}",
            _put_callback=SnowflakeAzureProgressPercentage,
            _get_callback=SnowflakeAzureProgressPercentage,
        )
        rec = await csr.fetchone()
        assert rec[0].startswith("data_"), "A file downloaded by GET"
        assert rec[1] == 36, "Return right file size"
        assert rec[2] == "DOWNLOADED", "Return DOWNLOADED status"
        assert rec[3] == "", "Return no error message"
    finally:
        if file_stream:
            file_stream.close()
        await csr.execute(f"drop table {table_name}")

    files = glob.glob(os.path.join(tmp_dir, "data_*"))
    with gzip.open(files[0], "rb") as fd:
        contents = fd.read().decode(UTF8)
    assert original_contents == contents, "Output is different from the original file"


async def test_put_copy_many_files_azure(tmpdir, aio_connection):
    """[azure] Puts and Copies many files."""
    # generates N files
    number_of_files = 10
    number_of_lines = 1000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )
    folder_name = random_string(5, "test_put_copy_many_files_azure_")

    files = os.path.join(tmp_dir, "file*")

    async def run(csr, sql):
        sql = sql.format(files=files, name=folder_name)
        return await (await csr.execute(sql)).fetchall()

    await aio_connection.connect()
    csr = aio_connection.cursor()

    await run(
        csr,
        """
    create or replace table {name} (
    aa int,
    dt date,
    ts timestamp,
    tsltz timestamp_ltz,
    tsntz timestamp_ntz,
    tstz timestamp_tz,
    pct float,
    ratio number(6,2))
    """,
    )
    try:
        all_recs = await run(csr, "put file://{files} @%{name}")
        assert all([rec[6] == "UPLOADED" for rec in all_recs])
        await run(csr, "copy into {name}")

        rows = sum(rec[0] for rec in await run(csr, "select count(*) from {name}"))
        assert rows == number_of_files * number_of_lines, "Number of rows"
    finally:
        await run(csr, "drop table if exists {name}")


async def test_put_copy_duplicated_files_azure(tmpdir, aio_connection):
    """[azure] Puts and Copies duplicated files."""
    # generates N files
    number_of_files = 5
    number_of_lines = 100
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )
    table_name = random_string(5, "test_put_copy_duplicated_files_azure_")

    files = os.path.join(tmp_dir, "file*")

    async def run(csr, sql):
        sql = sql.format(files=files, name=table_name)
        return await (await csr.execute(sql, _raise_put_get_error=False)).fetchall()

    await aio_connection.connect()
    csr = aio_connection.cursor()
    await run(
        csr,
        """
    create or replace table {name} (
    aa int,
    dt date,
    ts timestamp,
    tsltz timestamp_ltz,
    tsntz timestamp_ntz,
    tstz timestamp_tz,
    pct float,
    ratio number(6,2))
    """,
    )

    try:
        success_cnt = 0
        skipped_cnt = 0
        for rec in await run(csr, "put file://{files} @%{name}"):
            logger.info("rec=%s", rec)
            if rec[6] == "UPLOADED":
                success_cnt += 1
            elif rec[6] == "SKIPPED":
                skipped_cnt += 1
        assert success_cnt == number_of_files, "uploaded files"
        assert skipped_cnt == 0, "skipped files"

        deleted_cnt = 0
        await run(csr, "rm @%{name}/file0")
        deleted_cnt += 1
        await run(csr, "rm @%{name}/file1")
        deleted_cnt += 1
        await run(csr, "rm @%{name}/file2")
        deleted_cnt += 1

        success_cnt = 0
        skipped_cnt = 0
        for rec in await run(csr, "put file://{files} @%{name}"):
            logger.info("rec=%s", rec)
            if rec[6] == "UPLOADED":
                success_cnt += 1
            elif rec[6] == "SKIPPED":
                skipped_cnt += 1
        assert success_cnt == deleted_cnt, "uploaded files in the second time"
        assert (
            skipped_cnt == number_of_files - deleted_cnt
        ), "skipped files in the second time"

        await run(csr, "copy into {name}")
        rows = 0
        for rec in await run(csr, "select count(*) from {name}"):
            rows += rec[0]
        assert rows == number_of_files * number_of_lines, "Number of rows"
    finally:
        await run(csr, "drop table if exists {name}")


async def test_put_get_large_files_azure(tmpdir, aio_connection):
    """[azure] Puts and Gets Large files."""
    number_of_files = 3
    number_of_lines = 200000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")
    output_dir = os.path.join(tmp_dir, "output_dir")
    os.makedirs(output_dir)
    folder_name = random_string(5, "test_put_get_large_files_azure_")

    class cb(SnowflakeProgressPercentage):
        def __init__(self, filename, filesize, **_):
            pass

        def __call__(self, bytes_amount):
            pass

    async def run(cnx, sql):
        return await (
            await cnx.cursor().execute(
                sql.format(files=files, dir=folder_name, output_dir=output_dir),
                _put_callback_output_stream=sys.stdout,
                _get_callback_output_stream=sys.stdout,
                _get_callback=cb,
                _put_callback=cb,
            )
        ).fetchall()

    await aio_connection.connect()
    try:
        all_recs = await run(aio_connection, "PUT file://{files} @~/{dir}")
        assert all([rec[6] == "UPLOADED" for rec in all_recs])

        for _ in range(60):
            for _ in range(100):
                all_recs = await run(aio_connection, "LIST @~/{dir}")
                if len(all_recs) == number_of_files:
                    break
                # you may not get the files right after PUT command
                # due to the nature of Azure blob, which synchronizes
                # data eventually.
                time.sleep(1)
            else:
                # wait for another second and retry.
                # this could happen if the files are partially available
                # but not all.
                time.sleep(1)
                continue
            break  # success
        else:
            pytest.fail(
                "cannot list all files. Potentially "
                "PUT command missed uploading Files: {}".format(all_recs)
            )
        all_recs = await run(aio_connection, "GET @~/{dir} file://{output_dir}")
        assert len(all_recs) == number_of_files
        assert all([rec[2] == "DOWNLOADED" for rec in all_recs])
    finally:
        await run(aio_connection, "RM @~/{dir}")
