#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os
from test.generate_test_files import generate_k_lines_of_n_files
from unittest.mock import patch

import pytest

from snowflake.connector.aio._file_transfer_agent import SnowflakeFileTransferAgent


@pytest.mark.skipolddriver
@pytest.mark.aws
async def test_put_copy_large_files(tmpdir, conn_cnx, db_parameters):
    """[s3] Puts and Copies into large files."""
    # generates N files
    number_of_files = 2
    number_of_lines = 200000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")
    async with conn_cnx() as cnx:
        await cnx.cursor().execute(
            f"""
create table {db_parameters['name']} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(6,2))
"""
        )
    try:
        async with conn_cnx() as cnx:
            files = files.replace("\\", "\\\\")

            def mocked_file_agent(*args, **kwargs):
                newkwargs = kwargs.copy()
                newkwargs.update(multipart_threshold=10000)
                agent = SnowflakeFileTransferAgent(*args, **newkwargs)
                mocked_file_agent.agent = agent
                return agent

            with patch(
                "snowflake.connector.aio._file_transfer_agent.SnowflakeFileTransferAgent",
                side_effect=mocked_file_agent,
            ):
                # upload with auto compress = True
                await cnx.cursor().execute(
                    f"put 'file://{files}' @%{db_parameters['name']} auto_compress=True",
                )
                assert mocked_file_agent.agent._multipart_threshold == 10000
                await cnx.cursor().execute(f"remove @%{db_parameters['name']}")

                # upload with auto compress = False
                await cnx.cursor().execute(
                    f"put 'file://{files}' @%{db_parameters['name']} auto_compress=False",
                )
                assert mocked_file_agent.agent._multipart_threshold == 10000

                # Upload again. There was a bug when a large file is uploaded again while it already exists in a stage.
                # Refer to preprocess(self) of storage_client.py.
                # self.get_digest() needs to be called before self.get_file_header(meta.dst_file_name).
                # SNOW-749141
                await cnx.cursor().execute(
                    f"put 'file://{files}' @%{db_parameters['name']} auto_compress=False",
                )  # do not add `overwrite=True` because overwrite will skip the code path to extract file header.

            c = cnx.cursor()
            try:
                await c.execute("copy into {}".format(db_parameters["name"]))
                cnt = 0
                async for _ in c:
                    cnt += 1
                assert cnt == number_of_files, "Number of PUT files"
            finally:
                await c.close()

            c = cnx.cursor()
            try:
                await c.execute(
                    "select count(*) from {name}".format(name=db_parameters["name"])
                )
                cnt = 0
                async for rec in c:
                    cnt += rec[0]
                assert cnt == number_of_files * number_of_lines, "Number of rows"
            finally:
                await c.close()
    finally:
        async with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            await cnx.cursor().execute(
                "drop table if exists {table}".format(table=db_parameters["name"])
            )
