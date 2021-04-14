#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

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

from ..generate_test_files import generate_k_lines_of_n_files
from ..integ_helpers import put
from ..randomize import random_string

logger = getLogger(__name__)

# Mark every test in this module as an azure and a putget test
pytestmark = pytest.mark.azure


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
def test_put_get_with_azure(tmpdir, conn_cnx, db_parameters, from_path):
    """[azure] Puts and Gets a small text using Azure."""
    # create a data file
    fname = str(tmpdir.join("test_put_get_with_azure_token.txt.gz"))
    original_contents = "123,test1\n456,test2\n"
    with gzip.open(fname, "wb") as f:
        f.write(original_contents.encode(UTF8))
    tmp_dir = str(tmpdir.mkdir("test_put_get_with_azure_token"))
    table_name = random_string(5, "snow32806_")

    with conn_cnx() as cnx:
        with cnx.cursor() as csr:
            csr.execute(
                "create or replace table {} (a int, b string)".format(table_name)
            )
            try:
                file_stream = None if from_path else open(fname, "rb")
                put(
                    csr,
                    fname,
                    f"%{table_name}",
                    from_path,
                    sql_options=" auto_compress=true parallel=30",
                    _put_callback=SnowflakeAzureProgressPercentage,
                    _get_callback=SnowflakeAzureProgressPercentage,
                    file_stream=file_stream,
                )
                assert csr.fetchone()[6] == "UPLOADED"
                csr.execute("copy into {}".format(table_name))
                csr.execute("rm @%{}".format(table_name))
                assert csr.execute("ls @%{}".format(table_name)).fetchall() == []
                csr.execute(
                    "copy into @%{table_name} from {table_name} "
                    "file_format=(type=csv compression='gzip')".format(
                        table_name=table_name
                    )
                )
                csr.execute(
                    "get @%{table_name} file://{}".format(
                        tmp_dir, table_name=table_name
                    ),
                    _put_callback=SnowflakeAzureProgressPercentage,
                    _get_callback=SnowflakeAzureProgressPercentage,
                )
                rec = csr.fetchone()
                assert rec[0].startswith("data_"), "A file downloaded by GET"
                assert rec[1] == 36, "Return right file size"
                assert rec[2] == "DOWNLOADED", "Return DOWNLOADED status"
                assert rec[3] == "", "Return no error message"
            finally:
                if file_stream:
                    file_stream.close()
                csr.execute("drop table {}".format(table_name))

    files = glob.glob(os.path.join(tmp_dir, "data_*"))
    with gzip.open(files[0], "rb") as fd:
        contents = fd.read().decode(UTF8)
    assert original_contents == contents, "Output is different from the original file"


def test_put_copy_many_files_azure(tmpdir, conn_cnx, db_parameters):
    """[azure] Puts and Copies many files."""
    # generates N files
    number_of_files = 10
    number_of_lines = 1000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )
    folder_name = random_string(5, "test_put_copy_many_files_azure_")

    files = os.path.join(tmp_dir, "file*")

    def run(csr, sql):
        sql = sql.format(files=files, name=folder_name)
        return csr.execute(sql).fetchall()

    with conn_cnx() as cnx:
        with cnx.cursor() as csr:
            run(
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
                all_recs = run(csr, "put file://{files} @%{name}")
                assert all([rec[6] == "UPLOADED" for rec in all_recs])
                run(csr, "copy into {name}")

                rows = sum([rec[0] for rec in run(csr, "select count(*) from {name}")])
                assert rows == number_of_files * number_of_lines, "Number of rows"
            finally:
                run(csr, "drop table if exists {name}")


def test_put_copy_duplicated_files_azure(tmpdir, conn_cnx, db_parameters):
    """[azure] Puts and Copies duplicated files."""
    # generates N files
    number_of_files = 5
    number_of_lines = 100
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )
    table_name = random_string(5, "test_put_copy_duplicated_files_azure_")

    files = os.path.join(tmp_dir, "file*")

    def run(csr, sql):
        sql = sql.format(files=files, name=table_name)
        return csr.execute(sql, _raise_put_get_error=False).fetchall()

    with conn_cnx() as cnx:
        with cnx.cursor() as csr:
            run(
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
                for rec in run(csr, "put file://{files} @%{name}"):
                    logger.info("rec=%s", rec)
                    if rec[6] == "UPLOADED":
                        success_cnt += 1
                    elif rec[6] == "SKIPPED":
                        skipped_cnt += 1
                assert success_cnt == number_of_files, "uploaded files"
                assert skipped_cnt == 0, "skipped files"

                deleted_cnt = 0
                run(csr, "rm @%{name}/file0")
                deleted_cnt += 1
                run(csr, "rm @%{name}/file1")
                deleted_cnt += 1
                run(csr, "rm @%{name}/file2")
                deleted_cnt += 1

                success_cnt = 0
                skipped_cnt = 0
                for rec in run(csr, "put file://{files} @%{name}"):
                    logger.info("rec=%s", rec)
                    if rec[6] == "UPLOADED":
                        success_cnt += 1
                    elif rec[6] == "SKIPPED":
                        skipped_cnt += 1
                assert success_cnt == deleted_cnt, "uploaded files in the second time"
                assert (
                    skipped_cnt == number_of_files - deleted_cnt
                ), "skipped files in the second time"

                run(csr, "copy into {name}")
                rows = 0
                for rec in run(csr, "select count(*) from {name}"):
                    rows += rec[0]
                assert rows == number_of_files * number_of_lines, "Number of rows"
            finally:
                run(csr, "drop table if exists {name}")


def test_put_get_large_files_azure(tmpdir, conn_cnx, db_parameters):
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

    def run(cnx, sql):
        return (
            cnx.cursor()
            .execute(
                sql.format(files=files, dir=folder_name, output_dir=output_dir),
                _put_callback_output_stream=sys.stdout,
                _get_callback_output_stream=sys.stdout,
                _get_callback=cb,
                _put_callback=cb,
            )
            .fetchall()
        )

    with conn_cnx() as cnx:
        try:
            all_recs = run(cnx, "PUT file://{files} @~/{dir}")
            assert all([rec[6] == "UPLOADED" for rec in all_recs])

            for _ in range(60):
                for _ in range(100):
                    all_recs = run(cnx, "LIST @~/{dir}")
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
            all_recs = run(cnx, "GET @~/{dir} file://{output_dir}")
            assert len(all_recs) == number_of_files
            assert all([rec[2] == "DOWNLOADED" for rec in all_recs])
        finally:
            run(cnx, "RM @~/{dir}")
