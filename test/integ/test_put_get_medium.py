#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import datetime
import gzip
import os
import sys
import time
from logging import getLogger
from typing import IO, Tuple

import pytest
import pytz

from snowflake.connector import ProgrammingError
from snowflake.connector.cursor import DictCursor
from snowflake.connector.file_transfer_agent import (
    SnowflakeAzureProgressPercentage,
    SnowflakeProgressPercentage,
    SnowflakeS3ProgressPercentage,
)

from ..generate_test_files import generate_k_lines_of_n_files
from ..integ_helpers import put
from ..randomize import random_string

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
logger = getLogger(__name__)


@pytest.fixture()
def file_src(request) -> Tuple[str, int, IO[bytes]]:
    file_name = request.param
    data_file = os.path.join(THIS_DIR, "../data", file_name)
    file_size = os.stat(data_file).st_size
    stream = open(data_file, "rb")
    yield data_file, file_size, stream
    stream.close()


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["put_get_1.txt"], indirect=["file_src"])
def test_put_copy0(conn_cnx, db_parameters, from_path, file_src):
    """Puts and Copies a file."""
    file_path, _, file_stream = file_src
    kwargs = {
        "_put_callback": SnowflakeS3ProgressPercentage,
        "_get_callback": SnowflakeS3ProgressPercentage,
        "_put_azure_callback": SnowflakeAzureProgressPercentage,
        "_get_azure_callback": SnowflakeAzureProgressPercentage,
        "file_stream": file_stream,
    }

    def run(cnx, sql):
        sql = sql.format(name=db_parameters["name"])
        return cnx.cursor().execute(sql).fetchall()

    def run_with_cursor(cnx, sql):
        sql = sql.format(name=db_parameters["name"])
        c = cnx.cursor(DictCursor)
        return c, c.execute(sql).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        run(
            cnx,
            """
create table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(5,2))
""",
        )

        with cnx.cursor(DictCursor) as csr:
            ret = put(
                csr, file_path, f"%{db_parameters['name']}", from_path, **kwargs
            ).fetchall()
            assert csr.is_file_transfer, "PUT"
            assert len(ret) == 1, "Upload one file"
            assert ret[0]["source"] == os.path.basename(file_path), "File name"

        c, ret = run_with_cursor(cnx, "copy into {name}")
        assert not c.is_file_transfer, "COPY"
        assert len(ret) == 1 and ret[0]["status"] == "LOADED", "Failed to load data"

        assert ret[0]["rows_loaded"] == 3, "Failed to load 3 rows of data"

        run(cnx, "drop table if exists {name}")


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["gzip_sample.txt.gz"], indirect=["file_src"])
def test_put_copy_compressed(conn_cnx, db_parameters, from_path, file_src):
    """Puts and Copies compressed files."""
    file_name, file_size, file_stream = file_src

    def run(cnx, sql):
        sql = sql.format(name=db_parameters["name"])
        return cnx.cursor(DictCursor).execute(sql).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        run(cnx, "create or replace table {name} (value string)")
        with cnx.cursor(DictCursor) as csr:
            ret = put(
                csr,
                file_name,
                f"%{db_parameters['name']}",
                from_path,
                file_stream=file_stream,
            ).fetchall()
            assert ret[0]["source"] == os.path.basename(file_name), "File name"
            assert ret[0]["source_size"] == file_size, "File size"
            assert ret[0]["status"] == "UPLOADED"
        ret = run(cnx, "copy into {name}")
        assert len(ret) == 1 and ret[0]["status"] == "LOADED", "Failed to load data"
        assert ret[0]["rows_loaded"] == 1, "Failed to load 1 rows of data"

        run(cnx, "drop table if exists {name}")


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["bzip2_sample.txt.bz2"], indirect=["file_src"])
@pytest.mark.skip(reason="BZ2 is not detected in this test case. Need investigation")
def test_put_copy_bz2_compressed(conn_cnx, db_parameters, from_path, file_src):
    """Put and Copy bz2 compressed files."""
    file_name, _, file_stream = file_src

    def run(cnx, sql):
        sql = sql.format(name=db_parameters["name"])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        run(cnx, "create or replace table {name} (value string)")
        for rec in put(
            cnx.cursor(),
            file_name,
            f"%{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
        ).fetchall():
            print(rec)
            assert rec[-2] == "UPLOADED"

        for rec in run(cnx, "copy into {name}"):
            print(rec)
            assert rec[1] == "LOADED"

        run(cnx, "drop table if exists {name}")


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["brotli_sample.txt.br"], indirect=["file_src"])
def test_put_copy_brotli_compressed(conn_cnx, db_parameters, from_path, file_src):
    """Puts and Copies brotli compressed files."""
    file_name, _, file_stream = file_src

    def run(cnx, sql):
        sql = sql.format(name=db_parameters["name"])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:

        run(cnx, "create or replace table {name} (value string)")
        for rec in put(
            cnx.cursor(),
            file_name,
            f"%{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
        ).fetchall():
            print(rec)
            assert rec[-2] == "UPLOADED"

        for rec in run(cnx, "copy into {name} file_format=(compression='BROTLI')"):
            print(rec)
            assert rec[1] == "LOADED"

        run(cnx, "drop table if exists {name}")


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["zstd_sample.txt.zst"], indirect=["file_src"])
def test_put_copy_zstd_compressed(conn_cnx, db_parameters, from_path, file_src):
    """Puts and Copies zstd compressed files."""
    file_name, _, file_stream = file_src

    def run(cnx, sql):
        sql = sql.format(name=db_parameters["name"])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        run(cnx, "create or replace table {name} (value string)")
        for rec in put(
            cnx.cursor(),
            file_name,
            f"%{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
        ).fetchall():
            print(rec)
            assert rec[-2] == "UPLOADED"
        for rec in run(cnx, "copy into {name} file_format=(compression='ZSTD')"):
            print(rec)
            assert rec[1] == "LOADED"

        run(cnx, "drop table if exists {name}")


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["nation.impala.parquet"], indirect=["file_src"])
def test_put_copy_parquet_compressed(conn_cnx, db_parameters, from_path, file_src):
    """Puts and Copies parquet compressed files."""
    file_name, _, file_stream = file_src

    def run(cnx, sql):
        sql = sql.format(name=db_parameters["name"])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        run(cnx, "alter session set enable_parquet_filetype=true")
        run(
            cnx,
            """
create or replace table {name}
(value variant)
stage_file_format=(type='parquet')
""",
        )
        for rec in put(
            cnx.cursor(),
            file_name,
            f"%{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
        ).fetchall():
            print(rec)
            assert rec[-2] == "UPLOADED"
            assert rec[4] == "PARQUET"
            assert rec[5] == "PARQUET"

        for rec in run(cnx, "copy into {name}"):
            print(rec)
            assert rec[1] == "LOADED"

        run(cnx, "drop table if exists {name}")
        run(cnx, "alter session unset enable_parquet_filetype")


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["TestOrcFile.test1.orc"], indirect=["file_src"])
def test_put_copy_orc_compressed(conn_cnx, db_parameters, from_path, file_src):
    """Puts and Copies ORC compressed files."""
    file_name, _, file_stream = file_src

    def run(cnx, sql):
        sql = sql.format(name=db_parameters["name"])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        run(
            cnx,
            """
create or replace table {name} (value variant) stage_file_format=(type='orc')
""",
        )
        for rec in put(
            cnx.cursor(),
            file_name,
            f"%{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
        ).fetchall():
            print(rec)
            assert rec[-2] == "UPLOADED"
            assert rec[4] == "ORC"
            assert rec[5] == "ORC"
        for rec in run(cnx, "copy into {name}"):
            print(rec)
            assert rec[1] == "LOADED"

        run(cnx, "drop table if exists {name}")


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_copy_get(tmpdir, conn_cnx, db_parameters):
    """Copies and Gets a file."""
    name_unload = db_parameters["name"] + "_unload"
    tmp_dir = str(tmpdir.mkdir("copy_get_stage"))
    tmp_dir_user = str(tmpdir.mkdir("user_get"))

    def run(cnx, sql):
        sql = sql.format(
            name_unload=name_unload,
            tmpdir=tmp_dir,
            tmp_dir_user=tmp_dir_user,
            name=db_parameters["name"],
        )
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        run(cnx, "alter session set DISABLE_PUT_AND_GET_ON_EXTERNAL_STAGE=false")
        run(
            cnx,
            """
create or replace table {name} (
aa int,
dt date,
ts timestamp,
tsltz timestamp_ltz,
tsntz timestamp_ntz,
tstz timestamp_tz,
pct float,
ratio number(5,2))
""",
        )
        run(
            cnx,
            """
create or replace stage {name_unload}
file_format = (
format_name = 'common.public.csv'
field_delimiter = '|'
error_on_column_count_mismatch=false);
""",
        )
        current_time = datetime.datetime.utcnow()
        current_time = current_time.replace(tzinfo=pytz.timezone("America/Los_Angeles"))
        current_date = datetime.date.today()
        other_time = current_time.replace(tzinfo=pytz.timezone("Asia/Tokyo"))

        fmt = """
insert into {name}(aa, dt, tstz)
values(%(value)s,%(dt)s,%(tstz)s)
""".format(
            name=db_parameters["name"]
        )
        cnx.cursor().executemany(
            fmt,
            [
                {"value": 6543, "dt": current_date, "tstz": other_time},
                {"value": 1234, "dt": current_date, "tstz": other_time},
            ],
        )

        run(
            cnx,
            """
copy into @{name_unload}/data_
from {name}
file_format=(
format_name='common.public.csv'
compression='gzip')
max_file_size=10000000
""",
        )
        ret = run(cnx, "get @{name_unload}/ file://{tmp_dir_user}/")

        assert ret[0][2] == "DOWNLOADED", "Failed to download"
        cnt = 0
        for _, _, _ in os.walk(tmp_dir_user):
            cnt += 1
        assert cnt > 0, "No file was downloaded"

        run(cnx, "drop stage {name_unload}")
        run(cnx, "drop table if exists {name}")


@pytest.mark.flaky(reruns=3)
def test_put_copy_many_files(tmpdir, conn_cnx, db_parameters):
    """Puts and Copies many_files."""
    # generates N files
    number_of_files = 100
    number_of_lines = 1000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")

    def run(cnx, sql):
        sql = sql.format(files=files.replace("\\", "\\\\"), name=db_parameters["name"])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        run(
            cnx,
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
        run(cnx, "put 'file://{files}' @%{name}")
        run(cnx, "copy into {name}")
        rows = 0
        for rec in run(cnx, "select count(*) from {name}"):
            rows += rec[0]
        assert rows == number_of_files * number_of_lines, "Number of rows"

        run(cnx, "drop table if exists {name}")


@pytest.mark.aws
def test_put_copy_many_files_s3(tmpdir, conn_cnx, db_parameters):
    """[s3] Puts and Copies many files."""
    # generates N files
    number_of_files = 10
    number_of_lines = 1000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")

    def run(cnx, sql):
        sql = sql.format(files=files.replace("\\", "\\\\"), name=db_parameters["name"])
        return cnx.cursor().execute(sql).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        run(
            cnx,
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
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            run(cnx, "put 'file://{files}' @%{name}")
            run(cnx, "copy into {name}")

            rows = 0
            for rec in run(cnx, "select count(*) from {name}"):
                rows += rec[0]
            assert rows == number_of_files * number_of_lines, "Number of rows"
    finally:
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            run(cnx, "drop table if exists {name}")


@pytest.mark.aws
@pytest.mark.azure
@pytest.mark.flaky(reruns=3)
def test_put_copy_duplicated_files_s3(tmpdir, conn_cnx, db_parameters):
    """[s3] Puts and Copies duplicated files."""
    # generates N files
    number_of_files = 5
    number_of_lines = 100
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")

    def run(cnx, sql):
        sql = sql.format(files=files.replace("\\", "\\\\"), name=db_parameters["name"])
        return cnx.cursor().execute(sql, _raise_put_get_error=False).fetchall()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        run(
            cnx,
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
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            success_cnt = 0
            skipped_cnt = 0
            for rec in run(cnx, "put 'file://{files}' @%{name}"):
                logger.info("rec=%s", rec)
                if rec[6] == "UPLOADED":
                    success_cnt += 1
                elif rec[6] == "SKIPPED":
                    skipped_cnt += 1
            assert success_cnt == number_of_files, "uploaded files"
            assert skipped_cnt == 0, "skipped files"

            deleted_cnt = 0
            run(cnx, "rm @%{name}/file0")
            deleted_cnt += 1
            run(cnx, "rm @%{name}/file1")
            deleted_cnt += 1
            run(cnx, "rm @%{name}/file2")
            deleted_cnt += 1

            success_cnt = 0
            skipped_cnt = 0
            for rec in run(cnx, "put 'file://{files}' @%{name}"):
                logger.info("rec=%s", rec)
                if rec[6] == "UPLOADED":
                    success_cnt += 1
                elif rec[6] == "SKIPPED":
                    skipped_cnt += 1
            assert success_cnt == deleted_cnt, "uploaded files in the second time"
            assert (
                skipped_cnt == number_of_files - deleted_cnt
            ), "skipped files in the second time"

            run(cnx, "copy into {name}")
            rows = 0
            for rec in run(cnx, "select count(*) from {name}"):
                rows += rec[0]
            assert rows == number_of_files * number_of_lines, "Number of rows"
    finally:
        with conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        ) as cnx:
            run(cnx, "drop table if exists {name}")


@pytest.mark.skipolddriver
@pytest.mark.aws
@pytest.mark.azure
def test_put_collision(tmpdir, conn_cnx, db_parameters):
    """File name collision test. The data set have the same file names but contents are different."""
    number_of_files = 5
    number_of_lines = 10
    # data set 1
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines,
        number_of_files,
        compress=True,
        tmp_dir=str(tmpdir.mkdir("data1")),
    )
    files1 = os.path.join(tmp_dir, "file*")

    # data set 2
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines,
        number_of_files,
        compress=True,
        tmp_dir=str(tmpdir.mkdir("data2")),
    )
    files2 = os.path.join(tmp_dir, "file*")

    stage_name = random_string(5, "test_put_collision_")
    with conn_cnx() as cnx:
        cnx.cursor().execute("RM @~/{}".format(stage_name))
        try:
            # upload all files
            success_cnt = 0
            skipped_cnt = 0
            for rec in cnx.cursor().execute(
                "PUT 'file://{file}' @~/{stage_name}".format(
                    file=files1.replace("\\", "\\\\"), stage_name=stage_name
                )
            ):
                logger.info("rec=%s", rec)
                if rec[6] == "UPLOADED":
                    success_cnt += 1
                elif rec[6] == "SKIPPED":
                    skipped_cnt += 1
            assert success_cnt == number_of_files
            assert skipped_cnt == 0

            # will skip uploading all files
            success_cnt = 0
            skipped_cnt = 0
            for rec in cnx.cursor().execute(
                "PUT 'file://{file}' @~/{stage_name}".format(
                    file=files2.replace("\\", "\\\\"), stage_name=stage_name
                )
            ):
                logger.info("rec=%s", rec)
                if rec[6] == "UPLOADED":
                    success_cnt += 1
                elif rec[6] == "SKIPPED":
                    skipped_cnt += 1
            assert success_cnt == 0
            assert skipped_cnt == number_of_files

            # will overwrite all files
            success_cnt = 0
            skipped_cnt = 0
            for rec in cnx.cursor().execute(
                "PUT 'file://{file}' @~/{stage_name} OVERWRITE=true".format(
                    file=files2.replace("\\", "\\\\"), stage_name=stage_name
                )
            ):
                logger.info("rec=%s", rec)
                if rec[6] == "UPLOADED":
                    success_cnt += 1
                elif rec[6] == "SKIPPED":
                    skipped_cnt += 1
            assert success_cnt == number_of_files
            assert skipped_cnt == 0

        finally:
            with conn_cnx(
                user=db_parameters["user"],
                account=db_parameters["account"],
                password=db_parameters["password"],
            ) as cnx:
                cnx.cursor().execute("RM @~/{}".format(stage_name))


def _generate_huge_value_json(tmpdir, n=1, value_size=1):
    fname = str(tmpdir.join("test_put_get_huge_json"))
    f = gzip.open(fname, "wb")
    for i in range(n):
        logger.debug("adding a value in {}".format(i))
        f.write('{{"k":"{}"}}'.format(random_string(value_size)))
    f.close()
    return fname


def _huge_value_json_upload(tmpdir, conn_cnx, db_parameters):
    """(WIP) Huge json value data."""
    with conn_cnx() as cnx:
        json_table = db_parameters["name"] + "_json"
        cnx.cursor().execute(
            "create or replace table {table} (v variant)".format(table=json_table)
        )

        rows = 2
        size = 2000
        tmp_file = _generate_huge_value_json(tmpdir, n=rows, value_size=size)
        try:
            c = cnx.cursor()
            try:
                c.execute(
                    "put 'file://{tmp_file}' @%{name}".format(
                        tmp_file=tmp_file.replace("\\", "\\\\"), name=json_table
                    )
                )
                colmap = {}
                for index, item in enumerate(c.description):
                    colmap[item[0]] = index
                for rec in c:
                    source = rec[colmap["source"]]
                    logger.debug(source)
            finally:
                c.close()

            c = cnx.cursor()
            try:
                c.execute(
                    "copy into {name} on_error='skip_file' file_format=(type='json')".format(
                        name=json_table
                    )
                )
                cnt = 0
                rec = []
                for rec in c:
                    logger.debug(rec)
                    cnt += 1
                assert rec[1] == "LOAD_FAILED", "Loading huge value json should fail"
                assert cnt == 1, "Number of PUT files"
            finally:
                c.close()

            c = cnx.cursor()
            try:
                c.execute("select count(*) from {name}".format(name=json_table))
                cnt = -1
                for rec in c:
                    cnt = rec[0]
                assert cnt == 0, "Number of copied rows"
            finally:
                c.close()

            cnx.cursor().execute(
                "drop table if exists {table}".format(table=json_table)
            )
        finally:
            os.unlink(tmp_file)


@pytest.mark.aws
@pytest.mark.flaky(reruns=3)
def test_put_get_large_files_s3(tmpdir, conn_cnx, db_parameters):
    """[s3] Puts and Gets Large files."""
    number_of_files = 3
    number_of_lines = 200000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")
    output_dir = os.path.join(tmp_dir, "output_dir")
    os.makedirs(output_dir)

    class cb(SnowflakeProgressPercentage):
        def __init__(self, filename, filesize, **_):
            pass

        def __call__(self, bytes_amount):
            pass

    def run(cnx, sql):
        return (
            cnx.cursor()
            .execute(
                sql.format(
                    files=files.replace("\\", "\\\\"),
                    dir=db_parameters["name"],
                    output_dir=output_dir.replace("\\", "\\\\"),
                ),
                _put_callback_output_stream=sys.stdout,
                _get_callback_output_stream=sys.stdout,
                _get_callback=cb,
                _put_callback=cb,
            )
            .fetchall()
        )

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        try:
            run(cnx, "PUT 'file://{files}' @~/{dir}")
            # run(cnx, "PUT 'file://{files}' @~/{dir}")  # retry
            all_recs = []
            for _ in range(100):
                all_recs = run(cnx, "LIST @~/{dir}")
                if len(all_recs) == number_of_files:
                    break
                time.sleep(1)
            else:
                pytest.fail(
                    "cannot list all files. Potentially "
                    "PUT command missed uploading Files: {}".format(all_recs)
                )
            all_recs = run(cnx, "GET @~/{dir} 'file://{output_dir}'")
            assert len(all_recs) == number_of_files
            assert all([rec[2] == "DOWNLOADED" for rec in all_recs])
        finally:
            run(cnx, "RM @~/{dir}")


@pytest.mark.aws
@pytest.mark.azure
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["put_get_1.txt"], indirect=["file_src"])
def test_put_get_with_hint(tmpdir, conn_cnx, db_parameters, from_path, file_src):
    """SNOW-15153: PUTs and GETs with hint."""
    tmp_dir = str(tmpdir.mkdir("put_get_with_hint"))
    file_name, file_size, file_stream = file_src

    def run(cnx, sql, _is_put_get=None):
        sql = sql.format(
            local_dir=tmp_dir.replace("\\", "\\\\"), name=db_parameters["name"]
        )
        return cnx.cursor().execute(sql, _is_put_get=_is_put_get).fetchone()

    with conn_cnx(
        user=db_parameters["user"],
        account=db_parameters["account"],
        password=db_parameters["password"],
    ) as cnx:
        # regular PUT case
        ret = put(
            cnx.cursor(),
            file_name,
            f"~/{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
        ).fetchone()
        assert ret[0] == os.path.basename(file_name), "PUT filename"
        # clean up a file
        ret = run(cnx, "RM @~/{name}")
        assert ret[0].endswith(os.path.basename(file_name) + ".gz"), "RM filename"

        # PUT detection failure
        with pytest.raises(ProgrammingError):
            put(
                cnx.cursor(),
                file_name,
                f"~/{db_parameters['name']}",
                from_path,
                commented=True,
                file_stream=file_stream,
            )

        # PUT with hint
        ret = put(
            cnx.cursor(),
            file_name,
            f"~/{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
            _is_put_get=True,
        ).fetchone()
        assert ret[0] == os.path.basename(file_name), "PUT filename"

        # GET detection failure
        commented_get_sql = """
--- test comments
GET @~/{name} file://{local_dir}"""

        with pytest.raises(ProgrammingError):
            run(cnx, commented_get_sql)

        # GET with hint
        ret = run(cnx, commented_get_sql, _is_put_get=True)
        assert ret[0] == os.path.basename(file_name) + ".gz", "GET filename"
