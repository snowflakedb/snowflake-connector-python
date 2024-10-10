#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import datetime
import gzip
import os
import sys
from logging import getLogger
from typing import IO, TYPE_CHECKING

import pytest
import pytz

from snowflake.connector import ProgrammingError
from snowflake.connector.aio._cursor import DictCursor
from snowflake.connector.file_transfer_agent import (
    SnowflakeAzureProgressPercentage,
    SnowflakeProgressPercentage,
    SnowflakeS3ProgressPercentage,
)

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from test.randomize import random_string

from test.generate_test_files import generate_k_lines_of_n_files
from test.integ_helpers import put_async

if TYPE_CHECKING:
    from snowflake.connector.aio import SnowflakeConnection
    from snowflake.connector.aio._cursor import SnowflakeCursor

try:
    from ..parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
logger = getLogger(__name__)

pytestmark = pytest.mark.asyncio
CLOUD = os.getenv("cloud_provider", "dev")


@pytest.fixture()
def file_src(request) -> tuple[str, int, IO[bytes]]:
    file_name = request.param
    data_file = os.path.join(THIS_DIR, "../../data", file_name)
    file_size = os.stat(data_file).st_size
    stream = open(data_file, "rb")
    yield data_file, file_size, stream
    stream.close()


async def run(cnx, db_parameters, sql):
    sql = sql.format(name=db_parameters["name"])
    res = await cnx.cursor().execute(sql)
    return await res.fetchall()


async def run_file_operation(cnx, db_parameters, files, sql):
    sql = sql.format(files=files.replace("\\", "\\\\"), name=db_parameters["name"])
    res = await cnx.cursor().execute(sql)
    return await res.fetchall()


async def run_dict_result(cnx, db_parameters, sql):
    sql = sql.format(name=db_parameters["name"])
    res = await cnx.cursor(DictCursor).execute(sql)
    return await res.fetchall()


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["put_get_1.txt"], indirect=["file_src"])
async def test_put_copy0(aio_connection, db_parameters, from_path, file_src):
    """Puts and Copies a file."""
    file_path, _, file_stream = file_src
    kwargs = {
        "_put_callback": SnowflakeS3ProgressPercentage,
        "_get_callback": SnowflakeS3ProgressPercentage,
        "_put_azure_callback": SnowflakeAzureProgressPercentage,
        "_get_azure_callback": SnowflakeAzureProgressPercentage,
        "file_stream": file_stream,
    }

    async def run_with_cursor(
        cnx: SnowflakeConnection, sql: str
    ) -> tuple[SnowflakeCursor, list[tuple] | list[dict]]:
        sql = sql.format(name=db_parameters["name"])
        cur = cnx.cursor(DictCursor)
        res = await cur.execute(sql)
        return cur, await res.fetchall()

    await aio_connection.connect()
    cursor = aio_connection.cursor(DictCursor)
    await run(
        aio_connection,
        db_parameters,
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

    ret = await put_async(
        cursor, file_path, f"%{db_parameters['name']}", from_path, **kwargs
    )
    ret = await ret.fetchall()
    assert cursor.is_file_transfer, "PUT"
    assert len(ret) == 1, "Upload one file"
    assert ret[0]["source"] == os.path.basename(file_path), "File name"

    c, ret = await run_with_cursor(aio_connection, "copy into {name}")
    assert not c.is_file_transfer, "COPY"
    assert len(ret) == 1 and ret[0]["status"] == "LOADED", "Failed to load data"

    assert ret[0]["rows_loaded"] == 3, "Failed to load 3 rows of data"

    await run(aio_connection, db_parameters, "drop table if exists {name}")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["gzip_sample.txt.gz"], indirect=["file_src"])
async def test_put_copy_compressed(aio_connection, db_parameters, from_path, file_src):
    """Puts and Copies compressed files."""
    file_name, file_size, file_stream = file_src
    await aio_connection.connect()

    await run_dict_result(
        aio_connection, db_parameters, "create or replace table {name} (value string)"
    )
    csr = aio_connection.cursor(DictCursor)
    ret = await put_async(
        csr,
        file_name,
        f"%{db_parameters['name']}",
        from_path,
        file_stream=file_stream,
    )
    ret = await ret.fetchall()
    assert ret[0]["source"] == os.path.basename(file_name), "File name"
    assert ret[0]["source_size"] == file_size, "File size"
    assert ret[0]["status"] == "UPLOADED"

    ret = await run_dict_result(aio_connection, db_parameters, "copy into {name}")
    assert len(ret) == 1 and ret[0]["status"] == "LOADED", "Failed to load data"
    assert ret[0]["rows_loaded"] == 1, "Failed to load 1 rows of data"

    await run(aio_connection, db_parameters, "drop table if exists {name}")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["bzip2_sample.txt.bz2"], indirect=["file_src"])
@pytest.mark.skip(reason="BZ2 is not detected in this test case. Need investigation")
async def test_put_copy_bz2_compressed(
    aio_connection, db_parameters, from_path, file_src
):
    """Put and Copy bz2 compressed files."""
    file_name, _, file_stream = file_src
    await aio_connection.connect()

    await run(
        aio_connection, db_parameters, "create or replace table {name} (value string)"
    )
    res = await put_async(
        aio_connection.cursor(),
        file_name,
        f"%{db_parameters['name']}",
        from_path,
        file_stream=file_stream,
    )
    for rec in await res.fetchall():
        print(rec)
        assert rec[-2] == "UPLOADED"

    for rec in await run(aio_connection, db_parameters, "copy into {name}"):
        print(rec)
        assert rec[1] == "LOADED"

    await run(aio_connection, db_parameters, "drop table if exists {name}")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["brotli_sample.txt.br"], indirect=["file_src"])
async def test_put_copy_brotli_compressed(
    aio_connection, db_parameters, from_path, file_src
):
    """Puts and Copies brotli compressed files."""
    file_name, _, file_stream = file_src
    await aio_connection.connect()

    await run(
        aio_connection, db_parameters, "create or replace table {name} (value string)"
    )
    res = await put_async(
        aio_connection.cursor(),
        file_name,
        f"%{db_parameters['name']}",
        from_path,
        file_stream=file_stream,
    )
    for rec in await res.fetchall():
        print(rec)
        assert rec[-2] == "UPLOADED"

    for rec in await run(
        aio_connection,
        db_parameters,
        "copy into {name} file_format=(compression='BROTLI')",
    ):
        print(rec)
        assert rec[1] == "LOADED"

    await run(aio_connection, db_parameters, "drop table if exists {name}")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["zstd_sample.txt.zst"], indirect=["file_src"])
async def test_put_copy_zstd_compressed(
    aio_connection, db_parameters, from_path, file_src
):
    """Puts and Copies zstd compressed files."""
    file_name, _, file_stream = file_src
    await aio_connection.connect()

    await run(
        aio_connection, db_parameters, "create or replace table {name} (value string)"
    )
    res = await put_async(
        aio_connection.cursor(),
        file_name,
        f"%{db_parameters['name']}",
        from_path,
        file_stream=file_stream,
    )
    for rec in await res.fetchall():
        print(rec)
        assert rec[-2] == "UPLOADED"
    for rec in await run(
        aio_connection,
        db_parameters,
        "copy into {name} file_format=(compression='ZSTD')",
    ):
        print(rec)
        assert rec[1] == "LOADED"

    await run(aio_connection, db_parameters, "drop table if exists {name}")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["nation.impala.parquet"], indirect=["file_src"])
async def test_put_copy_parquet_compressed(
    aio_connection, db_parameters, from_path, file_src
):
    """Puts and Copies parquet compressed files."""
    file_name, _, file_stream = file_src
    await aio_connection.connect()

    await run(
        aio_connection,
        db_parameters,
        """
create or replace table {name}
(value variant)
stage_file_format=(type='parquet')
""",
    )
    for rec in await (
        await put_async(
            aio_connection.cursor(),
            file_name,
            f"%{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
        )
    ).fetchall():
        print(rec)
        assert rec[-2] == "UPLOADED"
        assert rec[4] == "PARQUET"
        assert rec[5] == "PARQUET"

    for rec in await run(aio_connection, db_parameters, "copy into {name}"):
        print(rec)
        assert rec[1] == "LOADED"

    await run(aio_connection, db_parameters, "drop table if exists {name}")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["TestOrcFile.test1.orc"], indirect=["file_src"])
async def test_put_copy_orc_compressed(
    aio_connection, db_parameters, from_path, file_src
):
    """Puts and Copies ORC compressed files."""
    file_name, _, file_stream = file_src
    await aio_connection.connect()
    await run(
        aio_connection,
        db_parameters,
        """
create or replace table {name} (value variant) stage_file_format=(type='orc')
""",
    )
    for rec in await (
        await put_async(
            aio_connection.cursor(),
            file_name,
            f"%{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
        )
    ).fetchall():
        print(rec)
        assert rec[-2] == "UPLOADED"
        assert rec[4] == "ORC"
        assert rec[5] == "ORC"
    for rec in await run(aio_connection, db_parameters, "copy into {name}"):
        print(rec)
        assert rec[1] == "LOADED"

    await run(aio_connection, db_parameters, "drop table if exists {name}")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
async def test_copy_get(tmpdir, aio_connection, db_parameters):
    """Copies and Gets a file."""
    name_unload = db_parameters["name"] + "_unload"
    tmp_dir = str(tmpdir.mkdir("copy_get_stage"))
    tmp_dir_user = str(tmpdir.mkdir("user_get"))
    await aio_connection.connect()

    async def run_test(cnx, sql):
        sql = sql.format(
            name_unload=name_unload,
            tmpdir=tmp_dir,
            tmp_dir_user=tmp_dir_user,
            name=db_parameters["name"],
        )
        res = await cnx.cursor().execute(sql)
        return await res.fetchall()

    await run_test(
        aio_connection, "alter session set DISABLE_PUT_AND_GET_ON_EXTERNAL_STAGE=false"
    )
    await run_test(
        aio_connection,
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
    await run_test(
        aio_connection,
        """
create or replace stage {name_unload}
file_format = (
format_name = 'common.public.csv'
field_delimiter = '|'
error_on_column_count_mismatch=false);
""",
    )
    current_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    current_time = current_time.replace(tzinfo=pytz.timezone("America/Los_Angeles"))
    current_date = datetime.date.today()
    other_time = current_time.replace(tzinfo=pytz.timezone("Asia/Tokyo"))

    fmt = """
insert into {name}(aa, dt, tstz)
values(%(value)s,%(dt)s,%(tstz)s)
""".format(
        name=db_parameters["name"]
    )
    aio_connection.cursor().executemany(
        fmt,
        [
            {"value": 6543, "dt": current_date, "tstz": other_time},
            {"value": 1234, "dt": current_date, "tstz": other_time},
        ],
    )

    await run_test(
        aio_connection,
        """
copy into @{name_unload}/data_
from {name}
file_format=(
format_name='common.public.csv'
compression='gzip')
max_file_size=10000000
""",
    )
    ret = await run_test(aio_connection, "get @{name_unload}/ file://{tmp_dir_user}/")

    assert ret[0][2] == "DOWNLOADED", "Failed to download"
    cnt = 0
    for _, _, _ in os.walk(tmp_dir_user):
        cnt += 1
    assert cnt > 0, "No file was downloaded"

    await run_test(aio_connection, "drop stage {name_unload}")
    await run_test(aio_connection, "drop table if exists {name}")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.flaky(reruns=3)
async def test_put_copy_many_files(tmpdir, aio_connection, db_parameters):
    """Puts and Copies many_files."""
    # generates N files
    number_of_files = 100
    number_of_lines = 1000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")
    await aio_connection.connect()

    await run_file_operation(
        aio_connection,
        db_parameters,
        files,
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
    await run_file_operation(
        aio_connection, db_parameters, files, "put 'file://{files}' @%{name}"
    )
    await run_file_operation(aio_connection, db_parameters, files, "copy into {name}")
    rows = 0
    for rec in await run_file_operation(
        aio_connection, db_parameters, files, "select count(*) from {name}"
    ):
        rows += rec[0]
    assert rows == number_of_files * number_of_lines, "Number of rows"

    await run_file_operation(
        aio_connection, db_parameters, files, "drop table if exists {name}"
    )


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.aws
async def test_put_copy_many_files_s3(tmpdir, aio_connection, db_parameters):
    """[s3] Puts and Copies many files."""
    # generates N files
    number_of_files = 10
    number_of_lines = 1000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")
    await aio_connection.connect()

    await run_file_operation(
        aio_connection,
        db_parameters,
        files,
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
        await run_file_operation(
            aio_connection, db_parameters, files, "put 'file://{files}' @%{name}"
        )
        await run_file_operation(
            aio_connection, db_parameters, files, "copy into {name}"
        )

        rows = 0
        for rec in await run_file_operation(
            aio_connection, db_parameters, files, "select count(*) from {name}"
        ):
            rows += rec[0]
        assert rows == number_of_files * number_of_lines, "Number of rows"
    finally:
        await run_file_operation(
            aio_connection, db_parameters, files, "drop table if exists {name}"
        )


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.aws
@pytest.mark.azure
@pytest.mark.flaky(reruns=3)
async def test_put_copy_duplicated_files_s3(tmpdir, aio_connection, db_parameters):
    """[s3] Puts and Copies duplicated files."""
    # generates N files
    number_of_files = 5
    number_of_lines = 100
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")
    await aio_connection.connect()

    await run_file_operation(
        aio_connection,
        db_parameters,
        files,
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
        for rec in await run_file_operation(
            aio_connection, db_parameters, files, "put 'file://{files}' @%{name}"
        ):
            logger.info("rec=%s", rec)
            if rec[6] == "UPLOADED":
                success_cnt += 1
            elif rec[6] == "SKIPPED":
                skipped_cnt += 1
        assert success_cnt == number_of_files, "uploaded files"
        assert skipped_cnt == 0, "skipped files"

        deleted_cnt = 0
        await run_file_operation(
            aio_connection, db_parameters, files, "rm @%{name}/file0"
        )
        deleted_cnt += 1
        await run_file_operation(
            aio_connection, db_parameters, files, "rm @%{name}/file1"
        )
        deleted_cnt += 1
        await run_file_operation(
            aio_connection, db_parameters, files, "rm @%{name}/file2"
        )
        deleted_cnt += 1

        success_cnt = 0
        skipped_cnt = 0
        for rec in await run_file_operation(
            aio_connection, db_parameters, files, "put 'file://{files}' @%{name}"
        ):
            logger.info("rec=%s", rec)
            if rec[6] == "UPLOADED":
                success_cnt += 1
            elif rec[6] == "SKIPPED":
                skipped_cnt += 1
        assert success_cnt == deleted_cnt, "uploaded files in the second time"
        assert (
            skipped_cnt == number_of_files - deleted_cnt
        ), "skipped files in the second time"

        await run_file_operation(
            aio_connection, db_parameters, files, "copy into {name}"
        )
        rows = 0
        for rec in await run_file_operation(
            aio_connection, db_parameters, files, "select count(*) from {name}"
        ):
            rows += rec[0]
        assert rows == number_of_files * number_of_lines, "Number of rows"
    finally:
        await run_file_operation(
            aio_connection, db_parameters, files, "drop table if exists {name}"
        )


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.skipolddriver
@pytest.mark.aws
@pytest.mark.azure
async def test_put_collision(tmpdir, aio_connection):
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
    await aio_connection.connect()
    cursor = aio_connection.cursor()
    # data set 2
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines,
        number_of_files,
        compress=True,
        tmp_dir=str(tmpdir.mkdir("data2")),
    )
    files2 = os.path.join(tmp_dir, "file*")

    stage_name = random_string(5, "test_put_collision_")
    await cursor.execute(f"RM @~/{stage_name}")
    try:
        # upload all files
        success_cnt = 0
        skipped_cnt = 0
        for rec in await (
            await cursor.execute(
                "PUT 'file://{file}' @~/{stage_name}".format(
                    file=files1.replace("\\", "\\\\"), stage_name=stage_name
                )
            )
        ).fetchall():

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
        for rec in await (
            await cursor.execute(
                "PUT 'file://{file}' @~/{stage_name}".format(
                    file=files2.replace("\\", "\\\\"), stage_name=stage_name
                )
            )
        ).fetchall():
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
        for rec in await (
            await cursor.execute(
                "PUT 'file://{file}' @~/{stage_name} OVERWRITE=true".format(
                    file=files2.replace("\\", "\\\\"), stage_name=stage_name
                )
            )
        ).fetchall():
            logger.info("rec=%s", rec)
            if rec[6] == "UPLOADED":
                success_cnt += 1
            elif rec[6] == "SKIPPED":
                skipped_cnt += 1
        assert success_cnt == number_of_files
        assert skipped_cnt == 0

    finally:
        await cursor.execute(f"RM @~/{stage_name}")


def _generate_huge_value_json(tmpdir, n=1, value_size=1):
    fname = str(tmpdir.join("test_put_get_huge_json"))
    f = gzip.open(fname, "wb")
    for i in range(n):
        logger.debug(f"adding a value in {i}")
        f.write(f'{{"k":"{random_string(value_size)}"}}')
    f.close()
    return fname


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.aws
async def test_put_get_large_files_s3(tmpdir, aio_connection, db_parameters):
    """[s3] Puts and Gets Large files."""
    number_of_files = 3
    number_of_lines = 200000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )

    files = os.path.join(tmp_dir, "file*")
    output_dir = os.path.join(tmp_dir, "output_dir")
    os.makedirs(output_dir)
    await aio_connection.connect()

    class cb(SnowflakeProgressPercentage):
        def __init__(self, filename, filesize, **_):
            pass

        def __call__(self, bytes_amount):
            pass

    async def run_test(cnx, sql):
        return await (
            await cnx.cursor().execute(
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
        ).fetchall()

    try:
        await run_test(aio_connection, "PUT 'file://{files}' @~/{dir}")
        # run(cnx, "PUT 'file://{files}' @~/{dir}")  # retry
        all_recs = []
        for _ in range(100):
            all_recs = await run_test(aio_connection, "LIST @~/{dir}")
            if len(all_recs) == number_of_files:
                break
            await asyncio.sleep(1)
        else:
            pytest.fail(
                "cannot list all files. Potentially "
                "PUT command missed uploading Files: {}".format(all_recs)
            )
        all_recs = await run_test(aio_connection, "GET @~/{dir} 'file://{output_dir}'")
        assert len(all_recs) == number_of_files
        assert all([rec[2] == "DOWNLOADED" for rec in all_recs])
    finally:
        await run_test(aio_connection, "RM @~/{dir}")


@pytest.mark.skipif(CLOUD not in ["aws", "dev"], reason="only test in aws now")
@pytest.mark.aws
@pytest.mark.azure
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
@pytest.mark.parametrize("file_src", ["put_get_1.txt"], indirect=["file_src"])
async def test_put_get_with_hint(
    tmpdir, aio_connection, db_parameters, from_path, file_src
):
    """SNOW-15153: PUTs and GETs with hint."""
    tmp_dir = str(tmpdir.mkdir("put_get_with_hint"))
    file_name, file_size, file_stream = file_src
    await aio_connection.connect()

    async def run_test(cnx, sql, _is_put_get=None):
        sql = sql.format(
            local_dir=tmp_dir.replace("\\", "\\\\"), name=db_parameters["name"]
        )
        res = await cnx.cursor().execute(sql, _is_put_get=_is_put_get)
        return await res.fetchone()

    # regular PUT case
    ret = await (
        await put_async(
            aio_connection.cursor(),
            file_name,
            f"~/{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
        )
    ).fetchone()
    assert ret[0] == os.path.basename(file_name), "PUT filename"
    # clean up a file
    ret = await run_test(aio_connection, "RM @~/{name}")
    assert ret[0].endswith(os.path.basename(file_name) + ".gz"), "RM filename"

    # PUT detection failure
    with pytest.raises(ProgrammingError):
        await put_async(
            aio_connection.cursor(),
            file_name,
            f"~/{db_parameters['name']}",
            from_path,
            commented=True,
            file_stream=file_stream,
        )

    # PUT with hint
    ret = await (
        await put_async(
            aio_connection.cursor(),
            file_name,
            f"~/{db_parameters['name']}",
            from_path,
            file_stream=file_stream,
            _is_put_get=True,
        )
    ).fetchone()
    assert ret[0] == os.path.basename(file_name), "PUT filename"

    # GET detection failure
    commented_get_sql = """
--- test comments
GET @~/{name} file://{local_dir}"""

    with pytest.raises(ProgrammingError):
        await run_test(aio_connection, commented_get_sql)

    # GET with hint
    ret = await run_test(aio_connection, commented_get_sql, _is_put_get=True)
    assert ret[0] == os.path.basename(file_name) + ".gz", "GET filename"
