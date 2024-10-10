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
from filecmp import cmp
from logging import getLogger
from unittest import mock

import aiohttp.web_exceptions
import pytest

from snowflake.connector.aio._file_transfer_agent import SnowflakeFileTransferAgent
from snowflake.connector.aio._gcs_storage_client import SnowflakeGCSRestClient
from snowflake.connector.constants import UTF8
from snowflake.connector.errors import ProgrammingError
from snowflake.connector.file_transfer_agent import SnowflakeProgressPercentage

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from test.randomize import random_string

from test.generate_test_files import generate_k_lines_of_n_files
from test.integ_helpers import put_async

# We need these for our OldDriver tests. We run most up to date tests with the oldest supported driver version
try:
    from snowflake.connector.vendored import requests

    vendored_request = True
except ImportError:  # pragma: no cover
    import requests

    vendored_request = False

logger = getLogger(__name__)

# Mark every test in this module as a gcp test
pytestmark = [pytest.mark.asyncio, pytest.mark.gcp]


@pytest.mark.parametrize("enable_gcs_downscoped", [True])
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
async def test_put_get_with_gcp(
    tmpdir,
    aio_connection,
    is_public_test,
    enable_gcs_downscoped,
    from_path,
):
    """[gcp] Puts and Gets a small text using gcp."""
    if enable_gcs_downscoped and is_public_test:
        pytest.xfail(
            "Server need to update with merged change. Expected release version: 4.41.0"
        )
    # create a data file
    fname = str(tmpdir.join("test_put_get_with_gcp_token.txt.gz"))
    original_contents = "123,test1\n456,test2\n"
    with gzip.open(fname, "wb") as f:
        f.write(original_contents.encode(UTF8))
    tmp_dir = str(tmpdir.mkdir("test_put_get_with_gcp_token"))
    table_name = random_string(5, "snow32806_")

    await aio_connection.connect()
    csr = aio_connection.cursor()
    try:
        await csr.execute(
            f"ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = {enable_gcs_downscoped}"
        )
    except ProgrammingError as e:
        if enable_gcs_downscoped:
            # not raise error when the parameter is not available yet, using old behavior
            raise e
    await csr.execute(f"create or replace table {table_name} (a int, b string)")
    try:
        file_stream = None if from_path else open(fname, "rb")
        await put_async(
            csr,
            fname,
            f"%{table_name}",
            from_path,
            sql_options=" auto_compress=true parallel=30",
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
        await csr.execute(f"get @%{table_name} file://{tmp_dir}")
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


@pytest.mark.parametrize("enable_gcs_downscoped", [True])
async def test_put_copy_many_files_gcp(
    tmpdir,
    aio_connection,
    is_public_test,
    enable_gcs_downscoped,
):
    """[gcp] Puts and Copies many files."""
    if enable_gcs_downscoped and is_public_test:
        pytest.xfail(
            "Server need to update with merged change. Expected release version: 4.41.0"
        )
    # generates N files
    number_of_files = 10
    number_of_lines = 1000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )
    table_name = random_string(5, "test_put_copy_many_files_gcp_")

    files = os.path.join(tmp_dir, "file*")

    async def run(csr, sql):
        sql = sql.format(files=files, name=table_name)
        return await (await csr.execute(sql)).fetchall()

    await aio_connection.connect()
    csr = aio_connection.cursor()
    try:
        await csr.execute(
            f"ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = {enable_gcs_downscoped}"
        )
    except ProgrammingError as e:
        if enable_gcs_downscoped:
            # not raise error when the parameter is not available yet, using old behavior
            raise e
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
        statement = "put file://{files} @%{name}"
        if enable_gcs_downscoped:
            statement += " overwrite = true"

        all_recs = await run(csr, statement)
        assert all([rec[6] == "UPLOADED" for rec in all_recs])
        await run(csr, "copy into {name}")

        rows = sum(rec[0] for rec in await run(csr, "select count(*) from {name}"))
        assert rows == number_of_files * number_of_lines, "Number of rows"
    finally:
        await run(csr, "drop table if exists {name}")


@pytest.mark.parametrize("enable_gcs_downscoped", [True])
async def test_put_copy_duplicated_files_gcp(
    tmpdir,
    aio_connection,
    is_public_test,
    enable_gcs_downscoped,
):
    """[gcp] Puts and Copies duplicated files."""
    if enable_gcs_downscoped and is_public_test:
        pytest.xfail(
            "Server need to update with merged change. Expected release version: 4.41.0"
        )
    # generates N files
    number_of_files = 5
    number_of_lines = 100
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )
    table_name = random_string(5, "test_put_copy_duplicated_files_gcp_")

    files = os.path.join(tmp_dir, "file*")

    async def run(csr, sql):
        sql = sql.format(files=files, name=table_name)
        return await (await csr.execute(sql)).fetchall()

    await aio_connection.connect()
    csr = aio_connection.cursor()
    try:
        await csr.execute(
            f"ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = {enable_gcs_downscoped}"
        )
    except ProgrammingError as e:
        if enable_gcs_downscoped:
            # not raise error when the parameter is not available yet, using old behavior
            raise e
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
        put_statement = "put file://{files} @%{name}"
        if enable_gcs_downscoped:
            put_statement += " overwrite = true"
        for rec in await run(csr, put_statement):
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
        for rec in await run(csr, put_statement):
            logger.info("rec=%s", rec)
            if rec[6] == "UPLOADED":
                success_cnt += 1
            elif rec[6] == "SKIPPED":
                skipped_cnt += 1
        assert success_cnt == number_of_files, "uploaded files in the second time"
        assert skipped_cnt == 0, "skipped files in the second time"

        await run(csr, "copy into {name}")
        rows = 0
        for rec in await run(csr, "select count(*) from {name}"):
            rows += rec[0]
        assert rows == number_of_files * number_of_lines, "Number of rows"
    finally:
        await run(csr, "drop table if exists {name}")


@pytest.mark.parametrize("enable_gcs_downscoped", [True])
async def test_put_get_large_files_gcp(
    tmpdir,
    aio_connection,
    is_public_test,
    enable_gcs_downscoped,
):
    """[gcp] Puts and Gets Large files."""
    if enable_gcs_downscoped and is_public_test:
        pytest.xfail(
            "Server need to update with merged change. Expected release version: 4.41.0"
        )
    number_of_files = 3
    number_of_lines = 200000
    tmp_dir = generate_k_lines_of_n_files(
        number_of_lines, number_of_files, tmp_dir=str(tmpdir.mkdir("data"))
    )
    folder_name = random_string(5, "test_put_get_large_files_gcp_")

    files = os.path.join(tmp_dir, "file*")
    output_dir = os.path.join(tmp_dir, "output_dir")
    os.makedirs(output_dir)

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
        try:
            await run(
                aio_connection,
                f"ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = {enable_gcs_downscoped}",
            )
        except ProgrammingError as e:
            if enable_gcs_downscoped:
                # not raise error when the parameter is not available yet, using old behavior
                raise e
        all_recs = await run(aio_connection, "PUT file://{files} @~/{dir}")
        assert all([rec[6] == "UPLOADED" for rec in all_recs])

        for _ in range(60):
            for _ in range(100):
                all_recs = await run(aio_connection, "LIST @~/{dir}")
                if len(all_recs) == number_of_files:
                    break
                # you may not get the files right after PUT command
                # due to the nature of gcs blob, which synchronizes
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
                f"PUT command missed uploading Files: {all_recs}"
            )
        all_recs = await run(aio_connection, "GET @~/{dir} file://{output_dir}")
        assert len(all_recs) == number_of_files
        assert all([rec[2] == "DOWNLOADED" for rec in all_recs])
    finally:
        await run(aio_connection, "RM @~/{dir}")


@pytest.mark.skip
async def test_get_gcp_file_object_http_400_error(tmpdir, aio_connection):
    pytest.skip("This test needs to be totally rewritten for sdkless mode")
    fname = str(tmpdir.join("test_put_get_with_gcp_token.txt.gz"))
    original_contents = "123,test1\n456,test2\n"
    with gzip.open(fname, "wb") as f:
        f.write(original_contents.encode(UTF8))
    tmp_dir = str(tmpdir.mkdir("test_put_get_with_gcp_token"))
    table_name = random_string(5, "snow32807_")

    await aio_connection.connect()
    csr = aio_connection.cursor()
    csr.execute(f"create or replace table {table_name} (a int, b string)")
    try:
        from snowflake.connector.vendored.requests import get, put

        def mocked_put(*args, **kwargs):
            if mocked_put.counter == 0:
                mocked_put.counter += 1
                aiohttp.web_exceptions.HTTPError
                exc = requests.exceptions.HTTPError(response=requests.Response())
                exc.response.status_code = 400
                raise exc
            else:
                return put(*args, **kwargs)

        mocked_put.counter = 0

        def mocked_file_agent(*args, **kwargs):
            agent = SnowflakeGCSRestClient(*args, **kwargs)
            agent._update_presigned_url = mock.MagicMock(
                wraps=agent._update_presigned_url
            )
            mocked_file_agent.agent = agent
            return agent

        with mock.patch(
            "snowflake.connector.file_transfer_agent.SnowflakeGCSRestClient",
            side_effect=mocked_file_agent,
        ):
            with mock.patch(
                (
                    "snowflake.connector.vendored.requests.put"
                    if vendored_request
                    else "request.put"
                ),
                side_effect=mocked_put,
            ):
                await csr.execute(
                    f"put file://{fname} @%{table_name} auto_compress=true parallel=30"
                )
        assert (await csr.fetchone())[6] == "UPLOADED"
        await csr.execute(f"copy into {table_name} purge = true")
        assert await (await csr.execute(f"ls @%{table_name}")).fetchall() == []
        await csr.execute(
            f"copy into @%{table_name} from {table_name} "
            "file_format=(type=csv compression='gzip')"
        )

        def mocked_get(*args, **kwargs):
            if mocked_get.counter == 0:
                mocked_get.counter += 1
                exc = requests.exceptions.HTTPError(response=requests.Response())
                exc.response.status_code = 400
                raise exc
            else:
                return get(*args, **kwargs)

        mocked_get.counter = 0

        with mock.patch(
            "snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent",
            side_effect=mocked_file_agent,
        ):
            with mock.patch(
                (
                    "snowflake.connector.vendored.requests.get"
                    if vendored_request
                    else "request.get"
                ),
                side_effect=mocked_get,
            ):
                csr.execute(f"get @%{table_name} file://{tmp_dir}")
            assert (
                mocked_file_agent.agent._update_file_metas_with_presigned_url.call_count
                == 2
            )
        rec = await csr.fetchone()
        assert rec[0].startswith("data_"), "A file downloaded by GET"
        assert rec[1] == 36, "Return right file size"
        assert rec[2] == "DOWNLOADED", "Return DOWNLOADED status"
        assert rec[3] == "", "Return no error message"
    finally:
        await csr.execute(f"drop table {table_name}")

    files = glob.glob(os.path.join(tmp_dir, "data_*"))
    with gzip.open(files[0], "rb") as fd:
        contents = fd.read().decode(UTF8)
    assert original_contents == contents, "Output is different from the original file"


@pytest.mark.parametrize("enable_gcs_downscoped", [True])
async def test_auto_compress_off_gcp(
    tmpdir,
    aio_connection,
    is_public_test,
    enable_gcs_downscoped,
):
    """[gcp] Puts and Gets a small text using gcp with no auto compression."""
    if enable_gcs_downscoped and is_public_test:
        pytest.xfail(
            "Server need to update with merged change. Expected release version: 4.41.0"
        )
    fname = str(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "../data", "example.json"
        )
    )
    stage_name = random_string(5, "teststage_")
    await aio_connection.connect()
    cursor = aio_connection.cursor()
    try:
        await cursor.execute(
            f"ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = {enable_gcs_downscoped}"
        )
    except ProgrammingError as e:
        if enable_gcs_downscoped:
            # not raise error when the parameter is not available yet, using old behavior
            raise e
    try:
        await cursor.execute(f"create or replace stage {stage_name}")
        await cursor.execute(f"put file://{fname} @{stage_name} auto_compress=false")
        await cursor.execute(f"get @{stage_name} file://{tmpdir}")
        downloaded_file = os.path.join(str(tmpdir), "example.json")
        assert cmp(fname, downloaded_file)
    finally:
        await cursor.execute(f"drop stage {stage_name}")


# TODO
@pytest.mark.skip
@pytest.mark.parametrize("error_code", [401, 403, 408, 429, 500, 503])
async def test_get_gcp_file_object_http_recoverable_error_refresh_with_downscoped(
    tmpdir,
    aio_connection,
    error_code,
    is_public_test,
):
    if is_public_test:
        pytest.xfail(
            "Server need to update with merged change. Expected release version: 4.41.0"
        )
    fname = str(tmpdir.join("test_put_get_with_gcp_token.txt.gz"))
    original_contents = "123,test1\n456,test2\n"
    with gzip.open(fname, "wb") as f:
        f.write(original_contents.encode(UTF8))
    tmp_dir = str(tmpdir.mkdir("test_put_get_with_gcp_token"))
    table_name = random_string(5, "snow32807_")

    await aio_connection.connect()
    csr = aio_connection.cursor()
    await csr.execute("ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = TRUE")
    await csr.execute(f"create or replace table {table_name} (a int, b string)")
    try:
        from snowflake.connector.vendored.requests import get, head, put

        def mocked_put(*args, **kwargs):
            if mocked_put.counter == 0:
                exc = requests.exceptions.HTTPError(response=requests.Response())
                exc.response.status_code = error_code
                mocked_put.counter += 1
                raise exc
            else:
                return put(*args, **kwargs)

        mocked_put.counter = 0

        def mocked_head(*args, **kwargs):
            if mocked_head.counter == 0:
                mocked_head.counter += 1
                exc = requests.exceptions.HTTPError(response=requests.Response())
                exc.response.status_code = error_code
                raise exc
            else:
                return head(*args, **kwargs)

        mocked_head.counter = 0

        def mocked_file_agent(*args, **kwargs):
            agent = SnowflakeFileTransferAgent(*args, **kwargs)
            agent.renew_expired_client = mock.MagicMock(
                wraps=agent.renew_expired_client
            )
            mocked_file_agent.agent = agent
            return agent

        with mock.patch(
            "snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent",
            side_effect=mocked_file_agent,
        ):
            with mock.patch(
                (
                    "snowflake.connector.vendored.requests.put"
                    if vendored_request
                    else "requests.put"
                ),
                side_effect=mocked_put,
            ):
                with mock.patch(
                    (
                        "snowflake.connector.vendored.requests.head"
                        if vendored_request
                        else "requests.head"
                    ),
                    side_effect=mocked_head,
                ):
                    await csr.execute(
                        f"put file://{fname} @%{table_name} auto_compress=true parallel=30"
                    )
            if error_code == 401:
                assert mocked_file_agent.agent.renew_expired_client.call_count == 2
        assert (await csr.fetchone())[6] == "UPLOADED"
        await csr.execute(f"copy into {table_name}")
        await csr.execute(f"rm @%{table_name}")
        assert await (await csr.execute(f"ls @%{table_name}")).fetchall() == []
        await csr.execute(
            f"copy into @%{table_name} from {table_name} "
            "file_format=(type=csv compression='gzip')"
        )

        def mocked_get(*args, **kwargs):
            if mocked_get.counter == 0:
                mocked_get.counter += 1
                exc = requests.exceptions.HTTPError(response=requests.Response())
                exc.response.status_code = error_code
                raise exc
            else:
                return get(*args, **kwargs)

        mocked_get.counter = 0

        with mock.patch(
            "snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent",
            side_effect=mocked_file_agent,
        ):
            with mock.patch(
                (
                    "snowflake.connector.vendored.requests.get"
                    if vendored_request
                    else "requests.get"
                ),
                ide_effect=mocked_get,
            ):
                await csr.execute(f"get @%{table_name} file://{tmp_dir}")
            if error_code == 401:
                assert mocked_file_agent.agent.renew_expired_client.call_count == 1
        rec = await csr.fetchone()
        assert rec[0].startswith("data_"), "A file downloaded by GET"
        assert rec[1] == 36, "Return right file size"
        assert rec[2] == "DOWNLOADED", "Return DOWNLOADED status"
        assert rec[3] == "", "Return no error message"
    finally:
        await csr.execute(f"drop table {table_name}")

    files = glob.glob(os.path.join(tmp_dir, "data_*"))
    with gzip.open(files[0], "rb") as fd:
        contents = fd.read().decode(UTF8)
    assert original_contents == contents, "Output is different from the original file"


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
async def test_put_overwrite_with_downscope(
    tmpdir,
    aio_connection,
    is_public_test,
    from_path,
):
    """Tests whether _force_put_overwrite and overwrite=true works as intended."""
    if is_public_test:
        pytest.xfail(
            "Server need to update with merged change. Expected release version: 4.41.0"
        )

    await aio_connection.connect()
    csr = aio_connection.cursor()
    tmp_dir = str(tmpdir.mkdir("data"))
    test_data = os.path.join(tmp_dir, "data.txt")
    with open(test_data, "w") as f:
        f.write("test1,test2")
        f.write("test3,test4")

    await csr.execute("RM @~/test_put_overwrite")
    try:
        file_stream = None if from_path else open(test_data, "rb")
        await csr.execute("ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = TRUE")
        await put_async(
            csr,
            test_data,
            "~/test_put_overwrite",
            from_path,
            file_stream=file_stream,
        )
        data = await csr.fetchall()
        assert data[0][6] == "UPLOADED"

        await put_async(
            csr,
            test_data,
            "~/test_put_overwrite",
            from_path,
            file_stream=file_stream,
        )
        data = await csr.fetchall()
        assert data[0][6] == "SKIPPED"

        await put_async(
            csr,
            test_data,
            "~/test_put_overwrite",
            from_path,
            sql_options="OVERWRITE = TRUE",
            file_stream=file_stream,
        )
        data = await csr.fetchall()
        assert data[0][6] == "UPLOADED"

        ret = await (await csr.execute("LS @~/test_put_overwrite")).fetchone()
        assert "test_put_overwrite/data.txt" in ret[0]
        assert "data.txt.gz" in ret[0]
    finally:
        if file_stream:
            file_stream.close()
        await csr.execute("RM @~/test_put_overwrite")
