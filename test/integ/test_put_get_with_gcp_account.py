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
from filecmp import cmp
from logging import getLogger

import mock
import pytest

from snowflake.connector.constants import UTF8
from snowflake.connector.errors import ProgrammingError
from snowflake.connector.file_transfer_agent import (
    SnowflakeFileTransferAgent,
    SnowflakeProgressPercentage,
)

from ..generate_test_files import generate_k_lines_of_n_files
from ..integ_helpers import put
from ..randomize import random_string

# We need these for our OldDriver tests. We run most up to date tests with the oldest supported driver version
try:
    from snowflake.connector.vendored import requests  # NOQA

    vendored_request = True
except ImportError:  # pragma: no cover
    import requests

    vendored_request = False

logger = getLogger(__name__)

# Mark every test in this module as a gcp test
pytestmark = pytest.mark.gcp


@pytest.mark.parametrize("enable_gcs_downscoped", [True, False])
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
def test_put_get_with_gcp(
    tmpdir, conn_cnx, db_parameters, is_public_test, enable_gcs_downscoped, from_path
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

    with conn_cnx() as cnx:
        with cnx.cursor() as csr:
            try:
                csr.execute(
                    f"ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = {enable_gcs_downscoped}"
                )
            except ProgrammingError as e:
                if enable_gcs_downscoped:
                    # not raise error when the parameter is not available yet, using old behavior
                    raise e
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
                    )
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


@pytest.mark.parametrize("enable_gcs_downscoped", [True, False])
def test_put_copy_many_files_gcp(
    tmpdir, conn_cnx, db_parameters, is_public_test, enable_gcs_downscoped
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

    def run(csr, sql):
        sql = sql.format(files=files, name=table_name)
        return csr.execute(sql).fetchall()

    with conn_cnx() as cnx:
        with cnx.cursor() as csr:
            try:
                csr.execute(
                    f"ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = {enable_gcs_downscoped}"
                )
            except ProgrammingError as e:
                if enable_gcs_downscoped:
                    # not raise error when the parameter is not available yet, using old behavior
                    raise e
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
                statement = "put file://{files} @%{name}"
                if enable_gcs_downscoped:
                    statement += " overwrite = true"

                all_recs = run(csr, statement)
                assert all([rec[6] == "UPLOADED" for rec in all_recs])
                run(csr, "copy into {name}")

                rows = sum([rec[0] for rec in run(csr, "select count(*) from {name}")])
                assert rows == number_of_files * number_of_lines, "Number of rows"
            finally:
                run(csr, "drop table if exists {name}")


@pytest.mark.parametrize("enable_gcs_downscoped", [True, False])
def test_put_copy_duplicated_files_gcp(
    tmpdir, conn_cnx, db_parameters, is_public_test, enable_gcs_downscoped
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

    def run(csr, sql):
        sql = sql.format(files=files, name=table_name)
        return csr.execute(sql).fetchall()

    with conn_cnx() as cnx:
        with cnx.cursor() as csr:
            try:
                csr.execute(
                    f"ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = {enable_gcs_downscoped}"
                )
            except ProgrammingError as e:
                if enable_gcs_downscoped:
                    # not raise error when the parameter is not available yet, using old behavior
                    raise e
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
                put_statement = "put file://{files} @%{name}"
                if enable_gcs_downscoped:
                    put_statement += " overwrite = true"
                for rec in run(csr, put_statement):
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
                for rec in run(csr, put_statement):
                    logger.info("rec=%s", rec)
                    if rec[6] == "UPLOADED":
                        success_cnt += 1
                    elif rec[6] == "SKIPPED":
                        skipped_cnt += 1
                assert (
                    success_cnt == number_of_files
                ), "uploaded files in the second time"
                assert skipped_cnt == 0, "skipped files in the second time"

                run(csr, "copy into {name}")
                rows = 0
                for rec in run(csr, "select count(*) from {name}"):
                    rows += rec[0]
                assert rows == number_of_files * number_of_lines, "Number of rows"
            finally:
                run(csr, "drop table if exists {name}")


@pytest.mark.parametrize("enable_gcs_downscoped", [True, False])
def test_put_get_large_files_gcp(
    tmpdir, conn_cnx, db_parameters, is_public_test, enable_gcs_downscoped
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
            try:
                run(
                    cnx,
                    f"ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = {enable_gcs_downscoped}",
                )
            except ProgrammingError as e:
                if enable_gcs_downscoped:
                    # not raise error when the parameter is not available yet, using old behavior
                    raise e
            all_recs = run(cnx, "PUT file://{files} @~/{dir}")
            assert all([rec[6] == "UPLOADED" for rec in all_recs])

            for _ in range(60):
                for _ in range(100):
                    all_recs = run(cnx, "LIST @~/{dir}")
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
                    "PUT command missed uploading Files: {}".format(all_recs)
                )
            all_recs = run(cnx, "GET @~/{dir} file://{output_dir}")
            assert len(all_recs) == number_of_files
            assert all([rec[2] == "DOWNLOADED" for rec in all_recs])
        finally:
            run(cnx, "RM @~/{dir}")


def test_get_gcp_file_object_http_400_error(tmpdir, conn_cnx, db_parameters):
    fname = str(tmpdir.join("test_put_get_with_gcp_token.txt.gz"))
    original_contents = "123,test1\n456,test2\n"
    with gzip.open(fname, "wb") as f:
        f.write(original_contents.encode(UTF8))
    tmp_dir = str(tmpdir.mkdir("test_put_get_with_gcp_token"))
    table_name = random_string(5, "snow32807_")

    with conn_cnx() as cnx:
        with cnx.cursor() as csr:
            csr.execute(
                "create or replace table {} (a int, b string)".format(table_name)
            )
            try:
                from snowflake.connector.vendored.requests import get, put

                def mocked_put(*args, **kwargs):
                    if mocked_put.counter == 0:
                        mocked_put.counter += 1
                        exc = requests.exceptions.HTTPError(
                            response=requests.Response()
                        )
                        exc.response.status_code = 400
                        raise exc
                    else:
                        return put(*args, **kwargs)

                mocked_put.counter = 0

                def mocked_file_agent(*args, **kwargs):
                    agent = SnowflakeFileTransferAgent(*args, **kwargs)
                    agent._update_file_metas_with_presigned_url = mock.MagicMock(
                        wraps=agent._update_file_metas_with_presigned_url
                    )
                    mocked_file_agent.agent = agent
                    return agent

                with mock.patch(
                    "snowflake.connector.cursor.SnowflakeFileTransferAgent",
                    side_effect=mocked_file_agent,
                ):
                    with mock.patch(
                        "snowflake.connector.vendored.requests.put"
                        if vendored_request
                        else "request.put",
                        side_effect=mocked_put,
                    ):
                        csr.execute(
                            "put file://{} @%{} auto_compress=true parallel=30".format(
                                fname, table_name
                            )
                        )
                    assert (
                        mocked_file_agent.agent._update_file_metas_with_presigned_url.call_count
                        == 2
                    )
                assert csr.fetchone()[6] == "UPLOADED"
                csr.execute("copy into {} purge = true".format(table_name))
                assert csr.execute("ls @%{}".format(table_name)).fetchall() == []
                csr.execute(
                    "copy into @%{table_name} from {table_name} "
                    "file_format=(type=csv compression='gzip')".format(
                        table_name=table_name
                    )
                )

                def mocked_get(*args, **kwargs):
                    if mocked_get.counter == 0:
                        mocked_get.counter += 1
                        exc = requests.exceptions.HTTPError(
                            response=requests.Response()
                        )
                        exc.response.status_code = 400
                        raise exc
                    else:
                        return get(*args, **kwargs)

                mocked_get.counter = 0

                with mock.patch(
                    "snowflake.connector.cursor.SnowflakeFileTransferAgent",
                    side_effect=mocked_file_agent,
                ):
                    with mock.patch(
                        "snowflake.connector.vendored.requests.get"
                        if vendored_request
                        else "request.get",
                        side_effect=mocked_get,
                    ):
                        csr.execute("get @%{} file://{}".format(table_name, tmp_dir))
                    assert (
                        mocked_file_agent.agent._update_file_metas_with_presigned_url.call_count
                        == 2
                    )
                rec = csr.fetchone()
                assert rec[0].startswith("data_"), "A file downloaded by GET"
                assert rec[1] == 36, "Return right file size"
                assert rec[2] == "DOWNLOADED", "Return DOWNLOADED status"
                assert rec[3] == "", "Return no error message"
            finally:
                csr.execute("drop table {}".format(table_name))

    files = glob.glob(os.path.join(tmp_dir, "data_*"))
    with gzip.open(files[0], "rb") as fd:
        contents = fd.read().decode(UTF8)
    assert original_contents == contents, "Output is different from the original file"


@pytest.mark.parametrize("enable_gcs_downscoped", [True, False])
def test_auto_compress_off_gcp(
    tmpdir, conn_cnx, db_parameters, is_public_test, enable_gcs_downscoped
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
    with conn_cnx() as cnx:
        with cnx.cursor() as cursor:
            try:
                cursor.execute(
                    f"ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = {enable_gcs_downscoped}"
                )
            except ProgrammingError as e:
                if enable_gcs_downscoped:
                    # not raise error when the parameter is not available yet, using old behavior
                    raise e
            try:
                cursor.execute("create or replace stage {}".format(stage_name))
                cursor.execute(
                    "put file://{} @{} auto_compress=false".format(fname, stage_name)
                )
                cursor.execute("get @{} file://{}".format(stage_name, str(tmpdir)))
                downloaded_file = os.path.join(str(tmpdir), "example.json")
                assert cmp(fname, downloaded_file)
            finally:
                cursor.execute("drop stage {}".format(stage_name))


@pytest.mark.parametrize("error_code", [401, 403, 408, 429, 500, 503])
def test_get_gcp_file_object_http_recoverable_error_refresh_with_downscoped(
    tmpdir, conn_cnx, db_parameters, error_code, is_public_test
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

    with conn_cnx() as cnx:
        with cnx.cursor() as csr:
            csr.execute("ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = TRUE")
            csr.execute(
                "create or replace table {} (a int, b string)".format(table_name)
            )
            try:
                from snowflake.connector.vendored.requests import get, head, put

                def mocked_put(*args, **kwargs):
                    if mocked_put.counter == 0:
                        exc = requests.exceptions.HTTPError(
                            response=requests.Response()
                        )
                        exc.response.status_code = error_code
                        mocked_put.counter += 1
                        raise exc
                    else:
                        return put(*args, **kwargs)

                mocked_put.counter = 0

                def mocked_head(*args, **kwargs):
                    if mocked_head.counter == 0:
                        mocked_head.counter += 1
                        exc = requests.exceptions.HTTPError(
                            response=requests.Response()
                        )
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
                    "snowflake.connector.cursor.SnowflakeFileTransferAgent",
                    side_effect=mocked_file_agent,
                ):
                    with mock.patch(
                        "snowflake.connector.vendored.requests.put"
                        if vendored_request
                        else "requests.put",
                        side_effect=mocked_put,
                    ):
                        with mock.patch(
                            "snowflake.connector.vendored.requests.head"
                            if vendored_request
                            else "requests.head",
                            side_effect=mocked_head,
                        ):
                            csr.execute(
                                "put file://{} @%{} auto_compress=true parallel=30".format(
                                    fname, table_name
                                )
                            )
                    if error_code == 401:
                        assert (
                            mocked_file_agent.agent.renew_expired_client.call_count == 2
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

                def mocked_get(*args, **kwargs):
                    if mocked_get.counter == 0:
                        mocked_get.counter += 1
                        exc = requests.exceptions.HTTPError(
                            response=requests.Response()
                        )
                        exc.response.status_code = error_code
                        raise exc
                    else:
                        return get(*args, **kwargs)

                mocked_get.counter = 0

                with mock.patch(
                    "snowflake.connector.cursor.SnowflakeFileTransferAgent",
                    side_effect=mocked_file_agent,
                ):
                    with mock.patch(
                        "snowflake.connector.vendored.requests.get"
                        if vendored_request
                        else "requests.get",
                        ide_effect=mocked_get,
                    ):
                        csr.execute("get @%{} file://{}".format(table_name, tmp_dir))
                    if error_code == 401:
                        assert (
                            mocked_file_agent.agent.renew_expired_client.call_count == 1
                        )
                rec = csr.fetchone()
                assert rec[0].startswith("data_"), "A file downloaded by GET"
                assert rec[1] == 36, "Return right file size"
                assert rec[2] == "DOWNLOADED", "Return DOWNLOADED status"
                assert rec[3] == "", "Return no error message"
            finally:
                csr.execute("drop table {}".format(table_name))

    files = glob.glob(os.path.join(tmp_dir, "data_*"))
    with gzip.open(files[0], "rb") as fd:
        contents = fd.read().decode(UTF8)
    assert original_contents == contents, "Output is different from the original file"


@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
def test_put_overwrite_with_downscope(
    tmpdir, conn_cnx, db_parameters, is_public_test, from_path
):
    """Tests whether _force_put_overwrite and overwrite=true works as intended."""
    if is_public_test:
        pytest.xfail(
            "Server need to update with merged change. Expected release version: 4.41.0"
        )

    with conn_cnx() as cnx:

        tmp_dir = str(tmpdir.mkdir("data"))
        test_data = os.path.join(tmp_dir, "data.txt")
        with open(test_data, "w") as f:
            f.write("test1,test2")
            f.write("test3,test4")

        cnx.cursor().execute("RM @~/test_put_overwrite")
        try:
            file_stream = None if from_path else open(test_data, "rb")
            with cnx.cursor() as cur:
                cur.execute("ALTER SESSION SET GCS_USE_DOWNSCOPED_CREDENTIAL = TRUE")
                put(
                    cur,
                    test_data,
                    "~/test_put_overwrite",
                    from_path,
                    file_stream=file_stream,
                )
                data = cur.fetchall()
                assert data[0][6] == "UPLOADED"

                put(
                    cur,
                    test_data,
                    "~/test_put_overwrite",
                    from_path,
                    file_stream=file_stream,
                )
                data = cur.fetchall()
                assert data[0][6] == "SKIPPED"

                put(
                    cur,
                    test_data,
                    "~/test_put_overwrite",
                    from_path,
                    sql_options="OVERWRITE = TRUE",
                    file_stream=file_stream,
                )
                data = cur.fetchall()
                assert data[0][6] == "UPLOADED"

            ret = cnx.cursor().execute("LS @~/test_put_overwrite").fetchone()
            assert "test_put_overwrite/data.txt" in ret[0]
            assert "data.txt.gz" in ret[0]
        finally:
            if file_stream:
                file_stream.close()
            cnx.cursor().execute("RM @~/test_put_overwrite")
