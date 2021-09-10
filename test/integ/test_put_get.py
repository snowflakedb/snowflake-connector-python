#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
import filecmp
import os
import pathlib
from functools import partial
from getpass import getuser
from logging import getLogger
from os import path
from typing import TYPE_CHECKING, Callable, NamedTuple

import mock
import pytest

from ..generate_test_files import generate_k_lines_of_n_files
from ..integ_helpers import put
from ..randomize import random_string

if TYPE_CHECKING:
    from snowflake.connector import SnowflakeConnection

try:
    from ..parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

THIS_DIR = path.dirname(path.realpath(__file__))

logger = getLogger(__name__)


class _TestData(NamedTuple):
    test_data_dir: pathlib.Path
    AWS_ACCESS_KEY_ID: str
    AWS_SECRET_ACCESS_KEY: str
    stage_name: str
    warehouse_name: str
    database_name: str
    user_bucket: str
    connection: Callable[..., "SnowflakeConnection"]


@pytest.fixture()
def test_data(
    request, conn_cnx: Callable[..., "SnowflakeConnection"], sdkless: bool
) -> _TestData:
    return create_test_data(request, partial(conn_cnx, use_new_put_get=sdkless))


def create_test_data(
    request, connection: Callable[..., "SnowflakeConnection"]
) -> _TestData:
    assert "AWS_ACCESS_KEY_ID" in os.environ
    assert "AWS_SECRET_ACCESS_KEY" in os.environ

    unique_name = random_string(5, "create_test_data_")
    warehouse_name = f"{unique_name}_wh"
    database_name = f"{unique_name}_db"

    def fin():
        with connection() as cnx:
            with cnx.cursor() as cur:
                cur.execute(f"drop database {database_name}")
                cur.execute(f"drop warehouse {warehouse_name}")

    request.addfinalizer(fin)

    ret = _TestData(
        test_data_dir=pathlib.Path(__file__).absolute().parent.parent / "data",
        AWS_ACCESS_KEY_ID=f"'{os.environ['AWS_ACCESS_KEY_ID']}'",
        AWS_SECRET_ACCESS_KEY=f"'{os.environ['AWS_SECRET_ACCESS_KEY']}'",
        stage_name=f"{unique_name}_stage",
        warehouse_name=warehouse_name,
        database_name=database_name,
        user_bucket=os.getenv(
            "SF_AWS_USER_BUCKET", f"sfc-dev1-regression/{getuser()}/reg"
        ),
        connection=connection,
    )

    with connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute("use role sysadmin")
            cur.execute(
                f"""
create or replace warehouse {warehouse_name}
warehouse_size = 'small'
warehouse_type='standard'
auto_suspend=1800
"""
            )
            cur.execute(
                f"""
create or replace database {database_name}
"""
            )
            cur.execute(
                """
create or replace schema pytesting_schema
"""
            )
            cur.execute(
                """
create or replace file format VSV type = 'CSV'
field_delimiter='|' error_on_column_count_mismatch=false
"""
            )

    return ret


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_load_s3(test_data):
    with test_data.connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute(f"use warehouse {test_data.warehouse_name}")
            cur.execute(f"use schema {test_data.database_name}.pytesting_schema")
            cur.execute(
                """
create or replace table tweets(created_at timestamp,
id number, id_str string, text string, source string,
in_reply_to_status_id number, in_reply_to_status_id_str string,
in_reply_to_user_id number, in_reply_to_user_id_str string,
in_reply_to_screen_name string, user__id number, user__id_str string,
user__name string, user__screen_name string, user__location string,
user__description string, user__url string,
user__entities__description__urls string, user__protected string,
user__followers_count number, user__friends_count number,
user__listed_count number, user__created_at timestamp,
user__favourites_count number, user__utc_offset number,
user__time_zone string, user__geo_enabled string, user__verified string,
user__statuses_count number, user__lang string,
user__contributors_enabled string, user__is_translator string,
user__profile_background_color string,
user__profile_background_image_url string,
user__profile_background_image_url_https string,
user__profile_background_tile string, user__profile_image_url string,
user__profile_image_url_https string, user__profile_link_color string,
user__profile_sidebar_border_color string,
user__profile_sidebar_fill_color string, user__profile_text_color string,
user__profile_use_background_image string, user__default_profile string,
user__default_profile_image string, user__following string,
user__follow_request_sent string, user__notifications string, geo string,
coordinates string, place string, contributors string,
retweet_count number,
favorite_count number, entities__hashtags string, entities__symbols string,
entities__urls string, entities__user_mentions string, favorited string,
retweeted string, lang string)"""
            )
            cur.execute("ls @%tweets")
            assert cur.rowcount == 0, (
                "table newly created should not have any " "files in its staging area"
            )
            cur.execute(
                f"""
copy into tweets from s3://sfc-dev1-data/twitter/O1k/tweets/
credentials=(
AWS_KEY_ID={test_data.AWS_ACCESS_KEY_ID}
AWS_SECRET_KEY={test_data.AWS_SECRET_ACCESS_KEY})
file_format=(
    skip_header=1 null_if=('')
    field_optionally_enclosed_by='"'
)
"""
            )
            assert cur.rowcount == 1, "copy into tweets did not set rowcount to 1"
            results = cur.fetchall()
            assert results[0][0] == ("s3://sfc-dev1-data/twitter/O1k/tweets/1.csv.gz")
            cur.execute("drop table tweets")


@pytest.mark.aws
@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_put_local_file(test_data):
    with test_data.connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute(f"use warehouse {test_data.warehouse_name}")
            cur.execute("alter session set DISABLE_PUT_AND_GET_ON_EXTERNAL_STAGE=false")
            cur.execute(f"use schema {test_data.database_name}.pytesting_schema")
            cur.execute(
                f"""
create or replace table pytest_putget_t1 (
c1 STRING, c2 STRING, c3 STRING,
c4 STRING, c5 STRING, c6 STRING, c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (
    field_delimiter = '|'
    error_on_column_count_mismatch=false)
    stage_copy_options = (purge=false)
    stage_location = (
        url = 's3://{test_data.user_bucket}/{test_data.stage_name}'
    credentials = (
        AWS_KEY_ID={test_data.AWS_ACCESS_KEY_ID}
        AWS_SECRET_KEY={test_data.AWS_SECRET_ACCESS_KEY})
)
"""
            )
            cur.execute(
                f"""
put file://{test_data.test_data_dir}/ExecPlatform/Database/data/orders_10*.csv @%pytest_putget_t1
"""
            )
            assert cur.is_file_transfer
            cur.execute("ls @%pytest_putget_t1").fetchall()
            assert not cur.is_file_transfer
            assert cur.rowcount == 2, "ls @%pytest_putget_t1 did not return 2 rows"
            cur.execute("copy into pytest_putget_t1")
            results = cur.fetchall()
            assert len(results) == 2, "2 files were not copied"
            assert results[0][1] == "LOADED", "file 1 was not loaded after copy"
            assert results[1][1] == "LOADED", "file 2 was not loaded after copy"

            cur.execute("select count(*) from pytest_putget_t1")
            results = cur.fetchall()
            assert results[0][0] == 73, "73 rows not loaded into putest_putget_t1"
            cur.execute("rm @%pytest_putget_t1")
            results = cur.fetchall()
            assert len(results) == 2, "two files were not removed"
            cur.execute(
                "select STATUS from information_schema.load_history where table_name='PYTEST_PUTGET_T1'"
            )
            results = cur.fetchall()
            assert results[0][0] == "LOADED", "history does not show file to be loaded"
            cur.execute("drop table pytest_putget_t1")


@pytest.mark.flaky(reruns=3)
@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_put_load_from_user_stage(test_data):
    with test_data.connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute("alter session set DISABLE_PUT_AND_GET_ON_EXTERNAL_STAGE=false")
            cur.execute(f"use warehouse {test_data.warehouse_name}")
            cur.execute(f"use schema {test_data.database_name}.pytesting_schema")
            cur.execute(
                f"""
create or replace stage {test_data.stage_name}
url='s3://{test_data.user_bucket}/{test_data.stage_name}'
credentials = (
AWS_KEY_ID={test_data.AWS_ACCESS_KEY_ID}
AWS_SECRET_KEY={test_data.AWS_SECRET_ACCESS_KEY})
"""
            )
            cur.execute(
                """
create or replace table pytest_putget_t2 (c1 STRING, c2 STRING, c3 STRING,
  c4 STRING, c5 STRING, c6 STRING, c7 STRING, c8 STRING, c9 STRING)
"""
            )
            cur.execute(
                f"""
put file://{test_data.test_data_dir}/ExecPlatform/Database/data/orders_10*.csv
@{test_data.stage_name}
"""
            )
            # two files should have been put in the staging are
            results = cur.fetchall()
            assert len(results) == 2

            cur.execute("ls @%pytest_putget_t2")
            results = cur.fetchall()
            assert len(results) == 0, "no files should have been loaded yet"

            # copy
            cur.execute(
                f"""
copy into pytest_putget_t2 from @{test_data.stage_name}
file_format = (field_delimiter = '|' error_on_column_count_mismatch=false)
purge=true
"""
            )
            results = sorted(cur.fetchall())
            assert len(results) == 2, "copy failed to load two files from the stage"
            assert results[0][0] == (
                f"s3://{test_data.user_bucket}/{test_data.stage_name}/orders_100.csv.gz"
            ), "copy did not load file orders_100"

            assert results[1][0] == (
                f"s3://{test_data.user_bucket}/{test_data.stage_name}/orders_101.csv.gz"
            ), "copy did not load file orders_101"

            # should be empty (purged)
            cur.execute(f"ls @{test_data.stage_name}")
            results = cur.fetchall()
            assert len(results) == 0, "copied files not purged"
            cur.execute("drop table pytest_putget_t2")
            cur.execute(f"drop stage {test_data.stage_name}")


@pytest.mark.aws
@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_unload(test_data):
    with test_data.connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute(f"use warehouse {test_data.warehouse_name}")
            cur.execute(f"use schema {test_data.database_name}.pytesting_schema")
            cur.execute(
                f"""
create or replace stage {test_data.stage_name}
url='s3://{test_data.user_bucket}/{test_data.stage_name}/pytest_put_unload/unload/'
credentials = (
AWS_KEY_ID={test_data.AWS_ACCESS_KEY_ID}
AWS_SECRET_KEY={test_data.AWS_SECRET_ACCESS_KEY})
"""
            )

            cur.execute(
                """
CREATE OR REPLACE TABLE pytest_t3  (
c1 STRING, c2 STRING, c3 STRING, c4 STRING, c5 STRING,
c6 STRING, c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (format_name = 'vsv' field_delimiter = '|'
 error_on_column_count_mismatch=false)"""
            )
            cur.execute(
                f"alter stage {test_data.stage_name} set file_format = ( format_name = 'VSV' )"
            )

            # make sure its clean
            cur.execute(f"rm @{test_data.stage_name}")

            # put local file
            cur.execute(
                f"put file://{test_data.test_data_dir}/ExecPlatform/Database/data/orders_10*.csv @%pytest_t3"
            )

            # copy into table
            cur.execute(
                """
copy into pytest_t3
file_format = (field_delimiter = '|' error_on_column_count_mismatch=false)
purge=true"""
            )
            # unload from table
            cur.execute(
                f"""
copy into @{test_data.stage_name}/data_
from pytest_t3 file_format=(format_name='VSV' compression='gzip')
max_file_size=10000000"""
            )

            # load the data back to another table
            cur.execute(
                """
CREATE OR REPLACE TABLE pytest_t3_copy (
c1 STRING, c2 STRING, c3 STRING, c4 STRING, c5 STRING,
c6 STRING, c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (format_name = 'VSV' )"""
            )
            cur.execute(
                f"""
copy into pytest_t3_copy
from @{test_data.stage_name}/data_ return_failed_only=true
"""
            )

            # check to make sure they are equal
            cur.execute(
                """
(select * from pytest_t3 minus select * from pytest_t3_copy)
union
(select * from pytest_t3_copy minus select * from pytest_t3)
"""
            )
            assert cur.rowcount == 0, "unloaded/reloaded data were not the same"
            # clean stage
            cur.execute(f"rm @{test_data.stage_name}/data_")
            assert cur.rowcount == 1, "only one file was expected to be removed"

            # unload with deflate
            cur.execute(
                f"""
copy into @{test_data.stage_name}/data_
from pytest_t3 file_format=(format_name='VSV' compression='deflate')
max_file_size=10000000
"""
            )
            results = cur.fetchall()
            assert results[0][0] == 73, "73 rows were expected to be loaded"

            # create a table to unload data into
            cur.execute(
                """
CREATE OR REPLACE TABLE pytest_t3_copy
(c1 STRING, c2 STRING, c3 STRING, c4 STRING, c5 STRING, c6 STRING,
c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (
format_name = 'VSV'
compression='deflate')"""
            )
            results = cur.fetchall()
            assert results[0][0], (
                "Table PYTEST_T3_COPY successfully created.",
                "table not created successfully",
            )

            cur.execute(
                f"""
alter stage {test_data.stage_name} set file_format = (
format_name = 'VSV'
compression='deflate')
"""
            )

            cur.execute(
                f"""
copy into pytest_t3_copy from @{test_data.stage_name}/data_
return_failed_only=true
"""
            )
            results = cur.fetchall()
            assert results[0][2] == "LOADED", "rows were not loaded successfully"
            assert results[0][4] == 73, "not all 73 rows were loaded successfully"
            # check to make sure they are equal
            cur.execute(
                """
(select * from pytest_t3 minus select * from pytest_t3_copy)
union
(select * from pytest_t3_copy minus select * from pytest_t3)
"""
            )
            assert cur.rowcount == 0, "unloaded/reloaded data were not the same"
            cur.execute(f"rm @{test_data.stage_name}/data_")
            assert cur.rowcount == 1, "only one file was expected to be removed"

            # clean stage
            cur.execute(f"rm @{test_data.stage_name}/data_")

            cur.execute("drop table pytest_t3_copy")
            cur.execute(f"drop stage {test_data.stage_name}")
            cur.close()


@pytest.mark.aws
@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
def test_put_with_auto_compress_false(
    tmp_path: pathlib.Path, conn_cnx, from_path, sdkless
):
    """Tests PUT command with auto_compress=False."""
    tmp_dir = tmp_path / "data"
    tmp_dir.mkdir()
    test_data = tmp_dir / "data.txt"
    with test_data.open("w") as f:
        f.write("test1,test2")
        f.write("test3,test4")

    with conn_cnx(use_new_put_get=sdkless) as cnx:
        cnx.cursor().execute("RM @~/test_put_uncompress_file")
        try:
            file_stream = None if from_path else test_data.open("rb")
            with cnx.cursor() as cur:
                put(
                    cur,
                    str(test_data),
                    "~/test_put_uncompress_file",
                    from_path,
                    sql_options="auto_compress=FALSE",
                    file_stream=file_stream,
                )

            ret = cnx.cursor().execute("LS @~/test_put_uncompress_file").fetchone()
            assert "test_put_uncompress_file/data.txt" in ret[0]
            assert "data.txt.gz" not in ret[0]
        finally:
            cnx.cursor().execute("RM @~/test_put_uncompress_file")
            if file_stream:
                file_stream.close()


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
@pytest.mark.parametrize(
    "from_path", [True, pytest.param(False, marks=pytest.mark.skipolddriver)]
)
def test_put_overwrite(tmp_path: pathlib.Path, from_path, conn_cnx, sdkless):
    """Tests whether _force_put_overwrite and overwrite=true works as intended."""
    tmp_dir = tmp_path / "data"
    tmp_dir.mkdir()
    test_data = tmp_dir / "data.txt"
    with test_data.open("w") as f:
        f.write("test1,test2")
        f.write("test3,test4")

    with conn_cnx(use_new_put_get=sdkless) as cnx:
        cnx.cursor().execute("RM @~/test_put_overwrite")
        try:
            file_stream = None if from_path else open(test_data, "rb")
            with cnx.cursor() as cur:
                with mock.patch.object(
                    cur, "_init_result_and_meta", wraps=cur._init_result_and_meta
                ) as mock_result:
                    put(
                        cur,
                        str(test_data),
                        "~/test_put_overwrite",
                        from_path,
                        file_stream=file_stream,
                    )
                    assert mock_result.call_args[0][0]["rowset"][0][-2] == "UPLOADED"
                with mock.patch.object(
                    cur, "_init_result_and_meta", wraps=cur._init_result_and_meta
                ) as mock_result:
                    put(
                        cur,
                        str(test_data),
                        "~/test_put_overwrite",
                        from_path,
                        file_stream=file_stream,
                    )
                    assert mock_result.call_args[0][0]["rowset"][0][-2] == "SKIPPED"
                with mock.patch.object(
                    cur, "_init_result_and_meta", wraps=cur._init_result_and_meta
                ) as mock_result:
                    put(
                        cur,
                        str(test_data),
                        "~/test_put_overwrite",
                        from_path,
                        file_stream=file_stream,
                        sql_options="OVERWRITE = TRUE",
                    )
                    assert mock_result.call_args[0][0]["rowset"][0][-2] == "UPLOADED"

            ret = cnx.cursor().execute("LS @~/test_put_overwrite").fetchone()
            assert "test_put_overwrite/" + os.path.basename(test_data) in ret[0]
            assert test_data.name + ".gz" in ret[0]
        finally:
            if file_stream:
                file_stream.close()
            cnx.cursor().execute("RM @~/test_put_overwrite")


@pytest.mark.skipolddriver
def test_utf8_filename(tmp_path, conn_cnx, sdkless):
    test_file = tmp_path / "utf卡豆.csv"
    test_file.write_text("1,2,3\n")
    stage_name = random_string(5, "test_utf8_filename_")
    with conn_cnx(use_new_put_get=sdkless) as con:
        with con.cursor() as cur:
            cur.execute(f"create temporary stage {stage_name}")
            cur.execute(
                "PUT 'file://{}' @{}".format(
                    str(test_file).replace("\\", "/"), stage_name
                )
            ).fetchall()
            cur.execute(f"select $1, $2, $3 from  @{stage_name}")
            assert cur.fetchone() == ("1", "2", "3")


@pytest.mark.skipolddriver
def test_put_threshold(tmp_path, conn_cnx, is_public_test, sdkless):
    if is_public_test:
        pytest.xfail(
            reason="This feature hasn't been rolled out for public Snowflake deployments yet."
        )
    file_name = "test_put_get_with_aws_token.txt.gz"
    stage_name = random_string(5, "test_put_get_threshold_")
    file = tmp_path / file_name
    file.touch()
    with conn_cnx(use_new_put_get=sdkless) as cnx, cnx.cursor() as cur:
        cur.execute(f"create temporary stage {stage_name}")
        from snowflake.connector.file_transfer_agent import SnowflakeFileTransferAgent

        with mock.patch(
            "snowflake.connector.cursor.SnowflakeFileTransferAgent"
            if sdkless
            else "snowflake.connector.cursor.SnowflakeFileTransferAgentSdk",
            autospec=SnowflakeFileTransferAgent,
        ) as mock_agent:
            cur.execute(f"put file://{file} @{stage_name} threshold=156")
        assert mock_agent.call_args.kwargs.get("multipart_threshold", -1) == 156


# Snowflake on GCP does not support multipart uploads
@pytest.mark.aws
@pytest.mark.azure
def test_multipart_put(sdkless, conn_cnx, tmp_path):
    """This test does a multipart upload of a smaller file and then downloads it."""
    if not sdkless:
        pytest.skip("New test, doesn't test non-SDKless mode")
    stage_name = random_string(5, "test_multipart_put_")
    chunk_size = 6967790
    # Generate about 12 MB
    generate_k_lines_of_n_files(100_000, 1, tmp_dir=str(tmp_path))
    get_dir = tmp_path / "get_dir"
    get_dir.mkdir()
    upload_file = tmp_path / "file0"
    with conn_cnx(
        use_new_put_get=sdkless,
    ) as con:
        with con.cursor() as cur:
            cur.execute(f"create temporary stage {stage_name}")
            real_cmd_query = con.cmd_query

            def fake_cmd_query(*a, **kw):
                """Create a mock function to inject some value into the returned JSON"""
                ret = real_cmd_query(*a, **kw)
                ret["data"]["threshold"] = chunk_size
                return ret

            with mock.patch.object(con, "cmd_query", side_effect=fake_cmd_query):
                with mock.patch(
                    "snowflake.connector.constants.S3_CHUNK_SIZE", chunk_size
                ):
                    cur.execute(
                        f"put file://{upload_file} @{stage_name} AUTO_COMPRESS=FALSE"
                    )
            cur.execute(f"get @{stage_name} file://{get_dir}")
    downloaded_file = get_dir / "file0"
    assert downloaded_file.exists()
    assert filecmp.cmp(upload_file, downloaded_file)
