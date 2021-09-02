#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import os
import pathlib
from getpass import getuser
from logging import getLogger
from os import path

import pytest

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

THIS_DIR = path.dirname(path.realpath(__file__))

logger = getLogger(__name__)


@pytest.fixture()
def test_data(request, conn_cnx, db_parameters):
    def connection():
        """Abstracting away connection creation."""
        return conn_cnx()

    return create_test_data(request, db_parameters, connection)


@pytest.fixture()
def s3_test_data(request, conn_cnx, db_parameters):
    def connection():
        """Abstracting away connection creation."""
        return conn_cnx(
            user=db_parameters["user"],
            account=db_parameters["account"],
            password=db_parameters["password"],
        )

    return create_test_data(request, db_parameters, connection)


def create_test_data(request, db_parameters, connection):
    assert "AWS_ACCESS_KEY_ID" in os.environ, "AWS_ACCESS_KEY_ID is missing"
    assert "AWS_SECRET_ACCESS_KEY" in os.environ, "AWS_SECRET_ACCESS_KEY is missing"

    unique_name = db_parameters["name"]
    database_name = "{}_db".format(unique_name)
    warehouse_name = "{}_wh".format(unique_name)

    def fin():
        with connection() as cnx:
            with cnx.cursor() as cur:
                cur.execute("drop database {}".format(database_name))
                cur.execute("drop warehouse {}".format(warehouse_name))

    request.addfinalizer(fin)

    class TestData(object):
        def __init__(self):
            self.test_data_dir = (pathlib.Path(__file__).parent / "data").absolute()
            self.AWS_ACCESS_KEY_ID = "'{}'".format(os.environ["AWS_ACCESS_KEY_ID"])
            self.AWS_SECRET_ACCESS_KEY = "'{}'".format(
                os.environ["AWS_SECRET_ACCESS_KEY"]
            )
            self.stage_name = "{}_stage".format(unique_name)
            self.warehouse_name = warehouse_name
            self.database_name = database_name
            self.connection = connection
            self.user_bucket = os.getenv(
                "SF_AWS_USER_BUCKET", "sfc-dev1-regression/{}/reg".format(getuser())
            )

    ret = TestData()

    with connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute("use role sysadmin")
            cur.execute(
                """
create or replace warehouse {}
warehouse_size = 'small' warehouse_type='standard'
auto_suspend=1800
""".format(
                    warehouse_name
                )
            )
            cur.execute(
                """
create or replace database {}
""".format(
                    database_name
                )
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
            cur.execute("use warehouse {}".format(test_data.warehouse_name))
            cur.execute(
                "use schema {}.pytesting_schema".format(test_data.database_name)
            )
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
coordinates string, place string, contributors string, retweet_count number,
favorite_count number, entities__hashtags string, entities__symbols string,
entities__urls string, entities__user_mentions string, favorited string,
retweeted string, lang string)
"""
            )
            cur.execute("ls @%tweets")
            assert cur.rowcount == 0, (
                "table newly created should not have any files in its " "staging area"
            )
            cur.execute(
                """
copy into tweets from s3://sfc-dev1-data/twitter/O1k/tweets/
credentials=(AWS_KEY_ID={aws_access_key_id}
AWS_SECRET_KEY={aws_secret_access_key})
file_format=(skip_header=1 null_if=('') field_optionally_enclosed_by='"')
""".format(
                    aws_access_key_id=test_data.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=test_data.AWS_SECRET_ACCESS_KEY,
                )
            )
            assert cur.rowcount == 1, "copy into tweets did not set rowcount to 1"
            results = cur.fetchall()
            assert (
                results[0][0] == "s3://sfc-dev1-data/twitter/O1k/tweets/1.csv.gz"
            ), "ls @%tweets failed"
            cur.execute("drop table tweets")


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_put_local_file(test_data):
    with test_data.connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute("alter session set DISABLE_PUT_AND_GET_ON_EXTERNAL_STAGE=false")
            cur.execute("use warehouse {}".format(test_data.warehouse_name))
            cur.execute(
                """use schema {}.pytesting_schema""".format(test_data.database_name)
            )
            cur.execute(
                """
create or replace table pytest_putget_t1 (c1 STRING, c2 STRING, c3 STRING,
c4 STRING, c5 STRING, c6 STRING, c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (field_delimiter = '|' error_on_column_count_mismatch=false)
stage_copy_options = (purge=false)
stage_location = (url = 's3://sfc-dev1-regression/jenkins/{stage_name}'
credentials = (
AWS_KEY_ID={aws_access_key_id}
AWS_SECRET_KEY={aws_secret_access_key}))
""".format(
                    aws_access_key_id=test_data.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=test_data.AWS_SECRET_ACCESS_KEY,
                    stage_name=test_data.stage_name,
                )
            )
            cur.execute(
                """put file://{}/ExecPlatform/Database/data/orders_10*.csv @%pytest_putget_t1""".format(
                    str(test_data.test_data_dir)
                )
            )
            cur.execute("ls @%pytest_putget_t1")
            _ = cur.fetchall()
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


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_put_load_from_user_stage(test_data):
    with test_data.connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute("alter session set DISABLE_PUT_AND_GET_ON_EXTERNAL_STAGE=false")
            cur.execute(
                """
use warehouse {}
""".format(
                    test_data.warehouse_name
                )
            )
            cur.execute(
                """
use schema {}.pytesting_schema
""".format(
                    test_data.database_name
                )
            )
            cur.execute(
                """
create or replace stage {stage_name}
url='s3://{user_bucket}/{stage_name}'
credentials = (
AWS_KEY_ID={aws_access_key_id}
AWS_SECRET_KEY={aws_secret_access_key})
""".format(
                    aws_access_key_id=test_data.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=test_data.AWS_SECRET_ACCESS_KEY,
                    user_bucket=test_data.user_bucket,
                    stage_name=test_data.stage_name,
                )
            )
            cur.execute(
                """
create or replace table pytest_putget_t2 (c1 STRING, c2 STRING, c3 STRING,
c4 STRING, c5 STRING, c6 STRING, c7 STRING, c8 STRING, c9 STRING)
"""
            )
            cur.execute(
                """put file://{}/ExecPlatform/Database/data/orders_10*.csv @{}""".format(
                    test_data.test_data_dir, test_data.stage_name
                )
            )
            # two files should have been put in the staging are
            results = cur.fetchall()
            assert len(results) == 2

            cur.execute("ls @%pytest_putget_t2")
            results = cur.fetchall()
            assert len(results) == 0, "no files should have been loaded yet"

            # copy
            cur.execute(
                """
copy into pytest_putget_t2 from @{stage_name}
file_format = (field_delimiter = '|' error_on_column_count_mismatch=false)
purge=true
""".format(
                    stage_name=test_data.stage_name
                )
            )
            results = sorted(cur.fetchall())
            assert len(results) == 2, "copy failed to load two files from the stage"
            assert results[0][
                0
            ] == "s3://{user_bucket}/{stage_name}/orders_100.csv.gz".format(
                user_bucket=test_data.user_bucket,
                stage_name=test_data.stage_name,
            ), "copy did not load file orders_100"

            assert results[1][
                0
            ] == "s3://{user_bucket}/{stage_name}/orders_101.csv.gz".format(
                user_bucket=test_data.user_bucket,
                stage_name=test_data.stage_name,
            ), "copy did not load file orders_101"

            # should be empty (purged)
            cur.execute("ls @{stage_name}".format(stage_name=test_data.stage_name))
            results = cur.fetchall()
            assert len(results) == 0, "copied files not purged"
            cur.execute("drop table pytest_putget_t2")
            cur.execute(
                "drop stage {stage_name}".format(stage_name=test_data.stage_name)
            )


@pytest.mark.aws
@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_unload(db_parameters, s3_test_data):
    with s3_test_data.connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute("""use warehouse {}""".format(s3_test_data.warehouse_name))
            cur.execute(
                """use schema {}.pytesting_schema""".format(s3_test_data.database_name)
            )
            cur.execute(
                """
create or replace stage {stage_name}
url='s3://{user_bucket}/{stage_name}/unload/'
credentials = (
AWS_KEY_ID={aws_access_key_id}
AWS_SECRET_KEY={aws_secret_access_key})
""".format(
                    aws_access_key_id=s3_test_data.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=s3_test_data.AWS_SECRET_ACCESS_KEY,
                    user_bucket=s3_test_data.user_bucket,
                    stage_name=s3_test_data.stage_name,
                )
            )

            cur.execute(
                """
CREATE OR REPLACE TABLE pytest_t3  (c1 STRING, c2 STRING, c3 STRING,
c4 STRING, c5 STRING, c6 STRING, c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (format_name = 'vsv' field_delimiter = '|'
error_on_column_count_mismatch=false)
"""
            )
            cur.execute(
                """
alter stage {stage_name} set file_format = (format_name = 'VSV' )
""".format(
                    stage_name=s3_test_data.stage_name
                )
            )

            # make sure its clean
            cur.execute("rm @{stage_name}".format(stage_name=s3_test_data.stage_name))

            # put local file
            cur.execute(
                "put file://{}/ExecPlatform/Database/data/orders_10*.csv @%pytest_t3".format(
                    s3_test_data.test_data_dir
                )
            )

            # copy into table
            cur.execute(
                """
copy into pytest_t3
file_format = (field_delimiter = '|' error_on_column_count_mismatch=false)
purge=true
"""
            )
            # unload from table
            cur.execute(
                """
copy into @{stage_name}/pytest_t3/data_
from pytest_t3 file_format=(format_name='VSV' compression='gzip')
max_file_size=10000000
""".format(
                    stage_name=s3_test_data.stage_name
                )
            )

            # load the data back to another table
            cur.execute(
                """
CREATE OR REPLACE TABLE pytest_t3_copy
(c1 STRING, c2 STRING, c3 STRING, c4 STRING, c5 STRING,
c6 STRING, c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (format_name = 'VSV' )
"""
            )

            cur.execute(
                """
copy into pytest_t3_copy
from @{stage_name}/pytest_t3/data_ return_failed_only=true
""".format(
                    stage_name=s3_test_data.stage_name
                )
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
            cur.execute(
                "rm @{stage_name}/pytest_t3/data_".format(
                    stage_name=s3_test_data.stage_name
                )
            )
            assert cur.rowcount == 1, "only one file was expected to be removed"

            # unload with deflate
            cur.execute(
                """
copy into @{stage_name}/pytest_t3/data_
from pytest_t3 file_format=(format_name='VSV' compression='deflate')
max_file_size=10000000
""".format(
                    stage_name=s3_test_data.stage_name
                )
            )
            results = cur.fetchall()
            assert results[0][0] == 73, "73 rows were expected to be loaded"

            # create a table to unload data into
            cur.execute(
                """
CREATE OR REPLACE TABLE pytest_t3_copy
(c1 STRING, c2 STRING, c3 STRING, c4 STRING, c5 STRING, c6 STRING,
c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (format_name = 'VSV'
compression='deflate')
"""
            )
            results = cur.fetchall()
            assert results[0][0] == "Table PYTEST_T3_COPY successfully created."

            cur.execute(
                """
alter stage {stage_name} set file_format = (format_name = 'VSV'
     compression='deflate')""".format(
                    stage_name=s3_test_data.stage_name
                )
            )

            cur.execute(
                """
copy into pytest_t3_copy from @{stage_name}/pytest_t3/data_
return_failed_only=true
""".format(
                    stage_name=s3_test_data.stage_name
                )
            )
            results = cur.fetchall()
            assert results[0][2] == "LOADED"
            assert results[0][4] == 73
            # check to make sure they are equal
            cur.execute(
                """
(select * from pytest_t3 minus select * from pytest_t3_copy) union
(select * from pytest_t3_copy minus select * from pytest_t3)"""
            )
            assert cur.rowcount == 0, "unloaded/reloaded data were not the same"
            cur.execute(
                "rm @{stage_name}/pytest_t3/data_".format(
                    stage_name=s3_test_data.stage_name
                )
            )
            assert cur.rowcount == 1, "only one file was expected to be removed"

            # clean stage
            cur.execute(
                "rm @{stage_name}/pytest_t3/data_".format(
                    stage_name=s3_test_data.stage_name
                )
            )

            cur.execute("drop table pytest_t3_copy")
            cur.execute(
                "drop stage {stage_name}".format(stage_name=s3_test_data.stage_name)
            )
