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

from ..integ_helpers import drop_database, drop_stage, drop_table, drop_warehouse
from ..randomize import random_string

try:
    from ..parameters import (CONNECTION_PARAMETERS_ADMIN)
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

THIS_DIR = path.dirname(path.realpath(__file__))

logger = getLogger(__name__)


@pytest.fixture()
def test_data(request, conn_cnx):
    assert 'AWS_ACCESS_KEY_ID' in os.environ, 'AWS_ACCESS_KEY_ID is missing'
    assert 'AWS_SECRET_ACCESS_KEY' in os.environ, \
        'AWS_SECRET_ACCESS_KEY is missing'

    unique_name = random_string(10, prefix="create_test_data_")
    database_name = f"{unique_name}_db"
    warehouse_name = f"{unique_name}_wh"

    class TestData(object):
        def __init__(self):
            self.test_data_dir = (pathlib.Path(__file__).parent.parent / 'data').absolute()
            self.AWS_ACCESS_KEY_ID = f"'{os.environ['AWS_ACCESS_KEY_ID']}'"
            self.AWS_SECRET_ACCESS_KEY = f"'{os.environ['AWS_SECRET_ACCESS_KEY']}'"
            self.stage_name = f"{unique_name}_stage"
            self.warehouse_name = warehouse_name
            self.database_name = database_name
            self.connection = conn_cnx
            self.user_bucket = os.getenv(
                'SF_AWS_USER_BUCKET',
                "sfc-dev1-regression/{}/reg".format(getuser()))

    with conn_cnx() as cnx:
        with cnx.cursor() as cur:
            cur.execute("use role sysadmin")
            cur.execute(f"""
create warehouse {warehouse_name}
warehouse_size = 'small' warehouse_type='standard'
auto_suspend=1800
""")
            request.addfinalizer(drop_warehouse(conn_cnx, warehouse_name))
            cur.execute(f"""
create database {database_name}
""")
            request.addfinalizer(drop_database(conn_cnx, database_name))
            cur.execute("""
create or replace schema pytesting_schema
""")
            cur.execute("""
create or replace file format VSV type = 'CSV'
field_delimiter='|' error_on_column_count_mismatch=false
    """)
    return TestData()


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_load_s3(test_data, request, conn_cnx):
    table_name = random_string(3, prefix="tweets_")
    with test_data.connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute(f"use warehouse {test_data.warehouse_name}")
            cur.execute(f"use schema {test_data.database_name}.pytesting_schema")

            cur.execute(f"""
create table {table_name}(created_at timestamp,
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
""")
            request.addfinalizer(drop_table(conn_cnx, table_name))
            cur.execute(f"ls @%{table_name}")
            assert cur.rowcount == 0, \
                ('table newly created should not have any files in its '
                 'staging area')

            cur.execute(f"""
                copy into {table_name} from s3://sfc-dev1-data/twitter/O1k/tweets/
                credentials=(AWS_KEY_ID={test_data.AWS_ACCESS_KEY_ID}
                AWS_SECRET_KEY={test_data.AWS_SECRET_ACCESS_KEY})
                file_format=(skip_header=1 null_if=('') field_optionally_enclosed_by='"')
                """)
            assert cur.rowcount == 1, 'copy into table did not set rowcount to 1'
            results = cur.fetchall()
            assert results[0][0] == "s3://sfc-dev1-data/twitter/O1k/tweets/1.csv.gz", \
                f"ls @%{table_name} failed"


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_local_file(test_data, request, conn_cnx):
    table_name = random_string(3, prefix="test_put_local_file_")
    with test_data.connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute("alter session set DISABLE_PUT_AND_GET_ON_EXTERNAL_STAGE=false")
            cur.execute("use warehouse {}".format(test_data.warehouse_name))
            cur.execute(
                """use schema {}.pytesting_schema""".format(
                    test_data.database_name))
            cur.execute(f"""
create table {table_name} (c1 STRING, c2 STRING, c3 STRING,
c4 STRING, c5 STRING, c6 STRING, c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (field_delimiter = '|' error_on_column_count_mismatch=false)
stage_copy_options = (purge=false)
stage_location = (url = 's3://sfc-dev1-regression/jenkins/{test_data.stage_name}'
credentials = (
AWS_KEY_ID={test_data.AWS_ACCESS_KEY_ID}
AWS_SECRET_KEY={test_data.AWS_SECRET_ACCESS_KEY}))
""")
            request.addfinalizer(drop_table(conn_cnx, table_name))
            cur.execute(
                f"""put file://{test_data.test_data_dir}/ExecPlatform/Database/data/orders_10*.csv @%{table_name}""")
            cur.execute(f"ls @%{table_name}")
            _ = cur.fetchall()
            assert cur.rowcount == 2, \
                f'ls @%{table_name} did not return 2 rows'
            cur.execute(f"copy into {table_name}")
            results = cur.fetchall()
            assert len(results) == 2, '2 files were not copied'
            assert results[0][1] == 'LOADED', \
                'file 1 was not loaded after copy'
            assert results[1][1] == 'LOADED', \
                'file 2 was not loaded after copy'

            cur.execute(f"select count(*) from {table_name}")
            results = cur.fetchall()
            assert results[0][0] == 73, \
                f'73 rows not loaded into {table_name}'
            cur.execute(f"rm @%{table_name}")
            results = cur.fetchall()
            assert len(results) == 2, 'two files were not removed'
            cur.execute(
                f"select STATUS from information_schema.load_history where table_name='{table_name.upper()}'")
            results = cur.fetchall()
            assert results[0][0] == 'LOADED', \
                'history does not show file to be loaded'


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_put_load_from_user_stage(test_data, conn_cnx, request):
    with test_data.connection() as cnx:
        with cnx.cursor() as cur:
            cur.execute(
                "alter session set DISABLE_PUT_AND_GET_ON_EXTERNAL_STAGE=false")
            cur.execute(f"""
use warehouse {test_data.warehouse_name}
""")
            cur.execute(f"""
use schema {test_data.database_name}.pytesting_schema
""")
            cur.execute(f"""
create stage {test_data.stage_name}
url='s3://{test_data.user_bucket}/{test_data.stage_name}'
credentials = (
AWS_KEY_ID={test_data.AWS_ACCESS_KEY_ID}
AWS_SECRET_KEY={test_data.AWS_SECRET_ACCESS_KEY})
""")
            request.addfinalizer(drop_stage(conn_cnx, test_data.stage_name))
            table_name = random_string(3, prefix="test_put_load_from_user_stage_")
            cur.execute(f"""
create table {table_name} (c1 STRING, c2 STRING, c3 STRING,
c4 STRING, c5 STRING, c6 STRING, c7 STRING, c8 STRING, c9 STRING)
""")
            request.addfinalizer(drop_table(conn_cnx, table_name))
            cur.execute("""put file://{}/ExecPlatform/Database/data/orders_10*.csv @{}""".format(
                test_data.test_data_dir,
                test_data.stage_name
            ))
            # two files should have been put in the staging are
            results = cur.fetchall()
            assert len(results) == 2

            cur.execute(f"ls @%{table_name}")
            results = cur.fetchall()
            assert len(results) == 0, \
                'no files should have been loaded yet'

            # copy
            cur.execute(f"""
copy into {table_name} from @{test_data.stage_name}
file_format = (field_delimiter = '|' error_on_column_count_mismatch=false)
purge=true
""")
            results = sorted(cur.fetchall())
            assert len(results) == 2, \
                'copy failed to load two files from the stage'
            assert results[0][0] == \
                   "s3://{user_bucket}/{stage_name}/orders_100.csv.gz".format(
                       user_bucket=test_data.user_bucket,
                       stage_name=test_data.stage_name,
                   ), 'copy did not load file orders_100'

            assert results[1][0] == \
                   "s3://{user_bucket}/{stage_name}/orders_101.csv.gz".format(
                       user_bucket=test_data.user_bucket,
                       stage_name=test_data.stage_name,
                   ), 'copy did not load file orders_101'

            # should be empty (purged)
            cur.execute(
                "ls @{stage_name}".format(stage_name=test_data.stage_name))
            results = cur.fetchall()
            assert len(results) == 0, 'copied files not purged'


@pytest.mark.aws
@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="Snowflake admin account is not accessible."
)
def test_unload(test_data, request, conn_cnx):
    with test_data.connection() as cnx:
        table_name = random_string(3, prefix="test_unload_")
        with cnx.cursor() as cur:
            cur.execute(
                f"""use warehouse {test_data.warehouse_name}""")
            cur.execute(
                f"""use schema {test_data.database_name}.pytesting_schema""")
            cur.execute(f"""
create stage {test_data.stage_name}
url='s3://{test_data.user_bucket}/{test_data.stage_name}/unload/'
credentials = (
AWS_KEY_ID={test_data.AWS_ACCESS_KEY_ID}
AWS_SECRET_KEY={test_data.AWS_SECRET_ACCESS_KEY})
""")
            request.addfinalizer(drop_stage(conn_cnx, test_data.stage_name))

            cur.execute(f"""
CREATE TABLE {table_name}  (c1 STRING, c2 STRING, c3 STRING,
c4 STRING, c5 STRING, c6 STRING, c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (format_name = 'vsv' field_delimiter = '|'
error_on_column_count_mismatch=false)
""")
            request.addfinalizer(drop_table(conn_cnx, table_name))
            cur.execute(f"""
alter stage {test_data.stage_name} set file_format = (format_name = 'VSV' )
""")

            # make sure its clean
            cur.execute(
                f"rm @{test_data.stage_name}")

            # put local file
            cur.execute(
                f"put file://{test_data.test_data_dir}/ExecPlatform/Database/data/orders_10*.csv @%{table_name}")

            # copy into table
            cur.execute(f"""
copy into {table_name}
file_format = (field_delimiter = '|' error_on_column_count_mismatch=false)
purge=true
""")
            # unload from table
            cur.execute(f"""
copy into @{test_data.stage_name}/{table_name}/data_
from {table_name} file_format=(format_name='VSV' compression='gzip')
max_file_size=10000000
""")
            table_name_copy = table_name + '_copy'

            # load the data back to another table
            cur.execute(f"""
CREATE TABLE {table_name_copy}
(c1 STRING, c2 STRING, c3 STRING, c4 STRING, c5 STRING,
c6 STRING, c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (format_name = 'VSV' )
""")
            request.addfinalizer(drop_table(conn_cnx, table_name_copy))
            cur.execute(f"""
copy into {table_name_copy}
from @{test_data.stage_name}/{table_name}/data_ return_failed_only=true
""")

            # check to make sure they are equal
            cur.execute(f"""
(select * from {table_name} minus select * from {table_name_copy})
union
(select * from {table_name_copy} minus select * from {table_name})
"""
                        )
            assert cur.rowcount == 0, \
                'unloaded/reloaded data were not the same'
            # clean stage
            cur.execute(f"rm @{test_data.stage_name}/{table_name}/data_")
            assert cur.rowcount == 1, \
                'only one file was expected to be removed'

            # unload with deflate
            cur.execute(f"""
copy into @{test_data.stage_name}/{table_name}/data_
from {table_name} file_format=(format_name='VSV' compression='deflate')
max_file_size=10000000
""")
            results = cur.fetchall()
            assert results[0][0] == 73, '73 rows were expected to be loaded'

            # create a table to unload data into
            cur.execute(f"""
CREATE OR REPLACE TABLE {table_name_copy}
(c1 STRING, c2 STRING, c3 STRING, c4 STRING, c5 STRING, c6 STRING,
c7 STRING, c8 STRING, c9 STRING)
stage_file_format = (format_name = 'VSV'
compression='deflate')
""")
            results = cur.fetchall()
            assert results[0][0] == \
                   f"Table {table_name_copy.upper()} successfully created."

            cur.execute(f"""
alter stage {test_data.stage_name} set file_format = (format_name = 'VSV'
     compression='deflate')""")

            cur.execute(f"""
copy into {table_name_copy} from @{test_data.stage_name}/{table_name}/data_
return_failed_only=true
""")
            results = cur.fetchall()
            assert results[0][2] == "LOADED"
            assert results[0][4] == 73
            # check to make sure they are equal
            cur.execute(f"""
(select * from {table_name} minus select * from {table_name_copy}) union
(select * from {table_name_copy} minus select * from {table_name})"""
                        )
            assert cur.rowcount == 0, \
                'unloaded/reloaded data were not the same'
            cur.execute(f"rm @{test_data.stage_name}/{table_name}/data_")
            assert cur.rowcount == 1, \
                'only one file was expected to be removed'

            # clean stage
            cur.execute(f"rm @{test_data.stage_name}/{table_name}/data_")
