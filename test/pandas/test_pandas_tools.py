#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import math
from typing import Callable, Dict, Generator

import mock
import pandas
import pytest

from snowflake.connector.pandas_tools import write_pandas

MYPY = False
if MYPY:  # from typing import TYPE_CHECKING once 3.5 is deprecated
    from snowflake.connector import SnowflakeConnection

sf_connector_version_data = [
    ('snowflake-connector-python', '1.2.23'),
    ('snowflake-sqlalchemy', '1.1.1'),
    ('snowflake-connector-go', '0.0.1'),
    ('snowflake-go', '1.0.1'),
    ('snowflake-odbc', '3.12.3'),
]

sf_connector_version_df = pandas.DataFrame(sf_connector_version_data, columns=['name', 'newest_version'])


@pytest.mark.parametrize('chunk_size', [5, 4, 3, 2, 1])
@pytest.mark.parametrize('compression', ['gzip', 'snappy'])
# Note: since the file will to small to chunk, this is only testing the put command's syntax
@pytest.mark.parametrize('parallel', [4, 99])
def test_write_pandas_quoted_identifiers(conn_cnx: Callable[..., Generator['SnowflakeConnection', None, None]],
                      db_parameters: Dict[str, str],
                      compression: str,
                      parallel: int,
                      chunk_size: int):
    num_of_chunks = math.ceil(len(sf_connector_version_data) / chunk_size)

    with conn_cnx(user=db_parameters['user'],
                  account=db_parameters['account'],
                  password=db_parameters['password']) as cnx:  # type: SnowflakeConnection
        table_name = 'driver_versions'
        cnx.execute_string('CREATE OR REPLACE TABLE "{}"("name" STRING, "newest_version" STRING)'.format(table_name))
        try:
            success, nchunks, nrows, _ = write_pandas(cnx,
                                                      sf_connector_version_df,
                                                      table_name,
                                                      compression=compression,
                                                      parallel=parallel,
                                                      chunk_size=chunk_size,
                                                      quote_identifiers=True)
            if num_of_chunks == 1:
                # Note: since we used one chunk order is conserved
                assert (cnx.cursor().execute('SELECT * FROM "{}"'.format(table_name)).fetchall() ==
                        sf_connector_version_data)
            else:
                # Note: since we used one chunk order is NOT conserved
                assert (set(cnx.cursor().execute('SELECT * FROM "{}"'.format(table_name)).fetchall()) ==
                        set(sf_connector_version_data))
            # Make sure all files were loaded and no error occurred
            assert success
            # Make sure overall as many rows were ingested as we tried to insert
            assert nrows == len(sf_connector_version_data)
            # Make sure we uploaded in as many chunk as we wanted to
            assert nchunks == num_of_chunks
        finally:
            cnx.execute_string("DROP TABLE IF EXISTS {}".format(table_name))


@pytest.mark.parametrize('chunk_size', [5, 4, 3, 2, 1])
@pytest.mark.parametrize('compression', ['gzip', 'snappy'])
# Note: since the file will be too small to chunk, this is only testing the put command's syntax
@pytest.mark.parametrize('parallel', [4, 99])
def test_write_pandas(conn_cnx: Callable[..., Generator['SnowflakeConnection', None, None]],
                      db_parameters: Dict[str, str],
                      compression: str,
                      parallel: int,
                      chunk_size: int):
    num_of_chunks = math.ceil(len(sf_connector_version_data) / chunk_size)

    with conn_cnx(user=db_parameters['user'],
                  account=db_parameters['account'],
                  password=db_parameters['password']) as cnx:  # type: SnowflakeConnection
        table_name = 'driver_versions'
        # by default (quote_identifiers=False), the user is not interested in quoting identifiers, so do
        # not quote them when creating table
        cnx.execute_string('CREATE OR REPLACE TABLE {} (name STRING, newest_version STRING)'.format(table_name))
        try:
            success, nchunks, nrows, _ = write_pandas(cnx,
                                                      sf_connector_version_df,
                                                      table_name,
                                                      compression=compression,
                                                      parallel=parallel,
                                                      chunk_size=chunk_size)
            if num_of_chunks == 1:
                # Note: since we used one chunk order is conserved
                assert (cnx.cursor().execute('SELECT * FROM {}'.format(table_name)).fetchall() ==
                        sf_connector_version_data)
            else:
                # Note: since we used one chunk order is NOT conserved
                assert (set(cnx.cursor().execute('SELECT * FROM {}'.format(table_name)).fetchall()) ==
                        set(sf_connector_version_data))
            # Make sure all files were loaded and no error occurred
            assert success
            # Make sure overall as many rows were ingested as we tried to insert
            assert nrows == len(sf_connector_version_data)
            # Make sure we uploaded in as many chunk as we wanted to
            assert nchunks == num_of_chunks
        finally:
            cnx.execute_string("DROP TABLE IF EXISTS {}".format(table_name))


@pytest.mark.parametrize('chunk_size', [5, 4, 3, 2, 1])
@pytest.mark.parametrize('compression', ['gzip', 'snappy'])
# Note: since the file will to small to chunk, this is only testing the put command's syntax
@pytest.mark.parametrize('parallel', [4, 99])
def test_write_pandas_default_cols(conn_cnx: Callable[..., Generator['SnowflakeConnection', None, None]],
                      db_parameters: Dict[str, str],
                      compression: str,
                      parallel: int,
                      chunk_size: int):
    from snowflake.connector import DictCursor
    num_of_chunks = math.ceil(len(sf_connector_version_data) / chunk_size)

    with conn_cnx(user=db_parameters['user'],
                  account=db_parameters['account'],
                  password=db_parameters['password']) as cnx:  # type: SnowflakeConnection
        table_name = 'driver_versions'
        # by default (quote_identifiers=False), the user is not interested in quoting identifiers, so do
        # not quote them when creating table
        cnx.execute_string("""CREATE OR REPLACE TABLE {} (
                              id varchar(36) default uuid_string(),
                              name STRING, newest_version STRING,
                              ts timestamp_ltz default current_timestamp)""".format(table_name))
        try:
            success, nchunks, nrows, _ = write_pandas(cnx,
                                                      sf_connector_version_df,
                                                      table_name,
                                                      compression=compression,
                                                      parallel=parallel,
                                                      chunk_size=chunk_size)
            result = cnx.cursor(DictCursor).execute('SELECT * FROM {}'.format(table_name)).fetchall()
            for row in result:
                assert row['ID'] is not None
                assert row['TS'] is not None
            # Make sure all files were loaded and no error occurred
            assert success
            # Make sure overall as many rows were ingested as we tried to insert
            assert nrows == len(sf_connector_version_data)
            # Make sure we uploaded in as many chunk as we wanted to
            assert nchunks == num_of_chunks
        finally:
            cnx.execute_string("DROP TABLE IF EXISTS {}".format(table_name))


def test_location_building_db_schema(conn_cnx):
    """This tests that write_pandas constructs location correctly with database, schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith('COPY INTO'):
                location = args[0].split(' ')[2]
                assert location == 'database.schema.table'
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur
        with mock.patch('snowflake.connector.cursor.SnowflakeCursor.execute', side_effect=mocked_execute) as m_execute:
            success, nchunks, nrows, _ = write_pandas(cnx, sf_connector_version_df, "table",
                                                      database='database', schema='schema')
            assert m_execute.called and any(map(lambda e: 'COPY INTO' in str(e.args), m_execute.call_args_list))


def test_location_building_db_schema_quoted_identifiers(conn_cnx):
    """This tests that write_pandas constructs location correctly with database, schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith('COPY INTO'):
                location = args[0].split(' ')[2]
                assert location == '"database"."schema"."table"'
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur
        with mock.patch('snowflake.connector.cursor.SnowflakeCursor.execute', side_effect=mocked_execute) as m_execute:
            success, nchunks, nrows, _ = write_pandas(cnx, sf_connector_version_df, "table",
                                                      database='database', schema='schema', quote_identifiers=True)
            assert m_execute.called and any(map(lambda e: 'COPY INTO' in str(e.args), m_execute.call_args_list))


def test_location_building_schema(conn_cnx):
    """This tests that write_pandas constructs location correctly with schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith('COPY INTO'):
                location = args[0].split(' ')[2]
                assert location == 'schema.table'
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur
        with mock.patch('snowflake.connector.cursor.SnowflakeCursor.execute', side_effect=mocked_execute) as m_execute:
            success, nchunks, nrows, _ = write_pandas(cnx, sf_connector_version_df, "table",
                                                      schema='schema')
            assert m_execute.called and any(map(lambda e: 'COPY INTO' in str(e.args), m_execute.call_args_list))


def test_location_building_schema_quoted_identifier(conn_cnx):
    """This tests that write_pandas constructs location correctly with schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith('COPY INTO'):
                location = args[0].split(' ')[2]
                assert location == '"schema"."table"'
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur
        with mock.patch('snowflake.connector.cursor.SnowflakeCursor.execute', side_effect=mocked_execute) as m_execute:
            success, nchunks, nrows, _ = write_pandas(cnx, sf_connector_version_df, "table",
                                                      schema='schema', quote_identifiers=True)
            assert m_execute.called and any(map(lambda e: 'COPY INTO' in str(e.args), m_execute.call_args_list))


def test_location_building(conn_cnx):
    """This tests that write_pandas constructs location correctly with schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith('COPY INTO'):
                location = args[0].split(' ')[2]
                assert location == 'teble.table'
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur
        with mock.patch('snowflake.connector.cursor.SnowflakeCursor.execute', side_effect=mocked_execute) as m_execute:
            success, nchunks, nrows, _ = write_pandas(cnx, sf_connector_version_df, "teble.table")
            assert m_execute.called and any(map(lambda e: 'COPY INTO' in str(e.args), m_execute.call_args_list))


def test_location_building_quoted_identifiers(conn_cnx):
    """This tests that write_pandas constructs location correctly with schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith('COPY INTO'):
                location = args[0].split(' ')[2]
                assert location == '"teble.table"'
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur
        with mock.patch('snowflake.connector.cursor.SnowflakeCursor.execute', side_effect=mocked_execute) as m_execute:
            success, nchunks, nrows, _ = write_pandas(cnx, sf_connector_version_df, "teble.table", quote_identifiers=True)
            assert m_execute.called and any(map(lambda e: 'COPY INTO' in str(e.args), m_execute.call_args_list))
