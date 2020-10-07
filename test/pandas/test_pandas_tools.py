#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import math
from datetime import datetime
from typing import Callable, Dict, Generator

import mock
import pandas
import pytest

from snowflake.connector.pandas_tools import write_pandas
from snowflake.connector.pandas_tools import pd_writer

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
@pytest.mark.parametrize('quote_identifiers', [True, False])
@pytest.mark.parametrize('create_default_columns', [True, False])
def test_write_pandas(conn_cnx: Callable[..., Generator['SnowflakeConnection', None, None]],
                      db_parameters: Dict[str, str],
                      compression: str,
                      parallel: int,
                      chunk_size: int,
                      quote_identifiers: bool,
                      create_default_columns: bool):
    num_of_chunks = math.ceil(len(sf_connector_version_data) / chunk_size)

    with conn_cnx(user=db_parameters['user'],
                  account=db_parameters['account'],
                  password=db_parameters['password']) as cnx:  # type: SnowflakeConnection
        table_name = 'driver_versions'

        if quote_identifiers:
            if create_default_columns:
                create_sql = """CREATE OR REPLACE TABLE "{}" 
                             ("name" STRING, "newest_version" STRING,
                             "id" varchar(36) default uuid_string(),
                             "ts" timestamp_ltz default current_timestamp)""".format(table_name)
                id_key = 'id'
                ts_key = 'ts'
            else:
                create_sql = 'CREATE OR REPLACE TABLE "{}" ("name" STRING, "newest_version" STRING)'.format(table_name)
            select_sql = 'SELECT * FROM "{}"'.format(table_name)
            drop_sql = 'DROP TABLE IF EXISTS "{}"'.format(table_name)
        else:
            if create_default_columns:
                create_sql = """CREATE OR REPLACE TABLE {} 
                             (name STRING, newest_version STRING,
                             id varchar(36) default uuid_string(),
                             ts timestamp_ltz default current_timestamp)""".format(table_name)
                id_key = 'ID'
                ts_key = 'TS'
            else:
                create_sql = 'CREATE OR REPLACE TABLE {} (name STRING, newest_version STRING)'.format(table_name)
            select_sql = 'SELECT * FROM {}'.format(table_name)
            drop_sql = 'DROP TABLE IF EXISTS {}'.format(table_name)

        cnx.execute_string(create_sql)
        try:
            success, nchunks, nrows, _ = write_pandas(cnx,
                                                      sf_connector_version_df,
                                                      table_name,
                                                      compression=compression,
                                                      parallel=parallel,
                                                      chunk_size=chunk_size,
                                                      quote_identifiers=quote_identifiers)
            
            if create_default_columns:
                from snowflake.connector import DictCursor
                result = cnx.cursor(DictCursor).execute(select_sql).fetchall()
                for row in result:
                    assert row[id_key] is not None  # ID (UUID String)
                    assert len(row[id_key]) == 36
                    assert row[ts_key] is not None  # TS (Current Timestamp)
                    assert isinstance(row[ts_key], datetime)
            elif num_of_chunks == 1:
                # Note: since we used one chunk order is conserved
                assert (cnx.cursor().execute(select_sql).fetchall() ==
                        sf_connector_version_data)
            else:
                # Note: since we used one chunk order is NOT conserved
                assert (set(cnx.cursor().execute(select_sql).fetchall()) ==
                        set(sf_connector_version_data))
                
            # Make sure all files were loaded and no error occurred
            assert success
            # Make sure overall as many rows were ingested as we tried to insert
            assert nrows == len(sf_connector_version_data)
            # Make sure we uploaded in as many chunk as we wanted to
            assert nchunks == num_of_chunks
        finally:
            cnx.execute_string(drop_sql)


@pytest.mark.parametrize('quote_identifiers', [True, False])
def test_location_building_db_schema(conn_cnx, quote_identifiers: bool):
    """This tests that write_pandas constructs location correctly with database, schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith('COPY INTO'):
                location = args[0].split(' ')[2]
                if quote_identifiers:
                    assert location == '"database"."schema"."table"'
                else:
                    assert location == 'database.schema.table'
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur
        with mock.patch('snowflake.connector.cursor.SnowflakeCursor.execute', side_effect=mocked_execute) as m_execute:
            success, nchunks, nrows, _ = write_pandas(cnx, sf_connector_version_df, "table",
                                                      database='database', schema='schema', 
                                                      quote_identifiers=quote_identifiers)
            assert m_execute.called and any(map(lambda e: 'COPY INTO' in str(e.args), m_execute.call_args_list))


@pytest.mark.parametrize('quote_identifiers', [True, False])
def test_location_building_schema(conn_cnx, quote_identifiers: bool):
    """This tests that write_pandas constructs location correctly with schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith('COPY INTO'):
                location = args[0].split(' ')[2]
                if quote_identifiers:
                    assert location == '"schema"."table"'
                else:
                    assert location == 'schema.table'
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur
        with mock.patch('snowflake.connector.cursor.SnowflakeCursor.execute', side_effect=mocked_execute) as m_execute:
            success, nchunks, nrows, _ = write_pandas(cnx, sf_connector_version_df, "table",
                                                      schema='schema', quote_identifiers=quote_identifiers)
            assert m_execute.called and any(map(lambda e: 'COPY INTO' in str(e.args), m_execute.call_args_list))


@pytest.mark.parametrize('quote_identifiers', [True, False])
def test_location_building(conn_cnx, quote_identifiers: bool):
    """This tests that write_pandas constructs location correctly with schema and table name."""
    from snowflake.connector.cursor import SnowflakeCursor
    with conn_cnx() as cnx:  # type: SnowflakeConnection
        def mocked_execute(*args, **kwargs):
            if len(args) >= 1 and args[0].startswith('COPY INTO'):
                location = args[0].split(' ')[2]
                if quote_identifiers:
                    assert location == '"teble.table"'
                else:
                    assert location == 'teble.table'
            cur = SnowflakeCursor(cnx)
            cur._result = iter([])
            return cur
        with mock.patch('snowflake.connector.cursor.SnowflakeCursor.execute', side_effect=mocked_execute) as m_execute:
            success, nchunks, nrows, _ = write_pandas(cnx, sf_connector_version_df, "teble.table",
                                                      quote_identifiers=quote_identifiers)
            assert m_execute.called and any(map(lambda e: 'COPY INTO' in str(e.args), m_execute.call_args_list))
            
@pytest.mark.parametrize('quote_identifiers', [True, False])
def test_pandas_to_sql(conn_cnx, db_parameters: Dict[str, str], quote_identifiers: bool):
    try:
        from sqlalchemy import create_engine
        from snowflake.sqlalchemy import URL
    except ImportError:
        from warnings import warn
        warn("Not testing pandas.dataframe.to_sql because snowflake-sqlalchemy is not installed", ImportWarning)
        # User does not have snowflake-sqlalchemy installed
        return
    table_name = 'driver_versions'
    select_sql = None  # forward declaration
    drop_sql = None  # forward declaration

    engine = create_engine(URL(
        account=db_parameters['account'],
        user=db_parameters['user'],
        password=db_parameters['password'],
        database=db_parameters['database'],
        schema=db_parameters['schema'],
        warehouse=db_parameters['warehouse']
    ))

    connection = engine.connect()

    try:
        if quote_identifiers:
            select_sql = 'SELECT * FROM "{}"'.format(table_name.upper())
            drop_sql = 'DROP TABLE IF EXISTS "{}"'.format(table_name.upper())

            # SQL alchemy connector creates table names case insensitively, even though write_pandas,
            # by default, quotes everything
            sf_connector_version_df.to_sql(name=table_name.upper(), con=engine, if_exists='replace', index=False)
            results = [tuple(r) for r in connection.execute(select_sql).fetchall()]
            assert (set(results) == set(sf_connector_version_data))
        else:
            select_sql = 'SELECT * FROM {}'.format(table_name)
            drop_sql = 'DROP TABLE IF EXISTS {}'.format(table_name)

            from functools import partial
            sf_connector_version_df.to_sql(name=table_name, con=engine, if_exists='replace', index=False,
                    method=partial(pd_writer, quote_identifiers=quote_identifiers))
            results = [tuple(r) for r in connection.execute(select_sql).fetchall()]
            assert (set(results) == set(sf_connector_version_data))
    finally:
        engine.execute(drop_sql)
        engine.dispose()
