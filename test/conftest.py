#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import os
import sys
import time
import uuid
from contextlib import contextmanager
from logging import getLogger
from typing import Callable, Generator

import pytest

import snowflake.connector
from generate_test_files import generate_k_lines_of_n_files
from parameters import CONNECTION_PARAMETERS
from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.connection import DefaultConverterClass

MYPY = False
if MYPY:  # from typing import TYPE_CHECKING once 3.5 is deprecated
    from snowflake.connector import SnowflakeConnection

try:
    from parameters import CONNECTION_PARAMETERS_S3
except ImportError:
    CONNECTION_PARAMETERS_S3 = {}

try:
    from parameters import CONNECTION_PARAMETERS_AZURE
except ImportError:
    CONNECTION_PARAMETERS_AZURE = {}

try:
    from parameters import CONNECTION_PARAMETERS_GCP
except ImportError:
    CONNECTION_PARAMETERS_GCP = {}

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}


logger = getLogger(__name__)

if os.getenv('TRAVIS') == 'true':
    TEST_SCHEMA = 'TRAVIS_JOB_{}'.format(os.getenv('TRAVIS_JOB_ID'))
elif os.getenv('APPVEYOR') == 'True':
    TEST_SCHEMA = 'APPVEYOR_JOB_{}'.format(os.getenv('APPVEYOR_BUILD_ID'))
else:
    TEST_SCHEMA = 'python_connector_tests_' + str(uuid.uuid4()).replace(
        '-', '_')

DEFAULT_PARAMETERS = {
    'account': '<account_name>',
    'user': '<user_name>',
    'password': '<password>',
    'database': '<database_name>',
    'schema': '<schema_name>',
    'protocol': 'https',
    'host': '<host>',
    'port': '443',
}


def help():
    print("""Connection parameter must be specified in parameters.py,
    for example:
CONNECTION_PARAMETERS = {
    'account': 'testaccount',
    'user': 'user1',
    'password': 'test',
    'database': 'testdb',
    'schema': 'public',
}
""")


@pytest.fixture(scope='session', autouse=True)
def filter_log():
    # TODO: maybe we can use env variable to control whether doing this or not (this should be done)
    # A workround to use our custom Formatter in pytest.
    # Based on the discussion here 'https://github.com/pytest-dev/pytest/issues/2987'
    from snowflake.connector.secret_detector import SecretDetector
    import logging
    import pathlib
    # the directory of this conftest file
    this_dir = pathlib.Path(__file__).parent.absolute()
    _logger = getLogger('snowflake.connector')
    _logger.setLevel(logging.DEBUG)
    sd = logging.FileHandler(os.path.join(str(this_dir), 'snowflake_ssm_rt.log'))
    sd.setLevel(logging.DEBUG)
    sd.setFormatter(SecretDetector('%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s'))
    _logger.addHandler(sd)


@pytest.fixture(scope='session')
def is_public_test():
    return is_public_testaccount()


def is_public_testaccount():
    db_parameters = get_db_parameters()
    return (os.getenv('GITHUB_ACTIONS') == 'true' or
           db_parameters.get('account').startswith('sfctest0'))


@pytest.fixture(scope='session')
def db_parameters():
    return get_db_parameters()


def get_db_parameters():
    """Sets the db connection parameters."""
    ret = {}
    os.environ['TZ'] = 'UTC'
    if not IS_WINDOWS:
        time.tzset()

    # testaccount connection info
    for k, v in CONNECTION_PARAMETERS.items():
        ret[k] = v

    for k, v in DEFAULT_PARAMETERS.items():
        if k not in ret:
            ret[k] = v

    # s3 testaccount connection info. Not available in TravisCI
    if CONNECTION_PARAMETERS_S3:
        for k, v in CONNECTION_PARAMETERS_S3.items():
            ret['s3_' + k] = v
    else:
        for k, v in CONNECTION_PARAMETERS.items():
            ret['s3_' + k] = v

    # azure testaccount connection info. Not available in TravisCI
    if CONNECTION_PARAMETERS_AZURE:
        for k, v in CONNECTION_PARAMETERS_AZURE.items():
            ret['azure_' + k] = v
    else:
        for k, v in CONNECTION_PARAMETERS.items():
            ret['azure_' + k] = v

    # azure testaccount connection info. Not available in TravisCI
    if CONNECTION_PARAMETERS_GCP:
        for k, v in CONNECTION_PARAMETERS_GCP.items():
            ret['gcp_' + k] = v
    else:
        for k, v in CONNECTION_PARAMETERS.items():
            ret['gcp_' + k] = v

    # snowflake admin account. Not available in TravisCI
    for k, v in CONNECTION_PARAMETERS_ADMIN.items():
        ret['sf_' + k] = v

    if 'host' in ret and ret['host'] == DEFAULT_PARAMETERS['host']:
        ret['host'] = ret['account'] + '.snowflakecomputing.com'

    if 'account' in ret and ret['account'] == DEFAULT_PARAMETERS['account']:
        help()
        sys.exit(2)

    # a unique table name
    ret['name'] = 'python_tests_' + str(uuid.uuid4()).replace('-', '_')
    ret['name_wh'] = ret['name'] + 'wh'

    ret['schema'] = TEST_SCHEMA

    # This reduces a chance to exposing password in test output.
    ret['a00'] = 'dummy parameter'
    ret['a01'] = 'dummy parameter'
    ret['a02'] = 'dummy parameter'
    ret['a03'] = 'dummy parameter'
    ret['a04'] = 'dummy parameter'
    ret['a05'] = 'dummy parameter'
    ret['a06'] = 'dummy parameter'
    ret['a07'] = 'dummy parameter'
    ret['a08'] = 'dummy parameter'
    ret['a09'] = 'dummy parameter'
    ret['a10'] = 'dummy parameter'
    ret['a11'] = 'dummy parameter'
    ret['a12'] = 'dummy parameter'
    ret['a13'] = 'dummy parameter'
    ret['a14'] = 'dummy parameter'
    ret['a15'] = 'dummy parameter'
    ret['a16'] = 'dummy parameter'
    return ret


@pytest.fixture(scope='session', autouse=True)
def init_test_schema(request, db_parameters):
    """Initializes and Deinitializes the test schema. This is automatically called per test session."""
    ret = db_parameters
    with snowflake.connector.connect(
            user=ret['user'],
            password=ret['password'],
            host=ret['host'],
            port=ret['port'],
            database=ret['database'],
            account=ret['account'],
            protocol=ret['protocol']
    ) as con:
        con.cursor().execute(
            "CREATE SCHEMA IF NOT EXISTS {}".format(TEST_SCHEMA))

    if CONNECTION_PARAMETERS_S3:
        with snowflake.connector.connect(
                user=ret['s3_user'],
                password=ret['s3_password'],
                host=ret['s3_host'],
                port=ret['s3_port'],
                database=ret['s3_database'],
                account=ret['s3_account'],
                protocol=ret['s3_protocol']
        ) as con:
            con.cursor().execute(
                "CREATE SCHEMA IF NOT EXISTS {}".format(TEST_SCHEMA))

    if CONNECTION_PARAMETERS_AZURE:
        with snowflake.connector.connect(
                user=ret['azure_user'],
                password=ret['azure_password'],
                host=ret['azure_host'],
                port=ret['azure_port'],
                database=ret['azure_database'],
                account=ret['azure_account'],
                protocol=ret['azure_protocol']
        ) as con:
            con.cursor().execute(
                "CREATE SCHEMA IF NOT EXISTS {}".format(TEST_SCHEMA))

    if CONNECTION_PARAMETERS_GCP:
        with snowflake.connector.connect(
                user=ret['gcp_user'],
                password=ret['gcp_password'],
                host=ret['gcp_host'],
                port=ret['gcp_port'],
                database=ret['gcp_database'],
                account=ret['gcp_account'],
                protocol=ret['gcp_protocol']
        ) as con:
            con.cursor().execute(
                "CREATE SCHEMA IF NOT EXISTS {}".format(TEST_SCHEMA))

    def fin():
        ret1 = db_parameters
        with snowflake.connector.connect(
                user=ret1['user'],
                password=ret1['password'],
                host=ret1['host'],
                port=ret1['port'],
                database=ret1['database'],
                account=ret1['account'],
                protocol=ret1['protocol']
        ) as con1:
            con1.cursor().execute(
                "DROP SCHEMA IF EXISTS {}".format(TEST_SCHEMA))
        if CONNECTION_PARAMETERS_S3:
            with snowflake.connector.connect(
                    user=ret1['s3_user'],
                    password=ret1['s3_password'],
                    host=ret1['s3_host'],
                    port=ret1['s3_port'],
                    database=ret1['s3_database'],
                    account=ret1['s3_account'],
                    protocol=ret1['s3_protocol']
            ) as con1:
                con1.cursor().execute(
                    "DROP SCHEMA IF EXISTS {}".format(TEST_SCHEMA))

    request.addfinalizer(fin)


def create_connection(**kwargs) -> 'SnowflakeConnection':
    """Creates a connection using the parameters defined in parameters.py."""
    ret = get_db_parameters()
    ret.update(kwargs)
    connection = snowflake.connector.connect(**ret)
    return connection


@contextmanager
def db(**kwargs) -> Generator['SnowflakeConnection', None, None]:
    if not kwargs.get('timezone'):
        kwargs['timezone'] = 'UTC'
    if not kwargs.get('converter_class'):
        kwargs['converter_class'] = DefaultConverterClass()
    cnx = create_connection(**kwargs)
    try:
        yield cnx
    finally:
        cnx.close()


@contextmanager
def negative_db(**kwargs):
    if not kwargs.get('timezone'):
        kwargs['timezone'] = 'UTC'
    if not kwargs.get('converter_class'):
        kwargs['converter_class'] = DefaultConverterClass()
    cnx = create_connection(**kwargs)
    if not is_public_testaccount():
        cnx.cursor().execute("alter session set SUPPRESS_INCIDENT_DUMPS=true")
    try:
        yield cnx
    finally:
        cnx.close()


@pytest.fixture()
def conn_testaccount(request):
    connection = create_connection()

    def fin():
        connection.close()  # close when done

    request.addfinalizer(fin)
    return connection


@pytest.fixture()
def conn_cnx() -> Callable[..., Generator['SnowflakeConnection', None, None]]:
    return db


@pytest.fixture()
def negative_conn_cnx():
    """Use this if an incident is expected and we don't want GS to create a dump file about the incident."""
    return negative_db


@pytest.fixture()
def test_files():
    return generate_k_lines_of_n_files


def pytest_runtest_setup(item):
    for _ in item.iter_markers(name="internal"):
        if is_public_testaccount():
            pytest.skip("cannot run on public CI")
