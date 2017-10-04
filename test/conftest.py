#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import os
import random
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from io import open
from logging import getLogger

import pytest

from parameters import CONNECTION_PARAMETERS

try:
    from parameters import CONNECTION_PARAMETERS_S3
except:
    CONNECTION_PARAMETERS_S3 = {}

try:
    from parameters import CONNECTION_PARAMETERS_AZURE
except:
    CONNECTION_PARAMETERS_AZURE = {}

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except:
    CONNECTION_PARAMETERS_ADMIN = {}

import snowflake.connector
from snowflake.connector.compat import (UTF8, TO_UNICODE, PY_ISSUE_23517)
from snowflake.connector.converter import SnowflakeConverter
from snowflake.connector.converter_issue23517 import (
    SnowflakeConverterIssue23517)

logger = getLogger(__name__)

if os.getenv('TRAVIS') == 'true':
    TEST_SCHEMA = 'TRAVIS_JOB_{0}'.format(os.getenv('TRAVIS_JOB_ID'))
else:
    TEST_SCHEMA = 'python_connector_tests_' + TO_UNICODE(uuid.uuid4()).replace(
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


@pytest.fixture()
def db_parameters():
    """
    Sets the db connection parameters
    """
    ret = {}
    os.environ['TZ'] = 'UTC'
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

    # snowflake admin account. Not available in TravisCI
    for k, v in CONNECTION_PARAMETERS_ADMIN.items():
        ret['sf_' + k] = v

    if 'host' in ret and ret['host'] == DEFAULT_PARAMETERS['host']:
        ret['host'] = ret['account'] + '.snowflakecomputing.com'

    if 'account' in ret and ret['account'] == DEFAULT_PARAMETERS['account']:
        help()
        sys.exit(2)

    # a unique table name
    ret['name'] = 'python_tests_' + TO_UNICODE(uuid.uuid4()).replace('-', '_')
    ret['name_wh'] = ret['name'] + 'wh'

    ret['schema'] = TEST_SCHEMA
    return ret


@pytest.fixture(scope='session', autouse=True)
def init_test_schema(request):
    """
    Initializes and Deinitializes the test schema
    This is automatically called per test session.
    """
    ret = db_parameters()
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
            "CREATE SCHEMA IF NOT EXISTS {0}".format(TEST_SCHEMA))

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
                "CREATE SCHEMA IF NOT EXISTS {0}".format(TEST_SCHEMA))
            
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
                "CREATE SCHEMA IF NOT EXISTS {0}".format(TEST_SCHEMA))

    def fin():
        ret1 = db_parameters()
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
                "DROP SCHEMA IF EXISTS {0}".format(TEST_SCHEMA))
        if CONNECTION_PARAMETERS_S3:
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
                    "DROP SCHEMA IF EXISTS {0}".format(TEST_SCHEMA))

    request.addfinalizer(fin)


def create_connection(user=None, password=None, account=None, use_numpy=False,
                      converter_class=None):
    """
    Creates a connection using the parameters defined in JDBC connect string
    """
    ret = db_parameters()

    if converter_class is None:
        converter_class = SnowflakeConverter if not PY_ISSUE_23517 else \
            SnowflakeConverterIssue23517
    if user is not None:
        ret['user'] = user
    if password is not None:
        ret['password'] = password
    if account is not None:
        ret['account'] = account
    connection = snowflake.connector.connect(
        protocol=ret['protocol'],
        account=ret['account'],
        user=ret['user'],
        password=ret['password'],
        host=ret['host'],
        port=ret['port'],
        database=ret['database'],
        schema=ret['schema'],
        timezone='UTC',
        numpy=use_numpy,
        converter_class=converter_class,
    )
    return connection


def generate_k_lines_of_n_files(tmpdir, k, n, compress=False):
    """
    Generates K lines of N files
    """
    tmp_dir = str(tmpdir.mkdir('data'))
    for i in range(n):
        with open(os.path.join(tmp_dir, 'file{0}'.format(i)), 'w',
                  encoding=UTF8) as f:
            for j in range(k):
                num = int(random.random() * 10000.0)
                tm = time.gmtime(
                    int(random.random() * 3000000000.0) - 1500000000)
                dt = time.strftime('%Y-%m-%d', tm)
                tm = time.gmtime(
                    int(random.random() * 3000000000.0) - 1500000000)
                ts = time.strftime('%Y-%m-%d %H:%M:%S', tm)
                tm = time.gmtime(
                    int(random.random() * 3000000000.0) - 1500000000)
                tsltz = time.strftime('%Y-%m-%d %H:%M:%S', tm)
                tm = time.gmtime(
                    int(random.random() * 3000000000.0) - 1500000000)
                tsntz = time.strftime('%Y-%m-%d %H:%M:%S', tm)
                tm = time.gmtime(
                    int(random.random() * 3000000000.0) - 1500000000)
                tstz = time.strftime('%Y-%m-%dT%H:%M:%S', tm) + \
                       ('-' if random.random() < 0.5 else '+') + \
                       "{0:02d}:{1:02d}".format(
                           int(random.random() * 12.0),
                           int(random.random() * 60.0))
                pct = random.random() * 1000.0
                ratio = u"{0:5.2f}".format(random.random() * 1000.0)
                rec = u"{0:d},{1:s},{2:s},{3:s},{4:s},{5:s},{6:f},{7:s}".format(
                    num, dt, ts, tsltz, tsntz, tstz,
                    pct,
                    ratio)
                f.write(rec + "\n")
        if compress:
            subprocess.Popen(
                ['gzip', os.path.join(tmp_dir, 'file{0}'.format(i))],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).communicate()
    return tmp_dir


@contextmanager
def db(user=None, password=None, account=None, use_numpy=False,
       converter_class=None):
    cnx = create_connection(
        user=user, password=password,
        account=account, use_numpy=use_numpy,
        converter_class=converter_class)
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
def conn_cnx():
    return db


@pytest.fixture()
def test_files():
    return generate_k_lines_of_n_files
