#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import os

import pytest
import threading
import queue

import snowflake.connector
from snowflake.connector import (
    DatabaseError,
    ProgrammingError, OperationalError)
from snowflake.connector.errors import (ForbiddenError)

try:
    from parameters import (CONNECTION_PARAMETERS_ADMIN)
except:
    CONNECTION_PARAMETERS_ADMIN = {}

from snowflake.connector.description import CLIENT_NAME
from snowflake.connector.network import APPLICATION_SNOWSQL
from snowflake.connector.connection import SnowflakeConnection


def test_basic(conn_testaccount):
    """
    Basic Connection test
    """
    assert conn_testaccount, 'invalid cnx'
    conn_testaccount._set_current_objects()


def test_connection_without_schema(db_parameters):
    """
    Basic Connection test without schema
    """
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        database=db_parameters['database'],
        protocol=db_parameters['protocol'],
        timezone='UTC',
    )
    assert cnx, 'invalid cnx'
    cnx.close()


def test_connection_without_database_schema(db_parameters):
    """
    Basic Connection test without database and schema
    """
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        protocol=db_parameters['protocol'],
        timezone='UTC',
    )
    assert cnx, 'invalid cnx'
    cnx.close()


def test_connection_without_database2(db_parameters):
    """
    Basic Connection test without database
    """
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        schema=db_parameters['schema'],
        protocol=db_parameters['protocol'],
        timezone='UTC',
    )
    assert cnx, 'invalid cnx'
    cnx.close()


def test_with_config(db_parameters):
    """
    Creates a connection with the config parameter
    """
    config = {
        'user': db_parameters['user'],
        'password': db_parameters['password'],
        'host': db_parameters['host'],
        'port': db_parameters['port'],
        'account': db_parameters['account'],
        'schema': db_parameters['schema'],
        'database': db_parameters['database'],
        'protocol': db_parameters['protocol'],
        'timezone': 'UTC',
    }
    cnx = snowflake.connector.connect(**config)
    try:
        assert cnx, 'invalid cnx'
        assert not cnx.client_session_keep_alive  # default is False
    finally:
        cnx.close()


def test_keep_alive_true(db_parameters):
    """
    Creates a connection with client_session_keep_alive parameter.
    """
    config = {
        'user': db_parameters['user'],
        'password': db_parameters['password'],
        'host': db_parameters['host'],
        'port': db_parameters['port'],
        'account': db_parameters['account'],
        'schema': db_parameters['schema'],
        'database': db_parameters['database'],
        'protocol': db_parameters['protocol'],
        'timezone': 'UTC',
        'client_session_keep_alive': True
    }
    cnx = snowflake.connector.connect(**config)
    try:
        assert cnx.client_session_keep_alive
    finally:
        cnx.close()


def test_keep_alive_heartbeat_frequency(db_parameters):
    """
    Creates a connection with client_session_keep_alive_heartbeat_frequency
    parameter.
    """
    config = {
        'user': db_parameters['user'],
        'password': db_parameters['password'],
        'host': db_parameters['host'],
        'port': db_parameters['port'],
        'account': db_parameters['account'],
        'schema': db_parameters['schema'],
        'database': db_parameters['database'],
        'protocol': db_parameters['protocol'],
        'timezone': 'UTC',
        'client_session_keep_alive': True,
        'client_session_keep_alive_heartbeat_frequency': 1000,
    }
    cnx = snowflake.connector.connect(**config)
    try:
        assert cnx.client_session_keep_alive_heartbeat_frequency == 1000
    finally:
        cnx.close()


def test_keep_alive_heartbeat_frequency_min(db_parameters):
    """
    Creates a connection with client_session_keep_alive_heartbeat_frequency
    parameter and set the minimum frequency
    """
    config = {
        'user': db_parameters['user'],
        'password': db_parameters['password'],
        'host': db_parameters['host'],
        'port': db_parameters['port'],
        'account': db_parameters['account'],
        'schema': db_parameters['schema'],
        'database': db_parameters['database'],
        'protocol': db_parameters['protocol'],
        'timezone': 'UTC',
        'client_session_keep_alive': True,
        'client_session_keep_alive_heartbeat_frequency': 10,
    }
    cnx = snowflake.connector.connect(**config)
    try:
        # The min value of client_session_keep_alive_heartbeat_frequency 
        # is 1/16 of master token validity, so 14400 / 4 /4 => 900
        assert cnx.client_session_keep_alive_heartbeat_frequency == 900
    finally:
        cnx.close()


def test_bad_db(db_parameters):
    """
    Attempts to use a bad DB
    """
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        protocol=db_parameters['protocol'],
        database='baddb',
    )
    assert cnx, 'invald cnx'
    cnx.close()


def test_bogus(db_parameters):
    """
    Attempts to login with invalid user name and password
    NOTE: this takes long time.
    """
    with pytest.raises(DatabaseError):
        snowflake.connector.connect(
            protocol='http',
            user='bogus',
            password='bogus',
            host=db_parameters['host'],
            port=db_parameters['port'],
            account=db_parameters['account'],
        )

    with pytest.raises(DatabaseError):
        snowflake.connector.connect(
            protocol='http',
            user='bogus',
            password='bogus',
            account='testaccount123',
            host=db_parameters['host'],
            port=db_parameters['port'],
            login_timeout=5,
            insecure_mode=True
        )

    with pytest.raises(DatabaseError):
        snowflake.connector.connect(
            protocol='http',
            user='snowman',
            password='',
            account='testaccount123',
            host=db_parameters['host'],
            port=db_parameters['port'],
            login_timeout=5,
        )

    with pytest.raises(ProgrammingError):
        snowflake.connector.connect(
            protocol='http',
            user='',
            password='password',
            account='testaccount123',
            host=db_parameters['host'],
            port=db_parameters['port'],
            login_timeout=5,
        )


def test_invalid_application(db_parameters):
    """
    Invalid application
    """
    with pytest.raises(snowflake.connector.Error):
        snowflake.connector.connect(
            protocol=db_parameters['protocol'],
            user=db_parameters['user'],
            password=db_parameters['password'],
            application='%%%')


def test_valid_application(db_parameters):
    """
    Valid app name
    """
    application = 'Special_Client'
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        application=application,
        protocol=db_parameters['protocol'],
    )
    assert cnx.application == application, "Must be valid application"
    cnx.close()


def test_invalid_default_parameters(db_parameters):
    """
    Invalid database, schema, warehouse and role name
    """
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        protocol=db_parameters['protocol'],
        database='neverexists',
        schema='neverexists',
        warehouse='neverexits',
    )
    assert cnx, "Must be success"

    with pytest.raises(snowflake.connector.DatabaseError):
        # must not success
        snowflake.connector.connect(
            user=db_parameters['user'],
            password=db_parameters['password'],
            host=db_parameters['host'],
            port=db_parameters['port'],
            account=db_parameters['account'],
            protocol=db_parameters['protocol'],
            database='neverexists',
            schema='neverexists',
            validate_default_parameters=True,
        )

    with pytest.raises(snowflake.connector.DatabaseError):
        # must not success
        snowflake.connector.connect(
            user=db_parameters['user'],
            password=db_parameters['password'],
            host=db_parameters['host'],
            port=db_parameters['port'],
            account=db_parameters['account'],
            protocol=db_parameters['protocol'],
            database=db_parameters['database'],
            schema='neverexists',
            validate_default_parameters=True,
        )

    with pytest.raises(snowflake.connector.DatabaseError):
        # must not success
        snowflake.connector.connect(
            user=db_parameters['user'],
            password=db_parameters['password'],
            host=db_parameters['host'],
            port=db_parameters['port'],
            account=db_parameters['account'],
            protocol=db_parameters['protocol'],
            database=db_parameters['database'],
            schema=db_parameters['schema'],
            warehouse='neverexists',
            validate_default_parameters=True,
        )

    # Invalid role name is already validated
    with pytest.raises(snowflake.connector.DatabaseError):
        # must not success
        snowflake.connector.connect(
            user=db_parameters['user'],
            password=db_parameters['password'],
            host=db_parameters['host'],
            port=db_parameters['port'],
            account=db_parameters['account'],
            protocol=db_parameters['protocol'],
            database=db_parameters['database'],
            schema=db_parameters['schema'],
            role='neverexists',
        )


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="The user needs a privilege of create warehouse."
)
def test_drop_create_user(conn_cnx, db_parameters):
    """
    Drops and creates user
    """

    with conn_cnx() as cnx:
        def exe(sql):
            return cnx.cursor().execute(sql)

        exe('use role accountadmin')
        exe('drop user if exists snowdog')
        exe("create user if not exists snowdog identified by 'testdoc'")
        exe("use {0}".format(db_parameters['database']))
        exe("create or replace role snowdog_role")
        exe("grant role snowdog_role to user snowdog")
        exe("grant all on database {0} to role snowdog_role".format(
            db_parameters['database']))
        exe("grant all on schema {0} to role snowdog_role".format(
            db_parameters['schema']))

    with conn_cnx(user='snowdog', password='testdoc') as cnx2:
        def exe(sql):
            return cnx2.cursor().execute(sql)

        exe('use role snowdog_role')
        exe(u"use {0}".format(db_parameters['database']))
        exe(u"use schema {0}".format(db_parameters['schema']))
        exe('create or replace table friends(name varchar(100))')
        exe('drop table friends')
    with conn_cnx() as cnx:
        def exe(sql):
            return cnx.cursor().execute(sql)

        exe('use role accountadmin')
        exe(
            'revoke all on database {0} from role snowdog_role'.format(
                db_parameters['database']))
        exe('drop role snowdog_role')
        exe('drop user if exists snowdog')


@pytest.mark.timeout(15)
def test_invalid_account_timeout():
    with pytest.raises(ForbiddenError):
        snowflake.connector.connect(
            account='bogus',
            user='test',
            password='test',
            login_timeout=5
        )


@pytest.mark.timeout(15)
def test_invalid_port(db_parameters):
    with pytest.raises(OperationalError):
        snowflake.connector.connect(
            protocol='http',
            account='testaccount',
            user=db_parameters['user'],
            password=db_parameters['password'],
            host=db_parameters['host'],
            port=12345,
            login_timeout=5,
        )


@pytest.mark.timeout(15)
def test_invalid_proxy(db_parameters):
    with pytest.raises(OperationalError):
        snowflake.connector.connect(
            protocol='http',
            account='testaccount',
            user=db_parameters['user'],
            password=db_parameters['password'],
            host=db_parameters['host'],
            port=db_parameters['port'],
            login_timeout=5,
            proxy_host='localhost',
            proxy_port='3333'
        )
    # NOTE environment variable is set if the proxy parameter is specified.
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']


@pytest.mark.timeout(15)
def test_eu_connection(tmpdir):
    """
    If region is specified to eu-central-1, the URL will become
    https://testaccount1234.eu-central-1.snowflakecomputing.com/
    NOTE: region is deprecated.
    """
    import os
    os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED"] = "true"
    with pytest.raises(ForbiddenError):
        # must reach Snowflake
        snowflake.connector.connect(
            account='testaccount1234',
            user='testuser',
            password='testpassword',
            region='eu-central-1',
            login_timeout=5,
            ocsp_response_cache_filename=os.path.join(
                str(tmpdir), "test_ocsp_cache.txt")
        )


#@pytest.mark.timeout(15)
def test_us_west_connection(tmpdir):
    """
    region='us-west-2' indicates no region is included in the hostname, i.e.,
    https://testaccount1234.snowflakecomputing.com.
    NOTE: region is deprecated.
    """
    with pytest.raises(ForbiddenError):
        # must reach Snowflake
        snowflake.connector.connect(
            account='testaccount1234',
            user='testuser',
            password='testpassword',
            region='us-west-2',
            login_timeout=5,
        )


@pytest.mark.timeout(60)
def test_privatelink(db_parameters):
    """
    Ensure the OCSP cache server URL is overridden if privatelink
    connection is used.
    """
    try:
        os.environ['SF_OCSP_FAIL_OPEN'] = 'false'
        os.environ['SF_OCSP_DO_RETRY'] = 'false'
        snowflake.connector.connect(
            account='testaccount',
            user='testuser',
            password='testpassword',
            region='eu-central-1.privatelink',
            login_timeout=5,
        )
        pytest.fail("should not make connection")
    except OperationalError:
        ocsp_url = os.getenv('SF_OCSP_RESPONSE_CACHE_SERVER_URL')
        assert ocsp_url is not None, "OCSP URL should not be None"
        assert ocsp_url == "http://ocsp.testaccount.eu-central-1." \
                           "privatelink.snowflakecomputing.com/" \
                           "ocsp_response_cache.json"

    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        database=db_parameters['database'],
        protocol=db_parameters['protocol'],
        timezone='UTC',
    )
    assert cnx, 'invalid cnx'

    ocsp_url = os.getenv('SF_OCSP_RESPONSE_CACHE_SERVER_URL')
    assert ocsp_url is None, "OCSP URL should be None: {0}".format(ocsp_url)
    del os.environ['SF_OCSP_DO_RETRY']
    del os.environ['SF_OCSP_FAIL_OPEN']


def test_disable_request_pooling(db_parameters):
    """
    Creates a connection with client_session_keep_alive parameter.
    """
    config = {
        'user': db_parameters['user'],
        'password': db_parameters['password'],
        'host': db_parameters['host'],
        'port': db_parameters['port'],
        'account': db_parameters['account'],
        'schema': db_parameters['schema'],
        'database': db_parameters['database'],
        'protocol': db_parameters['protocol'],
        'timezone': 'UTC',
        'disable_request_pooling': True
    }
    cnx = snowflake.connector.connect(**config)
    try:
        assert cnx.disable_request_pooling
    finally:
        cnx.close()


def test_privatelink_ocsp_url_creation():
    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    SnowflakeConnection.setup_ocsp_privatelink(APPLICATION_SNOWSQL, hostname)

    ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
    assert ocsp_cache_server == \
        "http://ocsp.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"

    del os.environ['SF_OCSP_RESPONSE_CACHE_SERVER_URL']

    SnowflakeConnection.setup_ocsp_privatelink(CLIENT_NAME, hostname)
    ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
    assert ocsp_cache_server == \
        "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"


def test_privatelink_ocsp_url_multithreaded():
    bucket = queue.Queue()

    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    expectation = "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    thread_obj = []
    for i in range(15):
        thread_obj.append(ExecPrivatelinkThread(bucket, hostname, expectation, CLIENT_NAME))

    for i in range(15):
        thread_obj[i].start()

    fail_flag = False
    for i in range(15):
        thread_obj[i].join()
        exc = bucket.get(block=False)
        if exc != 'Success' and not fail_flag:
            fail_flag = True

    if fail_flag:
        assert False, "OCSP URL was set incorrectly"

    if os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None) is not None:
        del os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"]


def test_privatelink_ocsp_url_multithreaded_snowsql():
    bucket = queue.Queue()

    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    expectation = "http://ocsp.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    thread_obj = []
    for i in range(15):
        thread_obj.append(ExecPrivatelinkThread(bucket, hostname, expectation, APPLICATION_SNOWSQL))

    for i in range(15):
        thread_obj[i].start()

    fail_flag = False
    for i in range(15):
        thread_obj[i].join()
        exc = bucket.get(block=False)
        if exc != 'Success' and not fail_flag:
            fail_flag = True

    if fail_flag:
        assert False, "OCSP URL was set incorrectly"


class ExecPrivatelinkThread(threading.Thread):

    def __init__(self, bucket, hostname, expectation, client_name):
        threading.Thread.__init__(self)
        self.bucket = bucket
        self.hostname = hostname
        self.expectation = expectation
        self.client_name = client_name

    def run(self):
        SnowflakeConnection.setup_ocsp_privatelink(self.client_name, self.hostname)
        ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
        if ocsp_cache_server is not None and ocsp_cache_server !=\
                self.expectation:
            print("Got {0} Expected {1}".format(ocsp_cache_server, self.expectation))
            self.bucket.put("Fail")
        else:
            self.bucket.put("Success")
