#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#
import logging
import os
import queue
import threading
import warnings
from uuid import uuid4

import mock
import pytest

import snowflake.connector
from snowflake.connector import DatabaseError, OperationalError, ProgrammingError
from snowflake.connector.auth_okta import AuthByOkta
from snowflake.connector.connection import SnowflakeConnection
from snowflake.connector.description import CLIENT_NAME
from snowflake.connector.errorcode import (
    ER_CONNECTION_IS_CLOSED,
    ER_FAILED_PROCESSING_PYFORMAT,
    ER_INVALID_VALUE,
    ER_NO_ACCOUNT_NAME,
    ER_NOT_IMPLICITY_SNOWFLAKE_DATATYPE,
)
from snowflake.connector.errors import Error, ForbiddenError
from snowflake.connector.network import APPLICATION_SNOWSQL, ReauthenticationRequest
from snowflake.connector.sqlstate import SQLSTATE_FEATURE_NOT_SUPPORTED

try:  # pragma: no cover
    from parameters import (CONNECTION_PARAMETERS_ADMIN)
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}


def test_basic(conn_testaccount):
    """Basic Connection test."""
    assert conn_testaccount, 'invalid cnx'
    # Test default values
    assert conn_testaccount.session_id


def test_connection_without_schema(db_parameters):
    """Basic Connection test without schema."""
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
    """Basic Connection test without database and schema."""
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
    """Basic Connection test without database."""
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
    """Creates a connection with the config parameter."""
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
    """Creates a connection with client_session_keep_alive parameter."""
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
    """Tests heartbeat setting.

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
    """Tests heartbeat setting with custom frequency.

    Creates a connection with client_session_keep_alive_heartbeat_frequency parameter and set the minimum frequency.
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
    """Attempts to use a bad DB."""
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
    """Attempts to login with invalid user name and password.

    Notes:
        This takes a long time.
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
    """Invalid application name."""
    with pytest.raises(snowflake.connector.Error):
        snowflake.connector.connect(
            protocol=db_parameters['protocol'],
            user=db_parameters['user'],
            password=db_parameters['password'],
            application='%%%')


def test_valid_application(db_parameters):
    """Valid application name."""
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
    """Invalid database, schema, warehouse and role name."""
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
    """Drops and creates user."""
    with conn_cnx() as cnx:
        def exe(sql):
            return cnx.cursor().execute(sql)

        exe('use role accountadmin')
        exe('drop user if exists snowdog')
        exe("create user if not exists snowdog identified by 'testdoc'")
        exe("use {}".format(db_parameters['database']))
        exe("create or replace role snowdog_role")
        exe("grant role snowdog_role to user snowdog")
        exe("grant all on database {} to role snowdog_role".format(
            db_parameters['database']))
        exe("grant all on schema {} to role snowdog_role".format(
            db_parameters['schema']))

    with conn_cnx(user='snowdog', password='testdoc') as cnx2:
        def exe(sql):
            return cnx2.cursor().execute(sql)

        exe('use role snowdog_role')
        exe("use {}".format(db_parameters['database']))
        exe("use schema {}".format(db_parameters['schema']))
        exe('create or replace table friends(name varchar(100))')
        exe('drop table friends')
    with conn_cnx() as cnx:
        def exe(sql):
            return cnx.cursor().execute(sql)

        exe('use role accountadmin')
        exe(
            'revoke all on database {} from role snowdog_role'.format(
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
    """Tests setting custom region.

    If region is specified to eu-central-1, the URL should become
    https://testaccount1234.eu-central-1.snowflakecomputing.com/ .

    Notes:
        Region is deprecated.
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


def test_us_west_connection(tmpdir):
    """Tests default region setting.

    Region='us-west-2' indicates no region is included in the hostname, i.e.,
    https://testaccount1234.snowflakecomputing.com.

    Notes:
        Region is deprecated.
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
    """Ensure the OCSP cache server URL is overridden if privatelink connection is used."""
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
    assert ocsp_url is None, "OCSP URL should be None: {}".format(ocsp_url)
    del os.environ['SF_OCSP_DO_RETRY']
    del os.environ['SF_OCSP_FAIL_OPEN']


def test_disable_request_pooling(db_parameters):
    """Creates a connection with client_session_keep_alive parameter."""
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
        "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"

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
    for _ in range(15):
        thread_obj.append(ExecPrivatelinkThread(bucket, hostname, expectation, CLIENT_NAME))

    for t in thread_obj:
        t.start()

    fail_flag = False
    for t in thread_obj:
        t.join()
        exc = bucket.get(block=False)
        if exc != 'Success' and not fail_flag:
            fail_flag = True

    if fail_flag:
        raise AssertionError()

    if os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None) is not None:
        del os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"]


def test_privatelink_ocsp_url_multithreaded_snowsql():
    bucket = queue.Queue()

    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    expectation = "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    thread_obj = []
    for _ in range(15):
        thread_obj.append(ExecPrivatelinkThread(bucket, hostname, expectation, APPLICATION_SNOWSQL))

    for t in thread_obj:
        t.start()

    fail_flag = False
    for i in range(15):
        thread_obj[i].join()
        exc = bucket.get(block=False)
        if exc != 'Success' and not fail_flag:
            fail_flag = True

    if fail_flag:
        raise AssertionError()


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
            print("Got {} Expected {}".format(ocsp_cache_server, self.expectation))
            self.bucket.put("Fail")
        else:
            self.bucket.put("Success")


def test_another_site(db_parameters):
    import urllib3

    def get(url):
        pool_manager = urllib3.PoolManager()
        res = pool_manager.request('GET', url)
        return res.status

    assert get('https://wikipedia.org') == 200


@pytest.mark.skipolddriver
def test_okta_url(db_parameters):
    orig_authenticator = 'https://someaccount.okta.com/snowflake/oO56fExYCGnfV83/2345'

    def mock_auth(self, auth_instance):
        assert isinstance(auth_instance, AuthByOkta)
        assert self._authenticator == orig_authenticator

    with mock.patch('snowflake.connector.connection.SnowflakeConnection._SnowflakeConnection__authenticate', mock_auth):
        cnx = snowflake.connector.connect(
            user=db_parameters['user'],
            password=db_parameters['password'],
            host=db_parameters['host'],
            port=db_parameters['port'],
            account=db_parameters['account'],
            schema=db_parameters['schema'],
            database=db_parameters['database'],
            protocol=db_parameters['protocol'],
            timezone='UTC',
            authenticator=orig_authenticator,
        )
        assert cnx


@pytest.mark.skipolddriver
def test_use_openssl_only(db_parameters):
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        protocol=db_parameters['protocol'],
        use_openssl_only=True,
    )
    assert cnx
    assert 'SF_USE_OPENSSL_ONLY' in os.environ
    # Note during testing conftest will default this value to False, so if testing this we need to manually clear it
    # Let's test it again, after clearing it
    del os.environ['SF_USE_OPENSSL_ONLY']
    cnx = snowflake.connector.connect(
        user=db_parameters['user'],
        password=db_parameters['password'],
        host=db_parameters['host'],
        port=db_parameters['port'],
        account=db_parameters['account'],
        protocol=db_parameters['protocol'],
        use_openssl_only=True,
    )
    assert cnx
    assert os.environ['SF_USE_OPENSSL_ONLY'] == 'True'


def test_dashed_url(db_parameters):
    """Test whether dashed URLs get created correctly."""
    with mock.patch("snowflake.connector.network.SnowflakeRestful.fetch",
                    return_value={'data': {'token': None,
                                           'masterToken': None},
                                  'success': True}) as mocked_fetch:
        with snowflake.connector.connect(
                user='test-user',
                password='test-password',
                host='test-host',
                port='443',
                account='test-account',
        ) as cnx:
            assert cnx
            cnx.commit = cnx.rollback = lambda: None  # Skip tear down, there's only a mocked rest api
            assert any([c.args[1].startswith('https://test-host:443') for c in mocked_fetch.call_args_list])


def test_dashed_url_account_name(db_parameters):
    """Tests whether dashed URLs get created correctly when no hostname is provided."""
    with mock.patch("snowflake.connector.network.SnowflakeRestful.fetch",
                    return_value={'data': {'token': None,
                                           'masterToken': None},
                                  'success': True}) as mocked_fetch:
        with snowflake.connector.connect(
                user='test-user',
                password='test-password',
                port='443',
                account='test-account',
        ) as cnx:
            assert cnx
            cnx.commit = cnx.rollback = lambda: None  # Skip tear down, there's only a mocked rest api
            assert any([c.args[1].startswith('https://test-account.snowflakecomputing.com:443') for c in mocked_fetch.call_args_list])


@pytest.mark.skipolddriver
@pytest.mark.parametrize('name,value,exc_warn', [
    # Not existing parameter
    ('no_such_parameter', True, UserWarning("'no_such_parameter' is an unknown connection parameter")),
    # Typo in parameter name
    ('applucation', True, UserWarning("'applucation' is an unknown connection parameter, did you mean 'application'?")),
    # Single type error
    ('support_negative_year', "True", UserWarning("'support_negative_year' connection parameter should be of type "
                                                  "'bool', but is a 'str'")),
    # Multiple possible type error
    ('autocommit', "True", UserWarning("'autocommit' connection parameter should be of type "
                                       "'(NoneType, bool)', but is a 'str'")),
])
def test_invalid_connection_parameter(db_parameters, name, value, exc_warn):
    with warnings.catch_warnings(record=True) as w:
        conn_params = {
            'account': db_parameters['account'],
            'user': db_parameters['user'],
            'password': db_parameters['password'],
            'schema': db_parameters['schema'],
            'database': db_parameters['database'],
            'protocol': db_parameters['protocol'],
            'host': db_parameters['host'],
            'port': db_parameters['port'],
            'validate_default_parameters': True,
            name: value
        }
        try:
            conn = snowflake.connector.connect(**conn_params)
            assert getattr(conn, '_' + name) == value
            assert len(w) == 1
            assert str(w[0].message) == str(exc_warn)
        finally:
            conn.close()


def test_invalid_connection_parameters_turned_off(db_parameters):
    """Makes sure parameter checking can be turned off."""
    with warnings.catch_warnings(record=True) as w:
        conn_params = {
            'account': db_parameters['account'],
            'user': db_parameters['user'],
            'password': db_parameters['password'],
            'schema': db_parameters['schema'],
            'database': db_parameters['database'],
            'protocol': db_parameters['protocol'],
            'host': db_parameters['host'],
            'port': db_parameters['port'],
            'validate_default_parameters': False,
            'autocommit': "True",  # Wrong type
            'applucation': "this is a typo or my own variable",  # Wrong name
        }
        try:
            conn = snowflake.connector.connect(**conn_params)
            assert conn._autocommit == conn_params['autocommit']
            assert conn._applucation == conn_params['applucation']
            assert len(w) == 0
        finally:
            conn.close()


def test_invalid_connection_parameters_only_warns(db_parameters):
    """This test supresses warnings to only have warehouse, database and schema checking."""
    with warnings.catch_warnings(record=True) as w:
        conn_params = {
            'account': db_parameters['account'],
            'user': db_parameters['user'],
            'password': db_parameters['password'],
            'schema': db_parameters['schema'],
            'database': db_parameters['database'],
            'protocol': db_parameters['protocol'],
            'host': db_parameters['host'],
            'port': db_parameters['port'],
            'validate_default_parameters': True,
            'autocommit': "True",  # Wrong type
            'applucation': "this is a typo or my own variable",  # Wrong name
        }
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                conn = snowflake.connector.connect(**conn_params)
            assert conn._autocommit == conn_params['autocommit']
            assert conn._applucation == conn_params['applucation']
            assert len(w) == 0
        finally:
            conn.close()


@pytest.mark.skipolddriver
def test_region_deprecation(conn_cnx):
    """Tests whether region raises a deprecation warning."""
    with conn_cnx() as conn:
        with warnings.catch_warnings(record=True) as w:
            conn.region
        assert len(w) == 1
        assert issubclass(w[0].category, PendingDeprecationWarning)
        assert "Region has been deprecated" in str(w[0].message)


def test_invalid_errorhander_error(conn_cnx):
    """Tests if no errorhandler cannot be set."""
    with conn_cnx() as conn:
        with pytest.raises(ProgrammingError, match="None errorhandler is specified"):
            conn.errorhandler = None
        original_handler = conn.errorhandler
        conn.errorhandler = original_handler
        assert conn.errorhandler is original_handler


def test_disable_request_pooling_setter(conn_cnx):
    """Tests whether request pooling can be set successfully."""
    with conn_cnx() as conn:
        original_value = conn.disable_request_pooling
        conn.disable_request_pooling = not original_value
        assert conn.disable_request_pooling == (not original_value)
        conn.disable_request_pooling = original_value
        assert conn.disable_request_pooling == original_value


def test_autocommit_closed_already(conn_cnx):
    """Test if setting autocommit on an already closed connection raised right error."""
    with conn_cnx() as conn:
        pass
    with pytest.raises(DatabaseError, match=r"Connection is closed") as dbe:
        conn.autocommit(True)
        assert dbe.errno == ER_CONNECTION_IS_CLOSED


def test_autocommit_invalid_type(conn_cnx):
    """Tests if setting autocommit on an already closed connection raised right error."""
    with conn_cnx() as conn:
        with pytest.raises(ProgrammingError, match=r"Invalid parameter: True") as dbe:
            conn.autocommit('True')
            assert dbe.errno == ER_INVALID_VALUE


def test_autocommit_unsupported(conn_cnx, caplog):
    """Tests if server-side error is handled correctly when setting autocommit."""
    with conn_cnx() as conn:
        with mock.patch('snowflake.connector.cursor.SnowflakeCursor.execute',
                        side_effect=Error("Test error", sqlstate=SQLSTATE_FEATURE_NOT_SUPPORTED)):
            conn.autocommit(True)
        assert ('snowflake.connector.connection',
                logging.DEBUG,
                "Autocommit feature is not enabled for this connection. Ignored") in caplog.record_tuples


def test_sequence_counter(conn_cnx):
    """Tests whether setting sequence counter and increasing it works as expected."""
    with conn_cnx(sequence_counter=4) as conn:
        assert conn.sequence_counter == 4
        with conn.cursor() as cur:
            assert cur.execute('select 1 ').fetchall() == [(1,)]
        assert conn.sequence_counter == 5


def test_missing_account(conn_cnx):
    """Test whether missing account raises the right exception."""
    with pytest.raises(ProgrammingError, match="Account must be specified") as pe:
        with conn_cnx(account=''):
            pass
        assert pe.errno == ER_NO_ACCOUNT_NAME


@pytest.mark.parametrize('resp', [None, {}])
def test_empty_response(conn_cnx, resp):
    """Tests that cmd_query returns an empty response when empty/no response is recevided from back-end."""
    with conn_cnx() as conn:
        with mock.patch('snowflake.connector.network.SnowflakeRestful.request', return_value=resp):
            assert conn.cmd_query('select 1', 0, uuid4()) == {'data': {}}


@pytest.mark.skipolddriver
def test_authenticate_error(conn_cnx, caplog):
    """Test Reauthenticate error handling while authenticating."""
    mock_auth = mock.MagicMock()
    mock_auth.authenticate.side_effect = ReauthenticationRequest(None)
    with conn_cnx() as conn:
        with pytest.raises(ReauthenticationRequest):
            conn._authenticate(mock_auth)
        assert ('snowflake.connector.connection',
                logging.DEBUG,
                'ID token expired. Reauthenticating...: None') in caplog.record_tuples


def test_process_qmark_params_error(conn_cnx):
    """Tests errors thrown in _process_params_qmarks."""
    with conn_cnx() as conn:
        with pytest.raises(ProgrammingError, match='Binding parameters must be a list: invalid input') as pe:
            conn._process_params_qmarks('invalid input')
            assert pe.errno == ER_FAILED_PROCESSING_PYFORMAT
        with pytest.raises(ProgrammingError,
                           match="Binding parameters must be a list where one element is a single value or "
                                 "a pair of Snowflake datatype and a value") as pe:
            conn._process_params_qmarks(((1, 2, 3),))
            assert pe.errno == ER_FAILED_PROCESSING_PYFORMAT
    with pytest.raises(ProgrammingError,
                       match=r"Python data type \[magicmock\] cannot be automatically mapped to Snowflake") as pe:
        conn._process_params_qmarks([mock.MagicMock()])
        assert pe.errno == ER_NOT_IMPLICITY_SNOWFLAKE_DATATYPE


@pytest.mark.skipolddriver
def test_process_param_dict_error(conn_cnx):
    """Tests whether exceptions in __process_params_dict are handled correctly."""
    with conn_cnx() as conn:
        with pytest.raises(ProgrammingError, match="Failed processing pyformat-parameters: test") as pe:
            with mock.patch('snowflake.connector.converter.SnowflakeConverter.to_snowflake',
                            side_effect=Exception('test')):
                conn._process_params({'asd': 'something'})
            assert pe.errno == ER_FAILED_PROCESSING_PYFORMAT
