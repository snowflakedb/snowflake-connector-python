#!/usr/bin/env python
from __future__ import annotations

import gc
import logging
import os
import pathlib
import queue
import stat
import tempfile
import threading
import warnings
import weakref
from unittest import mock
from uuid import uuid4

import pytest

import snowflake.connector
from snowflake.connector import DatabaseError, OperationalError, ProgrammingError
from snowflake.connector.connection import (
    DEFAULT_CLIENT_PREFETCH_THREADS,
    SnowflakeConnection,
)
from snowflake.connector.description import CLIENT_NAME
from snowflake.connector.errorcode import (
    ER_CONNECTION_IS_CLOSED,
    ER_FAILED_PROCESSING_PYFORMAT,
    ER_INVALID_VALUE,
    ER_NO_ACCOUNT_NAME,
    ER_NOT_IMPLICITY_SNOWFLAKE_DATATYPE,
)
from snowflake.connector.errors import Error
from snowflake.connector.network import APPLICATION_SNOWSQL, ReauthenticationRequest
from snowflake.connector.sqlstate import SQLSTATE_FEATURE_NOT_SUPPORTED
from snowflake.connector.telemetry import TelemetryField

from ..randomize import random_string
from .conftest import RUNNING_ON_GH, create_connection

try:  # pragma: no cover
    from ..parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}

try:  # pragma: no cover
    from snowflake.connector.auth import AuthByOkta, AuthByPlugin
except ImportError:
    from snowflake.connector.auth_by_plugin import AuthByPlugin
    from snowflake.connector.auth_okta import AuthByOkta

try:
    from snowflake.connector.errorcode import ER_FAILED_PROCESSING_QMARK
except ImportError:  # Keep olddrivertest from breaking
    ER_FAILED_PROCESSING_QMARK = 252012

try:
    from snowflake.connector.errors import HttpError
except ImportError:
    pass


def test_basic(conn_testaccount):
    """Basic Connection test."""
    assert conn_testaccount, "invalid cnx"
    # Test default values
    assert conn_testaccount.session_id


def test_connection_without_schema(db_parameters):
    """Basic Connection test without schema."""
    cnx = snowflake.connector.connect(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        database=db_parameters["database"],
        protocol=db_parameters["protocol"],
        timezone="UTC",
    )
    assert cnx, "invalid cnx"
    cnx.close()


def test_connection_without_database_schema(db_parameters):
    """Basic Connection test without database and schema."""
    cnx = snowflake.connector.connect(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        protocol=db_parameters["protocol"],
        timezone="UTC",
    )
    assert cnx, "invalid cnx"
    cnx.close()


def test_connection_without_database2(db_parameters):
    """Basic Connection test without database."""
    cnx = snowflake.connector.connect(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        schema=db_parameters["schema"],
        protocol=db_parameters["protocol"],
        timezone="UTC",
    )
    assert cnx, "invalid cnx"
    cnx.close()


def test_with_config(db_parameters):
    """Creates a connection with the config parameter."""
    from ..conftest import get_server_parameter_value

    config = {
        "user": db_parameters["user"],
        "password": db_parameters["password"],
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "account": db_parameters["account"],
        "schema": db_parameters["schema"],
        "database": db_parameters["database"],
        "protocol": db_parameters["protocol"],
        "timezone": "UTC",
    }
    cnx = snowflake.connector.connect(**config)
    try:
        assert cnx, "invalid cnx"

        # Check what the server default is to make test environment-aware
        server_default_str = get_server_parameter_value(
            cnx, "CLIENT_SESSION_KEEP_ALIVE"
        )
        if server_default_str:
            server_default = server_default_str.lower() == "true"
            # Test that connection respects server default when not explicitly set
            assert (
                cnx.client_session_keep_alive == server_default
            ), f"Expected client_session_keep_alive={server_default} (server default), got {cnx.client_session_keep_alive}"
        else:
            # Fallback: if we can't determine server default, expect False
            assert (
                not cnx.client_session_keep_alive
            ), "Expected client_session_keep_alive=False when server default unknown"
    finally:
        cnx.close()


@pytest.mark.skipolddriver
def test_with_tokens(conn_cnx, db_parameters):
    """Creates a connection using session and master token."""
    try:
        with conn_cnx(
            timezone="UTC",
        ) as initial_cnx:
            assert initial_cnx, "invalid initial cnx"
            master_token = initial_cnx.rest._master_token
            session_token = initial_cnx.rest._token
            with snowflake.connector.connect(
                account=db_parameters["account"],
                host=db_parameters["host"],
                port=db_parameters["port"],
                protocol=db_parameters["protocol"],
                session_token=session_token,
                master_token=master_token,
            ) as token_cnx:
                assert token_cnx, "invalid second cnx"
    except Exception:
        # This is my way of guaranteeing that we'll not expose the
        # sensitive information that this test needs to handle.
        # db_parameter contains passwords.
        pytest.fail("something failed", pytrace=False)


@pytest.mark.skipolddriver
def test_with_tokens_expired(conn_cnx, db_parameters):
    """Creates a connection using session and master token."""
    try:
        with conn_cnx(
            timezone="UTC",
        ) as initial_cnx:
            assert initial_cnx, "invalid initial cnx"
            master_token = initial_cnx._rest._master_token
            session_token = initial_cnx._rest._token

        with pytest.raises(ProgrammingError):
            token_cnx = snowflake.connector.connect(
                account=db_parameters["account"],
                host=db_parameters["host"],
                port=db_parameters["port"],
                protocol=db_parameters["protocol"],
                session_token=session_token,
                master_token=master_token,
            )
            token_cnx.close()
    except Exception:
        # This is my way of guaranteeing that we'll not expose the
        # sensitive information that this test needs to handle.
        # db_parameter contains passwords.
        pytest.fail("something failed", pytrace=False)


def test_keep_alive_true(db_parameters):
    """Creates a connection with client_session_keep_alive parameter."""
    config = {
        "user": db_parameters["user"],
        "password": db_parameters["password"],
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "account": db_parameters["account"],
        "schema": db_parameters["schema"],
        "database": db_parameters["database"],
        "protocol": db_parameters["protocol"],
        "timezone": "UTC",
        "client_session_keep_alive": True,
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
        "user": db_parameters["user"],
        "password": db_parameters["password"],
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "account": db_parameters["account"],
        "schema": db_parameters["schema"],
        "database": db_parameters["database"],
        "protocol": db_parameters["protocol"],
        "timezone": "UTC",
        "client_session_keep_alive": True,
        "client_session_keep_alive_heartbeat_frequency": 1000,
    }
    cnx = snowflake.connector.connect(**config)
    try:
        assert cnx.client_session_keep_alive_heartbeat_frequency == 1000
    finally:
        cnx.close()


@pytest.mark.skipolddriver
def test_keep_alive_heartbeat_frequency_min(db_parameters):
    """Tests heartbeat setting with custom frequency.

    Creates a connection with client_session_keep_alive_heartbeat_frequency parameter and set the minimum frequency.
    Also if a value comes as string, should be properly converted to int and not fail assertion.
    """
    config = {
        "user": db_parameters["user"],
        "password": db_parameters["password"],
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "account": db_parameters["account"],
        "schema": db_parameters["schema"],
        "database": db_parameters["database"],
        "protocol": db_parameters["protocol"],
        "timezone": "UTC",
        "client_session_keep_alive": True,
        "client_session_keep_alive_heartbeat_frequency": "10",
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
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        protocol=db_parameters["protocol"],
        database="baddb",
    )
    assert cnx, "invald cnx"
    cnx.close()


def test_with_string_login_timeout(db_parameters):
    """Test that login_timeout when passed as string does not raise TypeError.

    In this test, we pass bad login credentials to raise error and trigger login
    timeout calculation. We expect to see DatabaseError instead of TypeError that
    comes from str - int arithmetic.
    """
    with pytest.raises(DatabaseError):
        snowflake.connector.connect(
            protocol="http",
            user="bogus",
            password="bogus",
            host=db_parameters["host"],
            port=db_parameters["port"],
            account=db_parameters["account"],
            login_timeout="5",
        )


@pytest.mark.skip(reason="the test is affected by CI breaking change")
def test_bogus(db_parameters):
    """Attempts to login with invalid user name and password.

    Notes:
        This takes a long time.
    """
    with pytest.raises(DatabaseError):
        snowflake.connector.connect(
            protocol="http",
            user="bogus",
            password="bogus",
            host=db_parameters["host"],
            port=db_parameters["port"],
            account=db_parameters["account"],
            login_timeout=5,
        )

    with pytest.raises(DatabaseError):
        snowflake.connector.connect(
            protocol="http",
            user="bogus",
            password="bogus",
            account="testaccount123",
            host=db_parameters["host"],
            port=db_parameters["port"],
            login_timeout=5,
            disable_ocsp_checks=True,
        )

    with pytest.raises(DatabaseError):
        snowflake.connector.connect(
            protocol="http",
            user="snowman",
            password="",
            account="testaccount123",
            host=db_parameters["host"],
            port=db_parameters["port"],
            login_timeout=5,
        )

    with pytest.raises(ProgrammingError):
        snowflake.connector.connect(
            protocol="http",
            user="",
            password="password",
            account="testaccount123",
            host=db_parameters["host"],
            port=db_parameters["port"],
            login_timeout=5,
        )


def test_invalid_application(db_parameters):
    """Invalid application name."""
    with pytest.raises(snowflake.connector.Error):
        snowflake.connector.connect(
            protocol=db_parameters["protocol"],
            user=db_parameters["user"],
            password=db_parameters["password"],
            application="%%%",
        )


def test_valid_application(db_parameters):
    """Valid application name."""
    application = "Special_Client"
    cnx = snowflake.connector.connect(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        application=application,
        protocol=db_parameters["protocol"],
    )
    assert cnx.application == application, "Must be valid application"
    cnx.close()


def test_invalid_default_parameters(db_parameters):
    """Invalid database, schema, warehouse and role name."""
    cnx = snowflake.connector.connect(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        protocol=db_parameters["protocol"],
        database="neverexists",
        schema="neverexists",
        warehouse="neverexits",
    )
    assert cnx, "Must be success"

    with pytest.raises(snowflake.connector.DatabaseError):
        # must not success
        snowflake.connector.connect(
            user=db_parameters["user"],
            password=db_parameters["password"],
            host=db_parameters["host"],
            port=db_parameters["port"],
            account=db_parameters["account"],
            protocol=db_parameters["protocol"],
            database="neverexists",
            schema="neverexists",
            validate_default_parameters=True,
        )

    with pytest.raises(snowflake.connector.DatabaseError):
        # must not success
        snowflake.connector.connect(
            user=db_parameters["user"],
            password=db_parameters["password"],
            host=db_parameters["host"],
            port=db_parameters["port"],
            account=db_parameters["account"],
            protocol=db_parameters["protocol"],
            database=db_parameters["database"],
            schema="neverexists",
            validate_default_parameters=True,
        )

    with pytest.raises(snowflake.connector.DatabaseError):
        # must not success
        snowflake.connector.connect(
            user=db_parameters["user"],
            password=db_parameters["password"],
            host=db_parameters["host"],
            port=db_parameters["port"],
            account=db_parameters["account"],
            protocol=db_parameters["protocol"],
            database=db_parameters["database"],
            schema=db_parameters["schema"],
            warehouse="neverexists",
            validate_default_parameters=True,
        )

    # Invalid role name is already validated
    with pytest.raises(snowflake.connector.DatabaseError):
        # must not success
        snowflake.connector.connect(
            user=db_parameters["user"],
            password=db_parameters["password"],
            host=db_parameters["host"],
            port=db_parameters["port"],
            account=db_parameters["account"],
            protocol=db_parameters["protocol"],
            database=db_parameters["database"],
            schema=db_parameters["schema"],
            role="neverexists",
        )


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="The user needs a privilege of create warehouse.",
)
def test_drop_create_user(conn_cnx, db_parameters):
    """Drops and creates user."""
    with conn_cnx() as cnx:

        def exe(sql):
            return cnx.cursor().execute(sql)

        exe("use role accountadmin")
        exe("drop user if exists snowdog")
        exe("create user if not exists snowdog identified by 'testdoc'")
        exe("use {}".format(db_parameters["database"]))
        exe("create or replace role snowdog_role")
        exe("grant role snowdog_role to user snowdog")
        try:
            # This statement will be partially executed because REFERENCE_USAGE
            # will not be granted.
            exe(
                "grant all on database {} to role snowdog_role".format(
                    db_parameters["database"]
                )
            )
        except ProgrammingError as error:
            err_str = (
                "Grant partially executed: privileges [REFERENCE_USAGE] not granted."
            )
            assert 3011 == error.errno
            assert error.msg.find(err_str) != -1
        exe(
            "grant all on schema {} to role snowdog_role".format(
                db_parameters["schema"]
            )
        )

    with conn_cnx(user="snowdog", password="testdoc") as cnx2:

        def exe(sql):
            return cnx2.cursor().execute(sql)

        exe("use role snowdog_role")
        exe("use {}".format(db_parameters["database"]))
        exe("use schema {}".format(db_parameters["schema"]))
        exe("create or replace table friends(name varchar(100))")
        exe("drop table friends")
    with conn_cnx() as cnx:

        def exe(sql):
            return cnx.cursor().execute(sql)

        exe("use role accountadmin")
        exe(
            "revoke all on database {} from role snowdog_role".format(
                db_parameters["database"]
            )
        )
        exe("drop role snowdog_role")
        exe("drop user if exists snowdog")


@pytest.mark.timeout(15)
@pytest.mark.skipolddriver
def test_invalid_account_timeout():
    with pytest.raises(HttpError):
        snowflake.connector.connect(
            account="bogus", user="test", password="test", login_timeout=5
        )


@pytest.mark.timeout(15)
def test_invalid_proxy(db_parameters):
    with pytest.raises(OperationalError):
        snowflake.connector.connect(
            protocol="http",
            account="testaccount",
            user=db_parameters["user"],
            password=db_parameters["password"],
            host=db_parameters["host"],
            port=db_parameters["port"],
            login_timeout=5,
            proxy_host="localhost",
            proxy_port="3333",
        )
    # NOTE environment variable is set if the proxy parameter is specified.
    del os.environ["HTTP_PROXY"]
    del os.environ["HTTPS_PROXY"]


@pytest.mark.timeout(15)
@pytest.mark.skipolddriver
def test_eu_connection(tmpdir):
    """Tests setting custom region.

    If region is specified to eu-central-1, the URL should become
    https://testaccount1234.eu-central-1.snowflakecomputing.com/ .

    Notes:
        Region is deprecated.
    """
    import os

    os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED"] = "true"
    with pytest.raises(HttpError):
        # must reach Snowflake
        snowflake.connector.connect(
            account="testaccount1234",
            user="testuser",
            password="testpassword",
            region="eu-central-1",
            login_timeout=5,
            ocsp_response_cache_filename=os.path.join(
                str(tmpdir), "test_ocsp_cache.txt"
            ),
        )


@pytest.mark.skipolddriver
def test_us_west_connection(tmpdir):
    """Tests default region setting.

    Region='us-west-2' indicates no region is included in the hostname, i.e.,
    https://testaccount1234.snowflakecomputing.com.

    Notes:
        Region is deprecated.
    """
    with pytest.raises(HttpError):
        # must reach Snowflake
        snowflake.connector.connect(
            account="testaccount1234",
            user="testuser",
            password="testpassword",
            region="us-west-2",
            login_timeout=5,
        )


@pytest.mark.timeout(60)
def test_privatelink(db_parameters):
    """Ensure the OCSP cache server URL is overridden if privatelink connection is used."""
    try:
        os.environ["SF_OCSP_FAIL_OPEN"] = "false"
        os.environ["SF_OCSP_DO_RETRY"] = "false"
        snowflake.connector.connect(
            account="testaccount",
            user="testuser",
            password="testpassword",
            region="eu-central-1.privatelink",
            login_timeout=5,
        )
        pytest.fail("should not make connection")
    except OperationalError:
        ocsp_url = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL")
        assert ocsp_url is not None, "OCSP URL should not be None"
        assert (
            ocsp_url == "http://ocsp.testaccount.eu-central-1."
            "privatelink.snowflakecomputing.com/"
            "ocsp_response_cache.json"
        )

    cnx = snowflake.connector.connect(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        database=db_parameters["database"],
        protocol=db_parameters["protocol"],
        timezone="UTC",
    )
    assert cnx, "invalid cnx"

    ocsp_url = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL")
    assert ocsp_url is None, f"OCSP URL should be None: {ocsp_url}"
    del os.environ["SF_OCSP_DO_RETRY"]
    del os.environ["SF_OCSP_FAIL_OPEN"]


def test_disable_request_pooling(db_parameters):
    """Creates a connection with client_session_keep_alive parameter."""
    config = {
        "user": db_parameters["user"],
        "password": db_parameters["password"],
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "account": db_parameters["account"],
        "schema": db_parameters["schema"],
        "database": db_parameters["database"],
        "protocol": db_parameters["protocol"],
        "timezone": "UTC",
        "disable_request_pooling": True,
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
    assert (
        ocsp_cache_server
        == "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    )

    del os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"]

    SnowflakeConnection.setup_ocsp_privatelink(CLIENT_NAME, hostname)
    ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
    assert (
        ocsp_cache_server
        == "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    )


@pytest.mark.skipolddriver
def test_uppercase_privatelink_ocsp_url_creation():
    account = "TESTACCOUNT.US-EAST-1.PRIVATELINK"
    hostname = account + ".snowflakecomputing.com"

    SnowflakeConnection.setup_ocsp_privatelink(CLIENT_NAME, hostname)
    ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
    assert (
        ocsp_cache_server
        == "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    )


def test_privatelink_ocsp_url_multithreaded():
    bucket = queue.Queue()

    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    expectation = "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    thread_obj = []
    for _ in range(15):
        thread_obj.append(
            ExecPrivatelinkThread(bucket, hostname, expectation, CLIENT_NAME)
        )

    for t in thread_obj:
        t.start()

    fail_flag = False
    for t in thread_obj:
        t.join()
        exc = bucket.get(block=False)
        if exc != "Success" and not fail_flag:
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
        thread_obj.append(
            ExecPrivatelinkThread(bucket, hostname, expectation, APPLICATION_SNOWSQL)
        )

    for t in thread_obj:
        t.start()

    fail_flag = False
    for i in range(15):
        thread_obj[i].join()
        exc = bucket.get(block=False)
        if exc != "Success" and not fail_flag:
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
        if ocsp_cache_server is not None and ocsp_cache_server != self.expectation:
            print(f"Got {ocsp_cache_server} Expected {self.expectation}")
            self.bucket.put("Fail")
        else:
            self.bucket.put("Success")


@pytest.mark.skipolddriver
def test_okta_url(conn_cnx):
    orig_authenticator = "https://someaccount.okta.com/snowflake/oO56fExYCGnfV83/2345"

    def mock_auth(self, auth_instance):
        assert isinstance(auth_instance, AuthByOkta)
        assert self._authenticator == orig_authenticator

    with mock.patch(
        "snowflake.connector.connection.SnowflakeConnection._authenticate",
        mock_auth,
    ):
        cnx = conn_cnx(
            timezone="UTC",
            authenticator=orig_authenticator,
        )
        assert cnx


def test_dashed_url(db_parameters):
    """Test whether dashed URLs get created correctly."""
    with mock.patch(
        "snowflake.connector.network.SnowflakeRestful.fetch",
        return_value={"data": {"token": None, "masterToken": None}, "success": True},
    ) as mocked_fetch:
        with snowflake.connector.connect(
            user="test-user",
            password="test-password",
            host="test-host",
            port="443",
            account="test-account",
        ) as cnx:
            assert cnx
            cnx.commit = cnx.rollback = (
                lambda: None
            )  # Skip tear down, there's only a mocked rest api
            assert any(
                [
                    c[0][1].startswith("https://test-host:443")
                    for c in mocked_fetch.call_args_list
                ]
            )


def test_dashed_url_account_name(db_parameters):
    """Tests whether dashed URLs get created correctly when no hostname is provided."""
    with mock.patch(
        "snowflake.connector.network.SnowflakeRestful.fetch",
        return_value={"data": {"token": None, "masterToken": None}, "success": True},
    ) as mocked_fetch:
        with snowflake.connector.connect(
            user="test-user",
            password="test-password",
            port="443",
            account="test-account",
        ) as cnx:
            assert cnx
            cnx.commit = cnx.rollback = (
                lambda: None
            )  # Skip tear down, there's only a mocked rest api
            assert any(
                [
                    c[0][1].startswith(
                        "https://test-account.snowflakecomputing.com:443"
                    )
                    for c in mocked_fetch.call_args_list
                ]
            )


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "name,value,exc_warn",
    [
        # Not existing parameter
        (
            "no_such_parameter",
            True,
            UserWarning("'no_such_parameter' is an unknown connection parameter"),
        ),
        # Typo in parameter name
        (
            "applucation",
            True,
            UserWarning(
                "'applucation' is an unknown connection parameter, did you mean 'application'?"
            ),
        ),
        # Single type error
        (
            "support_negative_year",
            "True",
            UserWarning(
                "'support_negative_year' connection parameter should be of type "
                "'bool', but is a 'str'"
            ),
        ),
        # Multiple possible type error
        (
            "autocommit",
            "True",
            UserWarning(
                "'autocommit' connection parameter should be of type "
                "'(NoneType, bool)', but is a 'str'"
            ),
        ),
    ],
)
def test_invalid_connection_parameter(db_parameters, name, value, exc_warn):
    with warnings.catch_warnings(record=True) as w:
        conn_params = {
            "account": db_parameters["account"],
            "user": db_parameters["user"],
            "password": db_parameters["password"],
            "schema": db_parameters["schema"],
            "database": db_parameters["database"],
            "protocol": db_parameters["protocol"],
            "host": db_parameters["host"],
            "port": db_parameters["port"],
            "validate_default_parameters": True,
            name: value,
        }
        try:
            conn = snowflake.connector.connect(**conn_params)
            assert getattr(conn, "_" + name) == value
            # TODO: SNOW-2114216 remove filtering once the root cause for deprecation warning is fixed
            # Filter out the deprecation warning
            filtered_w = [
                warning for warning in w if warning.category != DeprecationWarning
            ]
            assert len(filtered_w) == 1
            assert str(filtered_w[0].message) == str(exc_warn)
        finally:
            conn.close()


def test_invalid_connection_parameters_turned_off(db_parameters):
    """Makes sure parameter checking can be turned off."""
    with warnings.catch_warnings(record=True) as w:
        conn_params = {
            "account": db_parameters["account"],
            "user": db_parameters["user"],
            "password": db_parameters["password"],
            "schema": db_parameters["schema"],
            "database": db_parameters["database"],
            "protocol": db_parameters["protocol"],
            "host": db_parameters["host"],
            "port": db_parameters["port"],
            "validate_default_parameters": False,
            "autocommit": "True",  # Wrong type
            "applucation": "this is a typo or my own variable",  # Wrong name
        }
        try:
            conn = snowflake.connector.connect(**conn_params)
            assert conn._autocommit == conn_params["autocommit"]
            assert conn._applucation == conn_params["applucation"]
            # TODO: SNOW-2114216 remove filtering once the root cause for deprecation warning is fixed
            # Filter out the deprecation warning
            filtered_w = [
                warning for warning in w if warning.category != DeprecationWarning
            ]
            assert len(filtered_w) == 0
        finally:
            conn.close()


def test_invalid_connection_parameters_only_warns(db_parameters):
    """This test supresses warnings to only have warehouse, database and schema checking."""
    with warnings.catch_warnings(record=True) as w:
        conn_params = {
            "account": db_parameters["account"],
            "user": db_parameters["user"],
            "password": db_parameters["password"],
            "schema": db_parameters["schema"],
            "database": db_parameters["database"],
            "protocol": db_parameters["protocol"],
            "host": db_parameters["host"],
            "port": db_parameters["port"],
            "validate_default_parameters": True,
            "autocommit": "True",  # Wrong type
            "applucation": "this is a typo or my own variable",  # Wrong name
        }
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                conn = snowflake.connector.connect(**conn_params)
            assert conn._autocommit == conn_params["autocommit"]
            assert conn._applucation == conn_params["applucation"]
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
            conn.autocommit("True")
            assert dbe.errno == ER_INVALID_VALUE


def test_autocommit_unsupported(conn_cnx, caplog):
    """Tests if server-side error is handled correctly when setting autocommit."""
    with conn_cnx() as conn:
        caplog.set_level(logging.DEBUG, "snowflake.connector")
        with mock.patch(
            "snowflake.connector.cursor.SnowflakeCursor.execute",
            side_effect=Error("Test error", sqlstate=SQLSTATE_FEATURE_NOT_SUPPORTED),
        ):
            conn.autocommit(True)
        assert (
            "snowflake.connector.connection",
            logging.DEBUG,
            "Autocommit feature is not enabled for this connection. Ignored",
        ) in caplog.record_tuples


def test_sequence_counter(conn_cnx):
    """Tests whether setting sequence counter and increasing it works as expected."""
    with conn_cnx(sequence_counter=4) as conn:
        assert conn.sequence_counter == 4
        with conn.cursor() as cur:
            assert cur.execute("select 1 ").fetchall() == [(1,)]
        assert conn.sequence_counter == 5


def test_missing_account(conn_cnx):
    """Test whether missing account raises the right exception."""
    with pytest.raises(ProgrammingError, match="Account must be specified") as pe:
        with conn_cnx(account=""):
            pass
        assert pe.errno == ER_NO_ACCOUNT_NAME


@pytest.mark.parametrize("resp", [None, {}])
def test_empty_response(conn_cnx, resp):
    """Tests that cmd_query returns an empty response when empty/no response is recevided from back-end."""
    with conn_cnx() as conn:
        with mock.patch(
            "snowflake.connector.network.SnowflakeRestful.request", return_value=resp
        ):
            assert conn.cmd_query("select 1", 0, uuid4()) == {"data": {}}


@pytest.mark.skipolddriver
def test_authenticate_error(conn_cnx, caplog):
    """Test Reauthenticate error handling while authenticating."""
    # The docs say unsafe should make this test work, but
    # it doesn't seem to work on MagicMock
    mock_auth = mock.Mock(spec=AuthByPlugin, unsafe=True)
    mock_auth.prepare.return_value = mock_auth
    mock_auth.update_body.side_effect = ReauthenticationRequest(None)
    mock_auth._retry_ctx = mock.MagicMock()
    with conn_cnx() as conn:
        caplog.set_level(logging.DEBUG, "snowflake.connector")
        with pytest.raises(ReauthenticationRequest):
            conn.authenticate_with_retry(mock_auth)
        assert (
            "snowflake.connector.connection",
            logging.DEBUG,
            "ID token expired. Reauthenticating...: None",
        ) in caplog.record_tuples


@pytest.mark.skipolddriver
def test_process_qmark_params_error(conn_cnx):
    """Tests errors thrown in _process_params_qmarks."""
    sql = "select 1;"
    with conn_cnx(paramstyle="qmark") as conn:
        with conn.cursor() as cur:
            with pytest.raises(
                ProgrammingError,
                match="Binding parameters must be a list: invalid input",
            ) as pe:
                cur.execute(sql, params="invalid input")
            assert pe.value.errno == ER_FAILED_PROCESSING_PYFORMAT
            with pytest.raises(
                ProgrammingError,
                match="Binding parameters must be a list where one element is a single "
                "value or a pair of Snowflake datatype and a value",
            ) as pe:
                cur.execute(
                    sql,
                    params=(
                        (
                            1,
                            2,
                            3,
                        ),
                    ),
                )
            assert pe.value.errno == ER_FAILED_PROCESSING_QMARK
            with pytest.raises(
                ProgrammingError,
                match=r"Python data type \[magicmock\] cannot be automatically mapped "
                r"to Snowflake",
            ) as pe:
                cur.execute(sql, params=[mock.MagicMock()])
            assert pe.value.errno == ER_NOT_IMPLICITY_SNOWFLAKE_DATATYPE


@pytest.mark.skipolddriver
def test_process_param_dict_error(conn_cnx):
    """Tests whether exceptions in __process_params_dict are handled correctly."""
    with conn_cnx() as conn:
        with pytest.raises(
            ProgrammingError, match="Failed processing pyformat-parameters: test"
        ) as pe:
            with mock.patch(
                "snowflake.connector.converter.SnowflakeConverter.to_snowflake",
                side_effect=Exception("test"),
            ):
                conn._process_params_pyformat({"asd": "something"})
            assert pe.errno == ER_FAILED_PROCESSING_PYFORMAT


@pytest.mark.skipolddriver
def test_process_param_error(conn_cnx):
    """Tests whether exceptions in __process_params_dict are handled correctly."""
    with conn_cnx() as conn:
        with pytest.raises(
            ProgrammingError, match="Failed processing pyformat-parameters; test"
        ) as pe:
            with mock.patch(
                "snowflake.connector.converter.SnowflakeConverter.to_snowflake",
                side_effect=Exception("test"),
            ):
                conn._process_params_pyformat(mock.Mock())
            assert pe.errno == ER_FAILED_PROCESSING_PYFORMAT


@pytest.mark.parametrize(
    "auto_commit", [pytest.param(True, marks=pytest.mark.skipolddriver), False]
)
def test_autocommit(conn_cnx, db_parameters, auto_commit):
    conn = snowflake.connector.connect(**db_parameters)
    with mock.patch.object(conn, "commit") as mocked_commit:
        with conn:
            with conn.cursor() as cur:
                cur.execute(f"alter session set autocommit = {auto_commit}")
    if auto_commit:
        assert not mocked_commit.called
    else:
        assert mocked_commit.called


@pytest.mark.skipolddriver
def test_client_prefetch_threads_setting(conn_cnx):
    """Tests whether client_prefetch_threads updated and is propagated to result set."""
    with conn_cnx() as conn:
        assert conn.client_prefetch_threads == DEFAULT_CLIENT_PREFETCH_THREADS
        new_thread_count = conn.client_prefetch_threads + 1
        with conn.cursor() as cur:
            cur.execute(f"alter session set client_prefetch_threads={new_thread_count}")
            assert cur._result_set.prefetch_thread_num == new_thread_count
        assert conn.client_prefetch_threads == new_thread_count


@pytest.mark.skipolddriver
def test_client_fetch_threads_setting(conn_cnx):
    """Tests whether client_fetch_threads is None by default and setting the parameter has effect."""
    with conn_cnx() as conn:
        assert conn.client_fetch_threads is None
        conn.client_fetch_threads = 32
        assert conn.client_fetch_threads == 32


@pytest.mark.external
def test_client_failover_connection_url(conn_cnx):
    with conn_cnx("client_failover") as conn:
        with conn.cursor() as cur:
            assert cur.execute("select 1;").fetchall() == [
                (1,),
            ]


def test_connection_gc(conn_cnx):
    """This test makes sure that a heartbeat thread doesn't prevent garbage collection of SnowflakeConnection."""
    conn = conn_cnx(client_session_keep_alive=True).__enter__()
    conn_wref = weakref.ref(conn)
    del conn
    gc.collect()
    assert conn_wref() is None


@pytest.mark.skipolddriver
def test_connection_cant_be_reused(conn_cnx):
    row_count = 50_000
    with conn_cnx() as conn:
        cursors = conn.execute_string(
            f"select seq4() as n from table(generator(rowcount => {row_count}));"
        )
        assert len(cursors[0]._result_set.batches) > 1  # We need to have remote results
    assert list(cursors[0])


@pytest.mark.external
@pytest.mark.skipolddriver
def test_ocsp_cache_working(conn_cnx):
    """Verifies that the OCSP cache is functioning.

    The only way we can verify this is that the number of hits and misses increase.
    """
    from snowflake.connector.ocsp_snowflake import OCSP_RESPONSE_VALIDATION_CACHE

    original_count = (
        OCSP_RESPONSE_VALIDATION_CACHE.telemetry["hit"]
        + OCSP_RESPONSE_VALIDATION_CACHE.telemetry["miss"]
    )
    with conn_cnx() as cnx:
        assert cnx
    assert (
        OCSP_RESPONSE_VALIDATION_CACHE.telemetry["hit"]
        + OCSP_RESPONSE_VALIDATION_CACHE.telemetry["miss"]
        > original_count
    )


@pytest.mark.skipolddriver
def test_imported_packages_telemetry(conn_cnx, capture_sf_telemetry, db_parameters):
    # these imports are not used but for testing
    import html.parser  # noqa: F401
    import json  # noqa: F401
    import multiprocessing as mp  # noqa: F401
    from datetime import date  # noqa: F401
    from math import sqrt  # noqa: F401

    def check_packages(message: str, expected_packages: list[str]) -> bool:
        return (
            all([package in message for package in expected_packages])
            and "__main__" not in message
        )

    packages = [
        "pytest",
        "unittest",
        "json",
        "multiprocessing",
        "html",
        "datetime",
        "math",
    ]

    with conn_cnx() as conn, capture_sf_telemetry.patch_connection(
        conn, False
    ) as telemetry_test:
        conn._log_telemetry_imported_packages()
        assert len(telemetry_test.records) > 0
        assert any(
            [
                t.message[TelemetryField.KEY_TYPE.value]
                == TelemetryField.IMPORTED_PACKAGES.value
                and CLIENT_NAME == t.message[TelemetryField.KEY_SOURCE.value]
                and check_packages(t.message["value"], packages)
                for t in telemetry_test.records
            ]
        )

    # test different application
    new_application_name = "PythonSnowpark"
    config = {
        "user": db_parameters["user"],
        "password": db_parameters["password"],
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "account": db_parameters["account"],
        "schema": db_parameters["schema"],
        "database": db_parameters["database"],
        "protocol": db_parameters["protocol"],
        "timezone": "UTC",
        "application": new_application_name,
    }
    with snowflake.connector.connect(
        **config
    ) as conn, capture_sf_telemetry.patch_connection(conn, False) as telemetry_test:
        conn._log_telemetry_imported_packages()
        assert len(telemetry_test.records) > 0
        assert any(
            [
                t.message[TelemetryField.KEY_TYPE.value]
                == TelemetryField.IMPORTED_PACKAGES.value
                and new_application_name == t.message[TelemetryField.KEY_SOURCE.value]
                for t in telemetry_test.records
            ]
        )

    # test opt out
    config["log_imported_packages_in_telemetry"] = False
    with snowflake.connector.connect(
        **config
    ) as conn, capture_sf_telemetry.patch_connection(conn, False) as telemetry_test:
        conn._log_telemetry_imported_packages()
        assert len(telemetry_test.records) == 0


@pytest.mark.skipolddriver
def test_disable_query_context_cache(conn_cnx) -> None:
    with conn_cnx(disable_query_context_cache=True) as conn:
        # check that connector function correctly when query context
        # cache is disabled
        ret = conn.cursor().execute("select 1").fetchone()
        assert ret == (1,)
        assert conn.query_context_cache is None


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "mode",
    ("file", "env"),
)
def test_connection_name_loading(monkeypatch, db_parameters, tmp_path, mode):
    import tomlkit

    doc = tomlkit.document()
    default_con = tomlkit.table()
    tmp_connections_file: None | pathlib.Path = None
    try:
        # If anything unexpected fails here, don't want to expose password
        for k, v in db_parameters.items():
            default_con[k] = v
        doc["default"] = default_con
        with monkeypatch.context() as m:
            if mode == "env":
                m.setenv("SF_CONNECTIONS", tomlkit.dumps(doc))
            else:
                tmp_connections_file = tmp_path / "connections.toml"
                tmp_connections_file.write_text(tomlkit.dumps(doc))
                tmp_connections_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
            with snowflake.connector.connect(
                connection_name="default",
                connections_file_path=tmp_connections_file,
            ) as conn:
                with conn.cursor() as cur:
                    assert cur.execute("select 1;").fetchall() == [
                        (1,),
                    ]
    except Exception:
        # This is my way of guaranteeing that we'll not expose the
        # sensitive information that this test needs to handle.
        # db_parameter contains passwords.
        pytest.fail("something failed", pytrace=False)


@pytest.mark.skipolddriver
def test_default_connection_name_loading(monkeypatch, db_parameters):
    import tomlkit

    doc = tomlkit.document()
    default_con = tomlkit.table()
    try:
        # If anything unexpected fails here, don't want to expose password
        for k, v in db_parameters.items():
            default_con[k] = v
        doc["default"] = default_con
        with monkeypatch.context() as m:
            m.setenv("SNOWFLAKE_CONNECTIONS", tomlkit.dumps(doc))
            m.setenv("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "default")
            with snowflake.connector.connect() as conn:
                with conn.cursor() as cur:
                    assert cur.execute("select 1;").fetchall() == [
                        (1,),
                    ]
    except Exception:
        # This is my way of guaranteeing that we'll not expose the
        # sensitive information that this test needs to handle.
        # db_parameter contains passwords.
        pytest.fail("something failed", pytrace=False)


@pytest.mark.skipolddriver
def test_not_found_connection_name():
    connection_name = random_string(5)
    with pytest.raises(
        Error,
        match=f"Invalid connection_name '{connection_name}', known ones are",
    ):
        snowflake.connector.connect(connection_name=connection_name)


@pytest.mark.skipolddriver
def test_server_session_keep_alive(conn_cnx):
    mock_delete_session = mock.MagicMock()
    with conn_cnx(server_session_keep_alive=True) as conn:
        conn.rest.delete_session = mock_delete_session
    mock_delete_session.assert_not_called()

    mock_delete_session = mock.MagicMock()
    with conn_cnx() as conn:
        conn.rest.delete_session = mock_delete_session
    mock_delete_session.assert_called_once()


@pytest.mark.skipolddriver
def test_ocsp_mode_disable_ocsp_checks(
    conn_cnx, is_public_test, is_local_dev_setup, caplog
):
    caplog.set_level(logging.DEBUG, "snowflake.connector.ocsp_snowflake")
    with conn_cnx(disable_ocsp_checks=True) as conn, conn.cursor() as cur:
        assert cur.execute("select 1").fetchall() == [(1,)]
        assert "snowflake.connector.ocsp_snowflake" not in caplog.text
        caplog.clear()

    with conn_cnx() as conn, conn.cursor() as cur:
        assert cur.execute("select 1").fetchall() == [(1,)]
        if is_public_test or is_local_dev_setup:
            assert "snowflake.connector.ocsp_snowflake" in caplog.text
            assert "This connection does not perform OCSP checks." not in caplog.text
        else:
            assert "snowflake.connector.ocsp_snowflake" not in caplog.text


@pytest.mark.skipolddriver
def test_ocsp_mode_insecure_mode(conn_cnx, is_public_test, is_local_dev_setup, caplog):
    caplog.set_level(logging.DEBUG, "snowflake.connector.ocsp_snowflake")
    with conn_cnx(insecure_mode=True) as conn, conn.cursor() as cur:
        assert cur.execute("select 1").fetchall() == [(1,)]
        assert "snowflake.connector.ocsp_snowflake" not in caplog.text
        if is_public_test or is_local_dev_setup:
            assert "This connection does not perform OCSP checks." in caplog.text


@pytest.mark.skipolddriver
def test_ocsp_mode_insecure_mode_and_disable_ocsp_checks_match(
    conn_cnx, is_public_test, is_local_dev_setup, caplog
):
    caplog.set_level(logging.DEBUG, "snowflake.connector.ocsp_snowflake")
    with conn_cnx(
        insecure_mode=True, disable_ocsp_checks=True
    ) as conn, conn.cursor() as cur:
        assert cur.execute("select 1").fetchall() == [(1,)]
        assert "snowflake.connector.ocsp_snowflake" not in caplog.text
        if is_public_test or is_local_dev_setup:
            assert (
                "The values for 'disable_ocsp_checks' and 'insecure_mode' differ. "
                "Using the value of 'disable_ocsp_checks."
            ) not in caplog.text
            assert "This connection does not perform OCSP checks." in caplog.text


@pytest.mark.skipolddriver
def test_ocsp_mode_insecure_mode_and_disable_ocsp_checks_mismatch_ocsp_disabled(
    conn_cnx, is_public_test, is_local_dev_setup, caplog
):
    caplog.set_level(logging.DEBUG, "snowflake.connector.ocsp_snowflake")
    with conn_cnx(
        insecure_mode=False, disable_ocsp_checks=True
    ) as conn, conn.cursor() as cur:
        assert cur.execute("select 1").fetchall() == [(1,)]
        assert "snowflake.connector.ocsp_snowflake" not in caplog.text
        if is_public_test or is_local_dev_setup:
            assert (
                "The values for 'disable_ocsp_checks' and 'insecure_mode' differ. "
                "Using the value of 'disable_ocsp_checks."
            ) in caplog.text
            assert "This connection does not perform OCSP checks." in caplog.text


@pytest.mark.skipolddriver
def test_ocsp_mode_insecure_mode_and_disable_ocsp_checks_mismatch_ocsp_enabled(
    conn_cnx, is_public_test, is_local_dev_setup, caplog
):
    caplog.set_level(logging.DEBUG, "snowflake.connector.ocsp_snowflake")
    with conn_cnx(
        insecure_mode=True, disable_ocsp_checks=False
    ) as conn, conn.cursor() as cur:
        assert cur.execute("select 1").fetchall() == [(1,)]
        if is_public_test or is_local_dev_setup:
            assert "snowflake.connector.ocsp_snowflake" in caplog.text
            assert (
                "The values for 'disable_ocsp_checks' and 'insecure_mode' differ. "
                "Using the value of 'disable_ocsp_checks."
            ) in caplog.text
            assert "This connection does not perform OCSP checks." not in caplog.text
        else:
            assert "snowflake.connector.ocsp_snowflake" not in caplog.text


@pytest.mark.skipolddriver
def test_ocsp_mode_insecure_mode_deprecation_warning(conn_cnx):
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("ignore")
        warnings.filterwarnings(
            "always", category=DeprecationWarning, message=".*insecure_mode"
        )
        with conn_cnx(insecure_mode=True):
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "The 'insecure_mode' connection property is deprecated." in str(
                w[0].message
            )


@pytest.mark.skipolddriver
def test_connection_atexit_close(conn_cnx):
    """Basic Connection test without schema."""
    with conn_cnx() as conn:
        conn._close_at_exit()
        assert conn.is_closed()


@pytest.mark.skipolddriver
def test_token_file_path(tmp_path, db_parameters):
    fake_token = "some token"
    token_file_path = tmp_path / "token"
    with open(token_file_path, "w") as f:
        f.write(fake_token)

    conn = snowflake.connector.connect(**db_parameters, token=fake_token)
    assert conn._token == fake_token
    conn = snowflake.connector.connect(**db_parameters, token_file_path=token_file_path)
    assert conn._token == fake_token


@pytest.mark.skipolddriver
@pytest.mark.skipif(not RUNNING_ON_GH, reason="no ocsp in the environment")
def test_mock_non_existing_server(conn_cnx, caplog):
    from snowflake.connector.cache import SFDictCache

    # disabling local cache and pointing ocsp cache server to a non-existing url
    # connection should still work as it will directly validate the certs against CA servers
    with tempfile.NamedTemporaryFile() as tmp, caplog.at_level(logging.DEBUG):
        with mock.patch(
            "snowflake.connector.url_util.extract_top_level_domain_from_hostname",
            return_value="nonexistingtopleveldomain",
        ):
            with mock.patch(
                "snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE",
                SFDictCache(),
            ):
                with mock.patch(
                    "snowflake.connector.ocsp_snowflake.OCSPCache.OCSP_RESPONSE_CACHE_FILE_NAME",
                    tmp.name,
                ):
                    with conn_cnx():
                        pass
        assert all(
            s in caplog.text
            for s in [
                "Failed to read OCSP response cache file",
                "It will validate with OCSP server.",
                "writing OCSP response cache file to",
            ]
        )


@pytest.mark.skipolddriver
def test_disable_telemetry(conn_cnx, caplog):
    # default behavior, closing connection, it will send telemetry
    with caplog.at_level(logging.DEBUG):
        with conn_cnx() as conn:
            with conn.cursor() as cur:
                cur.execute("select 1").fetchall()
            assert (
                len(conn._telemetry._log_batch) == 3
            )  # 3 events are import package, fetch first, fetch last
    assert "POST /telemetry/send" in caplog.text
    caplog.clear()

    # set session parameters to false
    with caplog.at_level(logging.DEBUG):
        with conn_cnx(
            session_parameters={"CLIENT_TELEMETRY_ENABLED": False}
        ) as conn, conn.cursor() as cur:
            cur.execute("select 1").fetchall()
            assert not conn.telemetry_enabled and not conn._telemetry._log_batch
            # this enable won't work as the session parameter is set to false
            conn.telemetry_enabled = True
            cur.execute("select 1").fetchall()
            assert not conn.telemetry_enabled and not conn._telemetry._log_batch

    assert "POST /telemetry/send" not in caplog.text
    caplog.clear()

    # test disable telemetry in the client
    with caplog.at_level(logging.DEBUG):
        with conn_cnx() as conn:
            assert conn.telemetry_enabled and len(conn._telemetry._log_batch) == 1
            conn.telemetry_enabled = False
            with conn.cursor() as cur:
                cur.execute("select 1").fetchall()
            assert not conn.telemetry_enabled
    assert "POST /telemetry/send" not in caplog.text


@pytest.mark.skipolddriver
def test_is_valid(conn_cnx):
    """Tests whether connection and session validation happens."""
    with conn_cnx() as conn:
        assert conn
        assert conn.is_valid() is True
    assert conn.is_valid() is False


@pytest.mark.skipolddriver
def test_no_auth_connection_negative_case():
    # AuthNoAuth does not exist in old drivers, so we import at test level to
    # skip importing it for old driver tests.
    from snowflake.connector.auth.no_auth import AuthNoAuth

    no_auth = AuthNoAuth()

    # Create a no-auth connection in an invalid way.
    # We do not fail connection establishment because there is no validated way
    # to tell whether the no-auth is a valid use case or not. But it is
    # effectively protected because invalid no-auth will fail to run any query.
    conn = create_connection("default", auth_class=no_auth)

    # Make sure we are indeed passing the no-auth configuration to the
    # connection.
    assert isinstance(conn.auth_class, AuthNoAuth)

    # We expect a failure here when executing queries, because invalid no-auth
    # connection is not able to run any query
    with pytest.raises(DatabaseError, match="Connection is closed"):
        conn.execute_string("select 1")


# _file_operation_parser and _stream_downloader are newly introduced and
# therefore should not be tested on old drivers.
@pytest.mark.skipolddriver
def test_file_utils_sanity_check():
    conn = create_connection("default")
    assert hasattr(conn._file_operation_parser, "parse_file_operation")
    assert hasattr(conn._stream_downloader, "download_as_stream")
