#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import gc
import logging
import os
import pathlib
import queue
import stat
import tempfile
import warnings
import weakref
from test.integ.conftest import RUNNING_ON_GH
from test.randomize import random_string
from unittest import mock
from uuid import uuid4

import pytest

import snowflake.connector.aio
from snowflake.connector import DatabaseError, OperationalError, ProgrammingError
from snowflake.connector.aio import SnowflakeConnection
from snowflake.connector.aio._description import CLIENT_NAME
from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.connection import DEFAULT_CLIENT_PREFETCH_THREADS
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

try:  # pragma: no cover
    from ..parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}
from snowflake.connector.aio.auth import AuthByOkta, AuthByPlugin

from .conftest import create_connection

try:
    from snowflake.connector.errorcode import ER_FAILED_PROCESSING_QMARK
except ImportError:  # Keep olddrivertest from breaking
    ER_FAILED_PROCESSING_QMARK = 252012

try:
    from snowflake.connector.errors import HttpError
except ImportError:
    pass


async def test_basic(conn_testaccount):
    """Basic Connection test."""
    assert conn_testaccount, "invalid cnx"
    # Test default values
    assert conn_testaccount.session_id


async def test_connection_without_schema(conn_cnx):
    """Basic Connection test without schema."""
    async with conn_cnx(schema=None, timezone="UTC") as cnx:
        assert cnx


async def test_connection_without_database_schema(conn_cnx):
    """Basic Connection test without database and schema."""
    async with conn_cnx(database=None, schema=None, timezone="UTC") as cnx:
        assert cnx


async def test_connection_without_database2(conn_cnx):
    """Basic Connection test without database."""
    async with conn_cnx(database=None, timezone="UTC") as cnx:
        assert cnx


async def test_with_config(conn_cnx):
    """Creates a connection with the config parameter."""
    async with conn_cnx(timezone="UTC") as cnx:
        assert cnx, "invalid cnx"
        # Default depends on server; if unreachable, fall back to False
        from ...conftest import get_server_parameter_value

        server_default_str = get_server_parameter_value(
            cnx, "CLIENT_SESSION_KEEP_ALIVE"
        )
        if server_default_str:
            server_default = server_default_str.lower() == "true"
            assert (
                cnx.client_session_keep_alive == server_default
            ), f"Expected client_session_keep_alive={server_default} (server default), got {cnx.client_session_keep_alive}"
        else:
            assert (
                not cnx.client_session_keep_alive
            ), "Expected client_session_keep_alive=False when server default unknown"


@pytest.mark.skipolddriver
async def test_with_tokens(conn_cnx):
    """Creates a connection using session and master token."""
    try:
        async with conn_cnx(
            timezone="UTC",
        ) as initial_cnx:
            assert initial_cnx, "invalid initial cnx"
            master_token = initial_cnx.rest._master_token
            session_token = initial_cnx.rest._token
            token_cnx = await create_connection(
                "default", session_token=session_token, master_token=master_token
            )
            try:
                assert token_cnx, "invalid second cnx"
            finally:
                await token_cnx.close()
    except Exception:
        # This is my way of guaranteeing that we'll not expose the
        # sensitive information that this test needs to handle.
        # db_parameter contains passwords.
        pytest.fail("something failed", pytrace=False)


@pytest.mark.skipolddriver
async def test_with_tokens_expired(conn_cnx):
    """Creates a connection using session and master token."""
    try:
        async with conn_cnx(
            timezone="UTC",
        ) as initial_cnx:
            assert initial_cnx, "invalid initial cnx"
            master_token = initial_cnx._rest._master_token
            session_token = initial_cnx._rest._token

        with pytest.raises(ProgrammingError):
            async with conn_cnx(
                session_token=session_token,
                master_token=master_token,
            ) as token_cnx:
                assert token_cnx
    except Exception:
        # This is my way of guaranteeing that we'll not expose the
        # sensitive information that this test needs to handle.
        # db_parameter contains passwords.
        pytest.fail("something failed", pytrace=False)


async def test_keep_alive_true(conn_cnx):
    """Creates a connection with client_session_keep_alive parameter."""
    async with conn_cnx(client_session_keep_alive=True) as cnx:
        assert cnx.client_session_keep_alive


async def test_keep_alive_heartbeat_frequency(conn_cnx):
    """Tests heartbeat setting.

    Creates a connection with client_session_keep_alive_heartbeat_frequency
    parameter.
    """
    async with conn_cnx(
        client_session_keep_alive=True,
        client_session_keep_alive_heartbeat_frequency=1000,
    ) as cnx:
        assert cnx.client_session_keep_alive_heartbeat_frequency == 1000


@pytest.mark.skipolddriver
async def test_keep_alive_heartbeat_frequency_min(conn_cnx):
    """Tests heartbeat setting with custom frequency.

    Creates a connection with client_session_keep_alive_heartbeat_frequency parameter and set the minimum frequency.
    Also if a value comes as string, should be properly converted to int and not fail assertion.
    """
    async with conn_cnx(
        client_session_keep_alive=True,
        client_session_keep_alive_heartbeat_frequency="10",
    ) as cnx:
        assert cnx.client_session_keep_alive_heartbeat_frequency == 900


async def test_keep_alive_heartbeat_send(conn_cnx, db_parameters):
    config = db_parameters.copy()
    config.update(
        {
            "timezone": "UTC",
            "client_session_keep_alive": True,
            "client_session_keep_alive_heartbeat_frequency": "1",
        }
    )
    with mock.patch(
        "snowflake.connector.aio._connection.SnowflakeConnection._validate_client_session_keep_alive_heartbeat_frequency",
        return_value=900,
    ), mock.patch(
        "snowflake.connector.aio._connection.SnowflakeConnection.client_session_keep_alive_heartbeat_frequency",
        new_callable=mock.PropertyMock,
        return_value=1,
    ), mock.patch(
        "snowflake.connector.aio._connection.SnowflakeConnection._heartbeat_tick"
    ) as mocked_heartbeat:
        cnx = snowflake.connector.aio.SnowflakeConnection(**config)
        try:
            await cnx.connect()
            # we manually call the heartbeat function once to verify heartbeat request works
            assert "success" in (await cnx._rest._heartbeat())
            assert cnx.client_session_keep_alive_heartbeat_frequency == 1
            await asyncio.sleep(3)

        finally:
            await cnx.close()
        # we verify the SnowflakeConnection._heartbeat_tick is called at least twice because we sleep for 3 seconds
        # while the frequency is 1 second
        assert mocked_heartbeat.called
        assert mocked_heartbeat.call_count >= 2


async def test_bad_db(conn_cnx):
    """Attempts to use a bad DB."""
    async with conn_cnx(database="baddb") as cnx:
        assert cnx, "invald cnx"


async def test_with_string_login_timeout(conn_cnx):
    """Test that login_timeout when passed as string does not raise TypeError.

    In this test, we pass bad login credentials to raise error and trigger login
    timeout calculation. We expect to see DatabaseError instead of TypeError that
    comes from str - int arithmetic.
    """
    with pytest.raises(DatabaseError):
        async with conn_cnx(
            protocol="http",
            user="bogus",
            password="bogus",
            login_timeout="5",
        ):
            pass


async def test_bogus(db_parameters):
    """Attempts to login with invalid user name and password.

    Notes:
        This takes a long time.
    """
    with pytest.raises(DatabaseError):
        async with snowflake.connector.aio.SnowflakeConnection(
            protocol="http",
            user="bogus",
            password="bogus",
            account="testaccount123",
            host=db_parameters["host"],
            port=db_parameters["port"],
            login_timeout=5,
            disable_ocsp_checks=True,
        ):
            pass

    with pytest.raises(DatabaseError):
        async with snowflake.connector.aio.SnowflakeConnection(
            protocol="http",
            user="snowman",
            password="",
            account="testaccount123",
            host=db_parameters["host"],
            port=db_parameters["port"],
            login_timeout=5,
        ):
            pass

    with pytest.raises(ProgrammingError):
        async with snowflake.connector.aio.SnowflakeConnection(
            protocol="http",
            user="",
            password="password",
            account="testaccount123",
            host=db_parameters["host"],
            port=db_parameters["port"],
            login_timeout=5,
        ):
            pass


async def test_invalid_application(conn_cnx):
    """Invalid application name."""
    with pytest.raises(snowflake.connector.Error):
        async with conn_cnx(application="%%%"):
            pass


async def test_valid_application(conn_cnx):
    """Valid application name."""
    application = "Special_Client"
    async with conn_cnx(application=application) as cnx:
        assert cnx.application == application, "Must be valid application"


async def test_invalid_default_parameters(conn_cnx):
    """Invalid database, schema, warehouse and role name."""
    async with conn_cnx(
        database="neverexists", schema="neverexists", warehouse="neverexits"
    ) as cnx:
        assert cnx, "Must be success"

    with pytest.raises(snowflake.connector.DatabaseError):
        async with conn_cnx(
            database="neverexists",
            schema="neverexists",
            validate_default_parameters=True,
        ):
            pass

    with pytest.raises(snowflake.connector.DatabaseError):
        async with conn_cnx(
            schema="neverexists",
            validate_default_parameters=True,
        ):
            pass

    with pytest.raises(snowflake.connector.DatabaseError):
        async with conn_cnx(
            warehouse="neverexists",
            validate_default_parameters=True,
        ):
            pass

    # Invalid role name is already validated
    with pytest.raises(snowflake.connector.DatabaseError):
        async with conn_cnx(role="neverexists"):
            pass


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="The user needs a privilege of create warehouse.",
)
async def test_drop_create_user(conn_cnx, db_parameters):
    """Drops and creates user."""
    async with conn_cnx() as cnx:

        async def exe(sql):
            return await cnx.cursor().execute(sql)

        await exe("use role accountadmin")
        await exe("drop user if exists snowdog")
        await exe("create user if not exists snowdog identified by 'testdoc'")
        await exe("use {}".format(db_parameters["database"]))
        await exe("create or replace role snowdog_role")
        await exe("grant role snowdog_role to user snowdog")
        try:
            # This statement will be partially executed because REFERENCE_USAGE
            # will not be granted.
            await exe(
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
        await exe(
            "grant all on schema {} to role snowdog_role".format(
                db_parameters["schema"]
            )
        )

    async with conn_cnx(user="snowdog", password="testdoc") as cnx2:

        async def exe(sql):
            return await cnx2.cursor().execute(sql)

        await exe("use role snowdog_role")
        await exe("use {}".format(db_parameters["database"]))
        await exe("use schema {}".format(db_parameters["schema"]))
        await exe("create or replace table friends(name varchar(100))")
        await exe("drop table friends")
    async with conn_cnx() as cnx:

        async def exe(sql):
            return await cnx.cursor().execute(sql)

        await exe("use role accountadmin")
        await exe(
            "revoke all on database {} from role snowdog_role".format(
                db_parameters["database"]
            )
        )
        await exe("drop role snowdog_role")
        await exe("drop user if exists snowdog")


@pytest.mark.timeout(15)
@pytest.mark.skipolddriver
async def test_invalid_account_timeout(conn_cnx):
    with pytest.raises(HttpError):
        async with conn_cnx(
            account="bogus", user="test", password="test", login_timeout=5
        ):
            pass


@pytest.mark.timeout(15)
async def test_invalid_proxy(conn_cnx):
    with pytest.raises(OperationalError):
        async with conn_cnx(
            protocol="http",
            account="testaccount",
            login_timeout=5,
            proxy_host="localhost",
            proxy_port="3333",
        ):
            pass
    # NOTE environment variable is set if the proxy parameter is specified.
    del os.environ["HTTP_PROXY"]
    del os.environ["HTTPS_PROXY"]


@pytest.mark.timeout(15)
@pytest.mark.skipolddriver
async def test_eu_connection(tmpdir):
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
        async with snowflake.connector.aio.SnowflakeConnection(
            account="testaccount1234",
            user="testuser",
            password="testpassword",
            region="eu-central-1",
            login_timeout=5,
            ocsp_response_cache_filename=os.path.join(
                str(tmpdir), "test_ocsp_cache.txt"
            ),
        ):
            pass


@pytest.mark.skipolddriver
async def test_us_west_connection(tmpdir):
    """Tests default region setting.

    Region='us-west-2' indicates no region is included in the hostname, i.e.,
    https://testaccount1234.snowflakecomputing.com.

    Notes:
        Region is deprecated.
    """
    with pytest.raises(HttpError):
        # must reach Snowflake
        async with snowflake.connector.aio.SnowflakeConnection(
            account="testaccount1234",
            user="testuser",
            password="testpassword",
            region="us-west-2",
            login_timeout=5,
        ):
            pass


@pytest.mark.timeout(60)
async def test_privatelink(conn_cnx):
    """Ensure the OCSP cache server URL is overridden if privatelink connection is used."""
    try:
        os.environ["SF_OCSP_FAIL_OPEN"] = "false"
        os.environ["SF_OCSP_DO_RETRY"] = "false"
        async with snowflake.connector.aio.SnowflakeConnection(
            account="testaccount",
            user="testuser",
            password="testpassword",
            region="eu-central-1.privatelink",
            login_timeout=5,
        ):
            pass
        pytest.fail("should not make connection")
    except OperationalError:
        ocsp_url = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL")
        assert ocsp_url is not None, "OCSP URL should not be None"
        assert (
            ocsp_url == "http://ocsp.testaccount.eu-central-1."
            "privatelink.snowflakecomputing.com/"
            "ocsp_response_cache.json"
        )

    async with conn_cnx(timezone="UTC") as cnx:
        assert cnx, "invalid cnx"

    ocsp_url = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL")
    assert ocsp_url is None, f"OCSP URL should be None: {ocsp_url}"
    del os.environ["SF_OCSP_DO_RETRY"]
    del os.environ["SF_OCSP_FAIL_OPEN"]


async def test_disable_request_pooling(conn_cnx):
    """Creates a connection with client_session_keep_alive parameter."""
    async with conn_cnx(timezone="UTC", disable_request_pooling=True) as cnx:
        assert cnx.disable_request_pooling


async def test_privatelink_ocsp_url_creation():
    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    await SnowflakeConnection.setup_ocsp_privatelink(APPLICATION_SNOWSQL, hostname)

    ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
    assert (
        ocsp_cache_server
        == "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    )

    del os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"]

    await SnowflakeConnection.setup_ocsp_privatelink(CLIENT_NAME, hostname)
    ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
    assert (
        ocsp_cache_server
        == "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    )


async def test_privatelink_ocsp_url_concurrent():
    bucket = queue.Queue()

    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    expectation = "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    task = []

    for _ in range(15):
        task.append(
            asyncio.create_task(
                ExecPrivatelinkAsyncTask(
                    bucket, hostname, expectation, CLIENT_NAME
                ).run()
            )
        )

    await asyncio.gather(*task)
    assert bucket.qsize() == 15
    for _ in range(15):
        if bucket.get() != "Success":
            raise AssertionError()

    if os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None) is not None:
        del os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"]


async def test_privatelink_ocsp_url_concurrent_snowsql():
    bucket = queue.Queue()

    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    expectation = "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    task = []

    for _ in range(15):
        task.append(
            asyncio.create_task(
                ExecPrivatelinkAsyncTask(
                    bucket, hostname, expectation, APPLICATION_SNOWSQL
                ).run()
            )
        )

    await asyncio.gather(*task)
    assert bucket.qsize() == 15
    for _ in range(15):
        if bucket.get() != "Success":
            raise AssertionError()


@pytest.mark.skipolddriver
async def test_uppercase_privatelink_ocsp_url_creation():
    account = "TESTACCOUNT.US-EAST-1.PRIVATELINK"
    hostname = account + ".snowflakecomputing.com"

    await SnowflakeConnection.setup_ocsp_privatelink(CLIENT_NAME, hostname)
    ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
    assert (
        ocsp_cache_server
        == "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    )


class ExecPrivatelinkAsyncTask:
    def __init__(self, bucket, hostname, expectation, client_name):
        self.bucket = bucket
        self.hostname = hostname
        self.expectation = expectation
        self.client_name = client_name

    async def run(self):
        await SnowflakeConnection.setup_ocsp_privatelink(
            self.client_name, self.hostname
        )
        ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
        if ocsp_cache_server is not None and ocsp_cache_server != self.expectation:
            print(f"Got {ocsp_cache_server} Expected {self.expectation}")
            self.bucket.put("Fail")
        else:
            self.bucket.put("Success")


async def test_okta_url(conn_cnx):
    orig_authenticator = "https://someaccount.okta.com/snowflake/oO56fExYCGnfV83/2345"

    async def mock_auth(self, auth_instance):
        assert isinstance(auth_instance, AuthByOkta)
        assert self._authenticator == orig_authenticator

    with mock.patch(
        "snowflake.connector.aio.SnowflakeConnection._authenticate",
        mock_auth,
    ):
        async with conn_cnx(
            timezone="UTC",
            authenticator=orig_authenticator,
            password="test-password",
        ) as cnx:
            assert cnx


async def test_dashed_url(db_parameters):
    """Test whether dashed URLs get created correctly."""
    with mock.patch(
        "snowflake.connector.aio._network.SnowflakeRestful.fetch",
        return_value={"data": {"token": None, "masterToken": None}, "success": True},
    ) as mocked_fetch:
        async with snowflake.connector.aio.SnowflakeConnection(
            user="test-user",
            password="test-password",
            host="test-host",
            port="443",
            account="test-account",
        ) as cnx:
            assert cnx
            cnx.commit = cnx.rollback = lambda: asyncio.sleep(
                0
            )  # Skip tear down, there's only a mocked rest api
            assert any(
                [
                    c[0][1].startswith("https://test-host:443")
                    for c in mocked_fetch.call_args_list
                ]
            )


async def test_dashed_url_account_name(db_parameters):
    """Tests whether dashed URLs get created correctly when no hostname is provided."""
    with mock.patch(
        "snowflake.connector.aio._network.SnowflakeRestful.fetch",
        return_value={"data": {"token": None, "masterToken": None}, "success": True},
    ) as mocked_fetch:
        async with snowflake.connector.aio.SnowflakeConnection(
            user="test-user",
            password="test-password",
            port="443",
            account="test-account",
        ) as cnx:
            assert cnx
            cnx.commit = cnx.rollback = lambda: asyncio.sleep(
                0
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
async def test_invalid_connection_parameter(conn_cnx, name, value, exc_warn):
    with warnings.catch_warnings(record=True) as warns:
        async with conn_cnx(validate_default_parameters=True, **{name: value}) as conn:
            assert getattr(conn, "_" + name) == value
            assert any(str(exc_warn) == str(w.message) for w in warns)


async def test_invalid_connection_parameters_turned_off(conn_cnx):
    """Makes sure parameter checking can be turned off."""
    with warnings.catch_warnings(record=True) as warns:
        async with conn_cnx(
            validate_default_parameters=False,
            autocommit="True",
            applucation="this is a typo or my own variable",
        ) as conn:
            assert conn._autocommit == "True"
            assert conn._applucation == "this is a typo or my own variable"
            assert not any(
                "_autocommit" in w.message or "_applucation" in w.message for w in warns
            )


async def test_invalid_connection_parameters_only_warns(conn_cnx):
    """This test supresses warnings to only have warehouse, database and schema checking."""
    with warnings.catch_warnings(record=True) as warns:
        async with conn_cnx(
            validate_default_parameters=True,
            autocommit="True",
            applucation="this is a typo or my own variable",
        ) as conn:
            assert conn._autocommit == "True"
            assert conn._applucation == "this is a typo or my own variable"
            assert not any(
                "_autocommit" in str(w.message) or "_applucation" in str(w.message)
                for w in warns
            )


@pytest.mark.skipolddriver
async def test_region_deprecation(conn_cnx):
    """Tests whether region raises a deprecation warning."""
    async with conn_cnx() as conn:
        with warnings.catch_warnings(record=True) as w:
            conn.region
        assert len(w) == 1
        assert issubclass(w[0].category, PendingDeprecationWarning)
        assert "Region has been deprecated" in str(w[0].message)


@pytest.mark.skip("SNOW-1763103")
async def test_invalid_errorhander_error(conn_cnx):
    """Tests if no errorhandler cannot be set."""
    async with conn_cnx() as conn:
        with pytest.raises(ProgrammingError, match="None errorhandler is specified"):
            conn.errorhandler = None
        original_handler = conn.errorhandler
        conn.errorhandler = original_handler
        assert conn.errorhandler is original_handler


async def test_disable_request_pooling_setter(conn_cnx):
    """Tests whether request pooling can be set successfully."""
    async with conn_cnx() as conn:
        original_value = conn.disable_request_pooling
        conn.disable_request_pooling = not original_value
        assert conn.disable_request_pooling == (not original_value)
        conn.disable_request_pooling = original_value
        assert conn.disable_request_pooling == original_value


async def test_autocommit_closed_already(conn_cnx):
    """Test if setting autocommit on an already closed connection raised right error."""
    async with conn_cnx() as conn:
        pass
    with pytest.raises(DatabaseError, match=r"Connection is closed") as dbe:
        await conn.autocommit(True)
        assert dbe.errno == ER_CONNECTION_IS_CLOSED


async def test_autocommit_invalid_type(conn_cnx):
    """Tests if setting autocommit on an already closed connection raised right error."""
    async with conn_cnx() as conn:
        with pytest.raises(ProgrammingError, match=r"Invalid parameter: True") as dbe:
            await conn.autocommit("True")
            assert dbe.errno == ER_INVALID_VALUE


async def test_autocommit_unsupported(conn_cnx, caplog):
    """Tests if server-side error is handled correctly when setting autocommit."""
    async with conn_cnx() as conn:
        caplog.set_level(logging.DEBUG, "snowflake.connector")
        with mock.patch(
            "snowflake.connector.aio.SnowflakeCursor.execute",
            side_effect=Error("Test error", sqlstate=SQLSTATE_FEATURE_NOT_SUPPORTED),
        ):
            await conn.autocommit(True)
        assert (
            "snowflake.connector.aio._connection",
            logging.DEBUG,
            "Autocommit feature is not enabled for this connection. Ignored",
        ) in caplog.record_tuples


async def test_sequence_counter(conn_cnx):
    """Tests whether setting sequence counter and increasing it works as expected."""
    async with conn_cnx(sequence_counter=4) as conn:
        assert conn.sequence_counter == 4
        async with conn.cursor() as cur:
            assert await (await cur.execute("select 1 ")).fetchall() == [(1,)]
        assert conn.sequence_counter == 5


async def test_missing_account(conn_cnx):
    """Test whether missing account raises the right exception."""
    with pytest.raises(ProgrammingError, match="Account must be specified") as pe:
        async with conn_cnx(account=""):
            pass
        assert pe.errno == ER_NO_ACCOUNT_NAME


@pytest.mark.parametrize("resp", [None, {}])
async def test_empty_response(conn_cnx, resp):
    """Tests that cmd_query returns an empty response when empty/no response is recevided from back-end."""
    async with conn_cnx() as conn:
        with mock.patch(
            "snowflake.connector.aio._network.SnowflakeRestful.request",
            return_value=resp,
        ):
            assert await conn.cmd_query("select 1", 0, uuid4()) == {"data": {}}


@pytest.mark.skipolddriver
async def test_authenticate_error(conn_cnx, caplog):
    """Test Reauthenticate error handling while authenticating."""
    # The docs say unsafe should make this test work, but
    # it doesn't seem to work on MagicMock
    mock_auth = mock.Mock(spec=AuthByPlugin, unsafe=True)
    mock_auth.prepare.return_value = mock_auth
    mock_auth.update_body.side_effect = ReauthenticationRequest(None)
    mock_auth._retry_ctx = mock.MagicMock()
    async with conn_cnx() as conn:
        caplog.set_level(logging.DEBUG, "snowflake.connector")
        with pytest.raises(ReauthenticationRequest):
            await conn.authenticate_with_retry(mock_auth)
        assert (
            "snowflake.connector.aio._connection",
            logging.DEBUG,
            "ID token expired. Reauthenticating...: None",
        ) in caplog.record_tuples


@pytest.mark.skipolddriver
async def test_process_qmark_params_error(conn_cnx):
    """Tests errors thrown in _process_params_qmarks."""
    sql = "select 1;"
    async with conn_cnx(paramstyle="qmark") as conn:
        async with conn.cursor() as cur:
            with pytest.raises(
                ProgrammingError,
                match="Binding parameters must be a list: invalid input",
            ) as pe:
                await cur.execute(sql, params="invalid input")
            assert pe.value.errno == ER_FAILED_PROCESSING_PYFORMAT
            with pytest.raises(
                ProgrammingError,
                match="Binding parameters must be a list where one element is a single "
                "value or a pair of Snowflake datatype and a value",
            ) as pe:
                await cur.execute(
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
                await cur.execute(sql, params=[mock.MagicMock()])
            assert pe.value.errno == ER_NOT_IMPLICITY_SNOWFLAKE_DATATYPE


@pytest.mark.skipolddriver
async def test_process_param_dict_error(conn_cnx):
    """Tests whether exceptions in __process_params_dict are handled correctly."""
    async with conn_cnx() as conn:
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
async def test_process_param_error(conn_cnx):
    """Tests whether exceptions in __process_params_dict are handled correctly."""
    async with conn_cnx() as conn:
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
async def test_autocommit(conn_cnx, db_parameters, auto_commit):
    conn = snowflake.connector.aio.SnowflakeConnection(**db_parameters)
    with mock.patch.object(conn, "commit") as mocked_commit:
        async with conn:
            async with conn.cursor() as cur:
                await cur.execute(f"alter session set autocommit = {auto_commit}")
    if auto_commit:
        assert not mocked_commit.called
    else:
        assert mocked_commit.called


@pytest.mark.skipolddriver
async def test_client_prefetch_threads_setting(conn_cnx):
    """Tests whether client_prefetch_threads updated and is propagated to result set."""
    async with conn_cnx() as conn:
        assert conn.client_prefetch_threads == DEFAULT_CLIENT_PREFETCH_THREADS
        new_thread_count = conn.client_prefetch_threads + 1
        async with conn.cursor() as cur:
            await cur.execute(
                f"alter session set client_prefetch_threads={new_thread_count}"
            )
            assert cur._result_set.prefetch_thread_num == new_thread_count
        assert conn.client_prefetch_threads == new_thread_count


@pytest.mark.skip(reason="Test stopped working after account setup change")
@pytest.mark.external
async def test_client_failover_connection_url(conn_cnx):
    async with conn_cnx("client_failover") as conn:
        async with conn.cursor() as cur:
            assert await (await cur.execute("select 1;")).fetchall() == [
                (1,),
            ]


async def test_connection_gc(conn_cnx):
    """This test makes sure that a heartbeat thread doesn't prevent garbage collection of SnowflakeConnection."""
    conn = await conn_cnx(client_session_keep_alive=True).__aenter__()
    conn_wref = weakref.ref(conn)
    del conn
    # this is different from sync test because we need to yield to give connection.close
    # coroutine a chance to run all the teardown tasks
    for _ in range(100):
        await asyncio.sleep(0.01)
    gc.collect()
    assert conn_wref() is None


@pytest.mark.skipolddriver
async def test_connection_cant_be_reused(conn_cnx):
    row_count = 50_000
    async with conn_cnx() as conn:
        cursors = await conn.execute_string(
            f"select seq4() as n from table(generator(rowcount => {row_count}));"
        )
        assert len(cursors[0]._result_set.batches) > 1  # We need to have remote results
    res = []
    async for result in cursors[0]:
        res.append(result)
    assert res


@pytest.mark.external
@pytest.mark.skipolddriver
async def test_ocsp_cache_working(conn_cnx):
    """Verifies that the OCSP cache is functioning.

    The only way we can verify this is that the number of hits and misses increase.
    """
    from snowflake.connector.ocsp_snowflake import OCSP_RESPONSE_VALIDATION_CACHE

    original_count = (
        OCSP_RESPONSE_VALIDATION_CACHE.telemetry["hit"]
        + OCSP_RESPONSE_VALIDATION_CACHE.telemetry["miss"]
    )
    async with conn_cnx() as cnx:
        assert cnx
    assert (
        OCSP_RESPONSE_VALIDATION_CACHE.telemetry["hit"]
        + OCSP_RESPONSE_VALIDATION_CACHE.telemetry["miss"]
        > original_count
    )


@pytest.mark.skipolddriver
async def test_imported_packages_telemetry(conn_cnx, capture_sf_telemetry_async):
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

    async with conn_cnx() as conn, capture_sf_telemetry_async.patch_connection(
        conn, False
    ) as telemetry_test:
        await conn._log_telemetry_imported_packages()
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
    async with conn_cnx(
        timezone="UTC", application=new_application_name
    ) as conn, capture_sf_telemetry_async.patch_connection(
        conn, False
    ) as telemetry_test:
        await conn._log_telemetry_imported_packages()
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
    async with conn_cnx(
        timezone="UTC",
        application=new_application_name,
        log_imported_packages_in_telemetry=False,
    ) as conn, capture_sf_telemetry_async.patch_connection(
        conn, False
    ) as telemetry_test:
        await conn._log_telemetry_imported_packages()
        assert len(telemetry_test.records) == 0


@pytest.mark.skipolddriver
async def test_disable_query_context_cache(conn_cnx) -> None:
    async with conn_cnx(disable_query_context_cache=True) as conn:
        # check that connector function correctly when query context
        # cache is disabled
        ret = await (await conn.cursor().execute("select 1")).fetchone()
        assert ret == (1,)
        assert conn.query_context_cache is None


@pytest.mark.skipolddriver
@pytest.mark.parametrize("mode", ("file", "env"))
@pytest.mark.parametrize("connection_name", ["default", "custom_connection_for_test"])
async def test_connection_name_loading(
    monkeypatch, db_parameters, tmp_path, mode, connection_name
):
    import tomlkit

    doc = tomlkit.document()
    default_con = tomlkit.table()
    tmp_connections_file: None | pathlib.Path = None
    try:
        # If anything unexpected fails here, don't want to expose password
        for k, v in db_parameters.items():
            default_con[k] = v
        doc[connection_name] = default_con
        with monkeypatch.context() as m:
            if mode == "env":
                m.setenv("SNOWFLAKE_CONNECTIONS", tomlkit.dumps(doc))
            else:
                tmp_connections_file = tmp_path / "connections.toml"
                tmp_connections_file.write_text(tomlkit.dumps(doc))
                tmp_connections_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
            async with snowflake.connector.aio.SnowflakeConnection(
                connection_name=connection_name,
                connections_file_path=tmp_connections_file,
            ) as conn:
                async with conn.cursor() as cur:
                    assert await (await cur.execute("select 1;")).fetchall() == [
                        (1,),
                    ]
    except Exception:
        # This is my way of guaranteeing that we'll not expose the
        # sensitive information that this test needs to handle.
        # db_parameter contains passwords.
        pytest.fail("something failed", pytrace=False)


@pytest.mark.skipolddriver
@pytest.mark.parametrize("connection_name", ["default", "custom_connection_for_test"])
async def test_default_connection_name_loading(
    monkeypatch, db_parameters, connection_name
):
    import tomlkit

    doc = tomlkit.document()
    default_con = tomlkit.table()
    try:
        # If anything unexpected fails here, don't want to expose password
        for k, v in db_parameters.items():
            default_con[k] = v
        doc[connection_name] = default_con
        with monkeypatch.context() as m:
            m.setenv("SNOWFLAKE_CONNECTIONS", tomlkit.dumps(doc))
            m.setenv("SNOWFLAKE_DEFAULT_CONNECTION_NAME", connection_name)
            async with snowflake.connector.aio.SnowflakeConnection() as conn:
                async with conn.cursor() as cur:
                    assert await (await cur.execute("select 1;")).fetchall() == [
                        (1,),
                    ]
    except Exception:
        # This is my way of guaranteeing that we'll not expose the
        # sensitive information that this test needs to handle.
        # db_parameter contains passwords.
        pytest.fail("something failed", pytrace=False)


@pytest.mark.skipolddriver
async def test_not_found_connection_name():
    connection_name = random_string(5)
    with pytest.raises(
        Error,
        match=f"Invalid connection_name '{connection_name}', known ones are",
    ):
        await snowflake.connector.aio.SnowflakeConnection(
            connection_name=connection_name
        ).connect()


@pytest.mark.skipolddriver
async def test_server_session_keep_alive(conn_cnx):
    mock_delete_session = mock.MagicMock()
    async with conn_cnx(server_session_keep_alive=True) as conn:
        conn.rest.delete_session = mock_delete_session
    mock_delete_session.assert_not_called()

    mock_delete_session = mock.MagicMock()
    async with conn_cnx() as conn:
        conn.rest.delete_session = mock_delete_session
    mock_delete_session.assert_called_once()


@pytest.mark.skipolddriver
@pytest.mark.parametrize("disable_ocsp_checks", [True, False, None])
async def test_ocsp_mode_disable_ocsp_checks(
    conn_cnx, is_public_test, is_local_dev_setup, caplog, disable_ocsp_checks
):
    caplog.set_level(logging.DEBUG, "snowflake.connector.aio._ocsp_snowflake")
    kwargs = (
        {"disable_ocsp_checks": disable_ocsp_checks}
        if disable_ocsp_checks is not None
        else {}
    )
    async with conn_cnx(**kwargs) as conn, conn.cursor() as cur:
        assert await (await cur.execute("select 1")).fetchall() == [(1,)]
        if disable_ocsp_checks is True:
            assert "snowflake.connector.aio._ocsp_snowflake" not in caplog.text
        else:
            if is_public_test or is_local_dev_setup:
                assert "snowflake.connector.aio._ocsp_snowflake" in caplog.text
                assert (
                    "This connection does not perform OCSP checks." not in caplog.text
                )
            else:
                assert "snowflake.connector.aio._ocsp_snowflake" not in caplog.text


@pytest.mark.skipolddriver
async def test_ocsp_mode_insecure_mode(
    conn_cnx, is_public_test, is_local_dev_setup, caplog
):
    caplog.set_level(logging.DEBUG, "snowflake.connector.aio._ocsp_snowflake")
    async with conn_cnx(insecure_mode=True) as conn, conn.cursor() as cur:
        assert await (await cur.execute("select 1")).fetchall() == [(1,)]
        assert "snowflake.connector.aio._ocsp_snowflake" not in caplog.text
        if is_public_test or is_local_dev_setup:
            assert "This connection does not perform OCSP checks." in caplog.text


@pytest.mark.skipolddriver
async def test_ocsp_mode_insecure_mode_and_disable_ocsp_checks_match(
    conn_cnx, is_public_test, is_local_dev_setup, caplog
):
    caplog.set_level(logging.DEBUG, "snowflake.connector.aio._ocsp_snowflake")
    async with conn_cnx(
        insecure_mode=True, disable_ocsp_checks=True
    ) as conn, conn.cursor() as cur:
        assert await (await cur.execute("select 1")).fetchall() == [(1,)]
        assert "snowflake.connector.aio._ocsp_snowflake" not in caplog.text
        if is_public_test or is_local_dev_setup:
            assert (
                "The values for 'disable_ocsp_checks' and 'insecure_mode' differ. "
                "Using the value of 'disable_ocsp_checks."
            ) not in caplog.text
            assert "This connection does not perform OCSP checks." in caplog.text


@pytest.mark.skipolddriver
async def test_ocsp_mode_insecure_mode_and_disable_ocsp_checks_mismatch_ocsp_disabled(
    conn_cnx, is_public_test, is_local_dev_setup, caplog
):
    caplog.set_level(logging.DEBUG, "snowflake.connector.aio._ocsp_snowflake")
    async with conn_cnx(
        insecure_mode=False, disable_ocsp_checks=True
    ) as conn, conn.cursor() as cur:
        assert await (await cur.execute("select 1")).fetchall() == [(1,)]
        assert "snowflake.connector.aio._ocsp_snowflake" not in caplog.text
        if is_public_test or is_local_dev_setup:
            assert (
                "The values for 'disable_ocsp_checks' and 'insecure_mode' differ. "
                "Using the value of 'disable_ocsp_checks."
            ) in caplog.text
            assert "This connection does not perform OCSP checks." in caplog.text


@pytest.mark.skipolddriver
async def test_ocsp_mode_insecure_mode_and_disable_ocsp_checks_mismatch_ocsp_enabled(
    conn_cnx, is_public_test, is_local_dev_setup, caplog
):
    caplog.set_level(logging.DEBUG, "snowflake.connector.aio._ocsp_snowflake")
    async with conn_cnx(
        insecure_mode=True, disable_ocsp_checks=False
    ) as conn, conn.cursor() as cur:
        assert await (await cur.execute("select 1")).fetchall() == [(1,)]
        if is_public_test or is_local_dev_setup:
            assert "snowflake.connector.aio._ocsp_snowflake" in caplog.text
            assert (
                "The values for 'disable_ocsp_checks' and 'insecure_mode' differ. "
                "Using the value of 'disable_ocsp_checks."
            ) in caplog.text
            assert "This connection does not perform OCSP checks." not in caplog.text
        else:
            assert "snowflake.connector.aio._ocsp_snowflake" not in caplog.text


@pytest.mark.skipolddriver
async def test_ocsp_mode_insecure_mode_deprecation_warning(conn_cnx):
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("ignore")
        warnings.filterwarnings(
            "always", category=DeprecationWarning, message=".*insecure_mode"
        )
        async with conn_cnx(insecure_mode=True):
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "The 'insecure_mode' connection property is deprecated." in str(
                w[0].message
            )


@pytest.mark.skipolddriver
def test_connection_atexit_close(db_parameters):
    """Basic Connection test without schema."""
    conn = snowflake.connector.aio.SnowflakeConnection(**db_parameters)

    async def func():
        await conn.connect()
        return conn

    conn = asyncio.run(func())
    conn._close_at_exit()
    assert conn.is_closed()


@pytest.mark.skipolddriver
async def test_token_file_path(tmp_path, db_parameters):
    fake_token = "some token"
    token_file_path = tmp_path / "token"
    with open(token_file_path, "w") as f:
        f.write(fake_token)

    conn = snowflake.connector.aio.SnowflakeConnection(
        **db_parameters, token=fake_token
    )
    await conn.connect()
    assert conn._token == fake_token
    conn = snowflake.connector.aio.SnowflakeConnection(
        **db_parameters, token_file_path=token_file_path
    )
    await conn.connect()
    assert conn._token == fake_token


@pytest.mark.skipolddriver
@pytest.mark.skipif(not RUNNING_ON_GH, reason="no ocsp in the environment")
async def test_mock_non_existing_server(conn_cnx, caplog):
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
                    async with conn_cnx():
                        pass
        assert all(
            s in caplog.text
            for s in [
                "Failed to read OCSP response cache file",
                "It will validate with OCSP server.",
                "writing OCSP response cache file to",
            ]
        )


@pytest.mark.xfail(
    reason="TODO: SNOW-1759084 await anext(self._generator, None) does not execute code after yield"
)
async def test_disable_telemetry(conn_cnx, caplog):
    # default behavior, closing connection, it will send telemetry
    with caplog.at_level(logging.DEBUG):
        async with conn_cnx() as conn:
            async with conn.cursor() as cur:
                await (await cur.execute("select 1")).fetchall()
            assert (
                len(conn._telemetry._log_batch) == 3
            )  # 3 events are `import package`, `fetch first`, it's missing `fetch last` because of SNOW-1759084

    assert "POST /telemetry/send" in caplog.text
    caplog.clear()

    # set session parameters to false
    with caplog.at_level(logging.DEBUG):
        async with conn_cnx(
            session_parameters={"CLIENT_TELEMETRY_ENABLED": False}
        ) as conn, conn.cursor() as cur:
            await (await cur.execute("select 1")).fetchall()
            assert not conn.telemetry_enabled and not conn._telemetry._log_batch
            # this enable won't work as the session parameter is set to false
            conn.telemetry_enabled = True
            await (await cur.execute("select 1")).fetchall()
            assert not conn.telemetry_enabled and not conn._telemetry._log_batch

    assert "POST /telemetry/send" not in caplog.text
    caplog.clear()

    # test disable telemetry in the client
    with caplog.at_level(logging.DEBUG):
        async with conn_cnx() as conn:
            assert conn.telemetry_enabled and len(conn._telemetry._log_batch) == 1
            conn.telemetry_enabled = False
            async with conn.cursor() as cur:
                await (await cur.execute("select 1")).fetchall()
            assert not conn.telemetry_enabled
    assert "POST /telemetry/send" not in caplog.text


@pytest.mark.skipolddriver
async def test_is_valid(conn_cnx):
    """Tests whether connection and session validation happens."""
    async with conn_cnx() as conn:
        assert conn
        assert await conn.is_valid() is True
    assert await conn.is_valid() is False


async def test_no_auth_connection_negative_case():
    # AuthNoAuth does not exist in old drivers, so we import at test level to
    # skip importing it for old driver tests.
    from test.integ.aio_it.conftest import create_connection

    from snowflake.connector.aio.auth._no_auth import AuthNoAuth

    no_auth = AuthNoAuth()

    # Create a no-auth connection in an invalid way.
    # We do not fail connection establishment because there is no validated way
    # to tell whether the no-auth is a valid use case or not. But it is
    # effectively protected because invalid no-auth will fail to run any query.
    conn = await create_connection("default", auth_class=no_auth)

    # Make sure we are indeed passing the no-auth configuration to the
    # connection.
    assert isinstance(conn.auth_class, AuthNoAuth)

    # We expect a failure here when executing queries, because invalid no-auth
    # connection is not able to run any query
    with pytest.raises(DatabaseError, match="Connection is closed"):
        await conn.execute_string("select 1")

    await conn.close()


@pytest.mark.skipolddriver
@pytest.mark.skipif(IS_WINDOWS, reason="chmod doesn't work on Windows")
async def test_unsafe_skip_file_permissions_check_skips_config_permissions_check(
    db_parameters, tmp_path
):
    """Test that unsafe_skip_file_permissions_check flag bypasses permission checks on config files."""
    # Write config file and set unsafe permissions (readable by others)
    tmp_config_file = tmp_path / "config.toml"
    tmp_config_file.write_text("[log]\n" "save_logs = false\n" 'level = "INFO"\n')
    tmp_config_file.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IROTH)

    async def _run_select_1(unsafe_skip_file_permissions_check: bool):
        warnings.simplefilter("always")
        # Connect directly with db_parameters, using custom config file path
        # We need to modify CONFIG_MANAGER to point to our test file
        from snowflake.connector.config_manager import CONFIG_MANAGER

        original_file_path = CONFIG_MANAGER.file_path
        try:
            CONFIG_MANAGER.file_path = tmp_config_file
            CONFIG_MANAGER.conf_file_cache = None  # Force re-read
            async with snowflake.connector.aio.SnowflakeConnection(
                **db_parameters,
                unsafe_skip_file_permissions_check=unsafe_skip_file_permissions_check,
            ) as conn:
                async with conn.cursor() as cur:
                    result = await (await cur.execute("select 1;")).fetchall()
                    assert result == [(1,)]
        finally:
            CONFIG_MANAGER.file_path = original_file_path
            CONFIG_MANAGER.conf_file_cache = None

    # Without the flag - should trigger permission warnings
    with warnings.catch_warnings(record=True) as warning_list:
        await _run_select_1(unsafe_skip_file_permissions_check=False)
    permission_warnings = [
        w for w in warning_list if "Bad owner or permissions" in str(w.message)
    ]
    assert (
        len(permission_warnings) > 0
    ), "Expected permission warning when unsafe_skip_file_permissions_check=False"

    # With the flag - should bypass permission checks and not show warnings
    with warnings.catch_warnings(record=True) as warning_list:
        await _run_select_1(unsafe_skip_file_permissions_check=True)
    permission_warnings = [
        w for w in warning_list if "Bad owner or permissions" in str(w.message)
    ]
    assert (
        len(permission_warnings) == 0
    ), "Expected no permission warning when unsafe_skip_file_permissions_check=True"


# The property snowflake_version is newly introduced and therefore should not be tested on old drivers.
@pytest.mark.skipolddriver
async def test_snowflake_version():
    import re

    conn = await create_connection("default")
    # Assert that conn has a snowflake_version attribute
    assert hasattr(
        conn, "snowflake_version"
    ), "conn should have a snowflake_version attribute"

    # Assert that conn.snowflake_version is a string.
    assert isinstance(
        conn.snowflake_version, str
    ), f"snowflake_version should be a string, but got {type(conn.snowflake_version)}"

    # Assert that conn.snowflake_version is in the format of "x.y.z", where
    # x, y and z are numbers.
    version_pattern = r"^\d+\.\d+\.\d+$"
    assert re.match(
        version_pattern, conn.snowflake_version
    ), f"snowflake_version should match pattern 'x.y.z', but got '{conn.snowflake_version}'"
