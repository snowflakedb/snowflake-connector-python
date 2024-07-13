#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from secrets import token_urlsafe
from textwrap import dedent
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import snowflake.connector
from snowflake.connector.connection import DEFAULT_CONFIGURATION
from snowflake.connector.errors import Error, OperationalError, ProgrammingError
from snowflake.connector.network import SnowflakeRestful

from ..randomize import random_string
from .mock_utils import mock_request_with_action, zero_backoff

try:
    from snowflake.connector.auth import (
        AuthByDefault,
        AuthByOAuth,
        AuthByOkta,
        AuthByWebBrowser,
    )
except ImportError:
    AuthByDefault = AuthByOkta = AuthByOAuth = AuthByWebBrowser = MagicMock

try:  # pragma: no cover
    from snowflake.connector.auth import AuthByUsrPwdMfa
    from snowflake.connector.config_manager import CONFIG_MANAGER
    from snowflake.connector.constants import ENV_VAR_PARTNER, QueryStatus
except ImportError:
    ENV_VAR_PARTNER = "SF_PARTNER"
    QueryStatus = CONFIG_MANAGER = None

    class AuthByUsrPwdMfa(AuthByDefault):
        def __init__(self, password: str, mfa_token: str) -> None:
            pass


def fake_connector(**kwargs) -> snowflake.connector.SnowflakeConnection:
    return snowflake.connector.connect(
        user="user",
        account="account",
        password="testpassword",
        database="TESTDB",
        warehouse="TESTWH",
        **kwargs,
    )


@pytest.fixture
def mock_post_requests(monkeypatch):
    request_body = {}

    def mock_post_request(request, url, headers, json_body, **kwargs):
        nonlocal request_body
        request_body.update(json.loads(json_body))
        return {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN",
                "masterToken": "MASTER_TOKEN",
                "idToken": None,
                "parameters": [{"name": "SERVICE_NAME", "value": "FAKE_SERVICE_NAME"}],
            },
        }

    monkeypatch.setattr(
        snowflake.connector.network.SnowflakeRestful, "_post_request", mock_post_request
    )

    return request_body


def test_connect_with_service_name(mock_post_requests):
    assert fake_connector().service_name == "FAKE_SERVICE_NAME"


@pytest.mark.skip(reason="Mock doesn't work as expected.")
@patch("snowflake.connector.network.SnowflakeRestful._post_request")
def test_connection_ignore_exception(mockSnowflakeRestfulPostRequest):
    def mock_post_request(url, headers, json_body, **kwargs):
        global mock_cnt
        ret = None
        if mock_cnt == 0:
            # return from /v1/login-request
            ret = {
                "success": True,
                "message": None,
                "data": {
                    "token": "TOKEN",
                    "masterToken": "MASTER_TOKEN",
                    "idToken": None,
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "FAKE_SERVICE_NAME"}
                    ],
                },
            }
        elif mock_cnt == 1:
            ret = {
                "success": False,
                "message": "Session gone",
                "data": None,
                "code": 390111,
            }
        mock_cnt += 1
        return ret

    # POST requests mock
    mockSnowflakeRestfulPostRequest.side_effect = mock_post_request

    global mock_cnt
    mock_cnt = 0

    account = "testaccount"
    user = "testuser"

    # connection
    con = snowflake.connector.connect(
        account=account,
        user=user,
        password="testpassword",
        database="TESTDB",
        warehouse="TESTWH",
    )
    # Test to see if closing connection works or raises an exception. If an exception is raised, test will fail.
    con.close()


@pytest.mark.skipolddriver
def test_is_still_running():
    """Checks that is_still_running returns expected results."""
    statuses = [
        (QueryStatus.RUNNING, True),
        (QueryStatus.ABORTING, False),
        (QueryStatus.SUCCESS, False),
        (QueryStatus.FAILED_WITH_ERROR, False),
        (QueryStatus.ABORTED, False),
        (QueryStatus.QUEUED, True),
        (QueryStatus.FAILED_WITH_INCIDENT, False),
        (QueryStatus.DISCONNECTED, False),
        (QueryStatus.RESUMING_WAREHOUSE, True),
        (QueryStatus.QUEUED_REPARING_WAREHOUSE, True),
        (QueryStatus.RESTARTED, False),
        (QueryStatus.BLOCKED, True),
        (QueryStatus.NO_DATA, True),
    ]
    for status, expected_result in statuses:
        assert (
            snowflake.connector.SnowflakeConnection.is_still_running(status)
            == expected_result
        )


@pytest.mark.skipolddriver
def test_partner_env_var(mock_post_requests):
    PARTNER_NAME = "Amanda"

    with patch.dict(os.environ, {ENV_VAR_PARTNER: PARTNER_NAME}):
        assert fake_connector().application == PARTNER_NAME

    assert (
        mock_post_requests["data"]["CLIENT_ENVIRONMENT"]["APPLICATION"] == PARTNER_NAME
    )


@pytest.mark.skipolddriver
def test_imported_module(mock_post_requests):
    with patch.dict(sys.modules, {"streamlit": "foo"}):
        assert fake_connector().application == "streamlit"

    assert (
        mock_post_requests["data"]["CLIENT_ENVIRONMENT"]["APPLICATION"] == "streamlit"
    )


@pytest.mark.parametrize(
    "auth_class",
    (
        pytest.param(
            type("auth_class", (AuthByDefault,), {})("my_secret_password"),
            id="AuthByDefault",
        ),
        pytest.param(
            type("auth_class", (AuthByOAuth,), {})("my_token"),
            id="AuthByOAuth",
        ),
        pytest.param(
            type("auth_class", (AuthByOkta,), {})("Python connector"),
            id="AuthByOkta",
        ),
        pytest.param(
            type("auth_class", (AuthByUsrPwdMfa,), {})("password", "mfa_token"),
            id="AuthByUsrPwdMfa",
        ),
        pytest.param(
            type("auth_class", (AuthByWebBrowser,), {})(None, None),
            id="AuthByWebBrowser",
        ),
    ),
)
def test_negative_custom_auth(auth_class):
    """Tests that non-AuthByKeyPair custom auth is not allowed."""
    with pytest.raises(
        TypeError,
        match="auth_class must be a child class of AuthByKeyPair",
    ):
        snowflake.connector.connect(
            account="account",
            user="user",
            auth_class=auth_class,
        )


def test_missing_default_connection(monkeypatch, tmp_path):
    connections_file = tmp_path / "connections.toml"
    config_file = tmp_path / "config.toml"
    with monkeypatch.context() as m:
        m.delenv("SNOWFLAKE_DEFAULT_CONNECTION_NAME", raising=False)
        m.delenv("SNOWFLAKE_CONNECTIONS", raising=False)
        m.setattr(CONFIG_MANAGER, "conf_file_cache", None)
        m.setattr(CONFIG_MANAGER, "file_path", config_file)

        with pytest.raises(
            Error,
            match="Default connection with name 'default' cannot be found, known ones are \\[\\]",
        ):
            snowflake.connector.connect(connections_file_path=connections_file)


def test_missing_default_connection_conf_file(monkeypatch, tmp_path):
    connection_name = random_string(5)
    connections_file = tmp_path / "connections.toml"
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        dedent(
            f"""\
            default_connection_name = "{connection_name}"
            """
        )
    )
    config_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    with monkeypatch.context() as m:
        m.delenv("SNOWFLAKE_DEFAULT_CONNECTION_NAME", raising=False)
        m.delenv("SNOWFLAKE_CONNECTIONS", raising=False)
        m.setattr(CONFIG_MANAGER, "conf_file_cache", None)
        m.setattr(CONFIG_MANAGER, "file_path", config_file)

        with pytest.raises(
            Error,
            match=f"Default connection with name '{connection_name}' cannot be found, known ones are \\[\\]",
        ):
            snowflake.connector.connect(connections_file_path=connections_file)


def test_missing_default_connection_conn_file(monkeypatch, tmp_path):
    connections_file = tmp_path / "connections.toml"
    config_file = tmp_path / "config.toml"
    connections_file.write_text(
        dedent(
            """\
            [con_a]
            user = "test user"
            account = "test account"
            password = "test password"
            """
        )
    )
    connections_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    with monkeypatch.context() as m:
        m.delenv("SNOWFLAKE_DEFAULT_CONNECTION_NAME", raising=False)
        m.delenv("SNOWFLAKE_CONNECTIONS", raising=False)
        m.setattr(CONFIG_MANAGER, "conf_file_cache", None)
        m.setattr(CONFIG_MANAGER, "file_path", config_file)

        with pytest.raises(
            Error,
            match="Default connection with name 'default' cannot be found, known ones are \\['con_a'\\]",
        ):
            snowflake.connector.connect(connections_file_path=connections_file)


def test_missing_default_connection_conf_conn_file(monkeypatch, tmp_path):
    connection_name = random_string(5)
    connections_file = tmp_path / "connections.toml"
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        dedent(
            f"""\
            default_connection_name = "{connection_name}"
            """
        )
    )
    config_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    connections_file.write_text(
        dedent(
            """\
            [con_a]
            user = "test user"
            account = "test account"
            password = "test password"
            """
        )
    )
    connections_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    with monkeypatch.context() as m:
        m.delenv("SNOWFLAKE_DEFAULT_CONNECTION_NAME", raising=False)
        m.delenv("SNOWFLAKE_CONNECTIONS", raising=False)
        m.setattr(CONFIG_MANAGER, "conf_file_cache", None)
        m.setattr(CONFIG_MANAGER, "file_path", config_file)

        with pytest.raises(
            Error,
            match=f"Default connection with name '{connection_name}' cannot be found, known ones are \\['con_a'\\]",
        ):
            snowflake.connector.connect(connections_file_path=connections_file)


def test_invalid_backoff_policy():
    with pytest.raises(ProgrammingError):
        # zero_backoff() is a generator, not a generator function
        _ = fake_connector(backoff_policy=zero_backoff())

    with pytest.raises(ProgrammingError):
        # passing a non-generator function should not work
        _ = fake_connector(backoff_policy=lambda: None)

    with pytest.raises(OperationalError):
        # passing a generator function should make it pass config and error during connection
        _ = fake_connector(backoff_policy=zero_backoff)


@pytest.mark.parametrize("next_action", ("RETRY", "ERROR"))
@patch("snowflake.connector.vendored.requests.sessions.Session.request")
def test_handle_timeout(mockSessionRequest, next_action):
    mockSessionRequest.side_effect = mock_request_with_action(next_action, sleep=5)

    with pytest.raises(OperationalError):
        # no backoff for testing
        _ = fake_connector(
            login_timeout=9,
            backoff_policy=zero_backoff,
        )

    # authenticator should be the only retry mechanism for login requests
    # 9 seconds should be enough for authenticator to attempt twice
    # however, loosen restrictions to avoid thread scheduling causing failure
    assert 1 < mockSessionRequest.call_count < 4


def test__get_private_bytes_from_file(tmp_path: Path):
    private_key_file = tmp_path / "key.pem"

    private_key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=2048
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pkb = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    private_key_file.write_bytes(private_key_pem)

    private_key = snowflake.connector.connection._get_private_bytes_from_file(
        private_key_file=str(private_key_file)
    )

    assert pkb == private_key


def test_private_key_file_reading(tmp_path: Path):
    key_file = tmp_path / "key.pem"

    private_key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=2048
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    key_file.write_bytes(private_key_pem)

    pkb = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    exc_msg = "stop execution"

    with mock.patch(
        "snowflake.connector.auth.keypair.AuthByKeyPair.__init__",
        side_effect=Exception(exc_msg),
    ) as m:
        with pytest.raises(
            Exception,
            match=exc_msg,
        ):
            snowflake.connector.connect(
                account="test_account",
                user="test_user",
                private_key_file=str(key_file),
            )
    assert m.call_count == 1
    assert m.call_args_list[0].kwargs["private_key"] == pkb


def test_encrypted_private_key_file_reading(tmp_path: Path):
    key_file = tmp_path / "key.pem"
    private_key_password = token_urlsafe(25)
    private_key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=2048
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            private_key_password.encode("utf-8")
        ),
    )

    key_file.write_bytes(private_key_pem)

    pkb = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    exc_msg = "stop execution"

    with mock.patch(
        "snowflake.connector.auth.keypair.AuthByKeyPair.__init__",
        side_effect=Exception(exc_msg),
    ) as m:
        with pytest.raises(
            Exception,
            match=exc_msg,
        ):
            snowflake.connector.connect(
                account="test_account",
                user="test_user",
                private_key_file=str(key_file),
                private_key_file_pwd=private_key_password,
            )
    assert m.call_count == 1
    assert m.call_args_list[0].kwargs["private_key"] == pkb


def test_expired_detection():
    with mock.patch(
        "snowflake.connector.network.SnowflakeRestful._post_request",
        return_value={
            "data": {
                "masterToken": "some master token",
                "token": "some token",
                "validityInSeconds": 3600,
                "masterValidityInSeconds": 14400,
                "displayUserName": "TEST_USER",
                "serverVersion": "7.42.0",
            },
            "code": None,
            "message": None,
            "success": True,
        },
    ):
        conn = fake_connector()
    assert not conn.expired
    with conn.cursor() as cur:
        with mock.patch(
            "snowflake.connector.network.SnowflakeRestful.fetch",
            return_value={
                "data": {
                    "errorCode": "390114",
                    "reAuthnMethods": ["USERNAME_PASSWORD"],
                },
                "code": "390114",
                "message": "Authentication token has expired.  The user must authenticate again.",
                "success": False,
                "headers": None,
            },
        ):
            with pytest.raises(ProgrammingError):
                cur.execute("select 1;")
    assert conn.expired


@pytest.mark.skipolddriver
def test_disable_saml_url_check_config():
    with mock.patch(
        "snowflake.connector.network.SnowflakeRestful._post_request",
        return_value={
            "data": {
                "serverVersion": "a.b.c",
            },
            "code": None,
            "message": None,
            "success": True,
        },
    ):
        conn = fake_connector()
        assert (
            conn._disable_saml_url_check
            == DEFAULT_CONFIGURATION.get("disable_saml_url_check")[0]
        )


def test_request_guid():
    assert (
        SnowflakeRestful.add_request_guid(
            "https://test.snowflakecomputing.com"
        ).startswith("https://test.snowflakecomputing.com?request_guid=")
        and SnowflakeRestful.add_request_guid(
            "http://test.snowflakecomputing.cn?a=b"
        ).startswith("http://test.snowflakecomputing.cn?a=b&request_guid=")
        and SnowflakeRestful.add_request_guid(
            "https://test.snowflakecomputing.com.cn"
        ).startswith("https://test.snowflakecomputing.com.cn?request_guid=")
        and SnowflakeRestful.add_request_guid("https://test.abc.cn?a=b")
        == "https://test.abc.cn?a=b"
    )
