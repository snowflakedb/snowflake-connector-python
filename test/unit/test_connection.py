#!/usr/bin/env python
from __future__ import annotations

import json
import logging
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
from snowflake.connector.errors import (
    Error,
    HttpError,
    OperationalError,
    ProgrammingError,
)
from snowflake.connector.network import SnowflakeRestful
from snowflake.connector.wif_util import AttestationProvider

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
    import snowflake.connector.vendored.requests as requests
    from snowflake.connector.auth import AuthByUsrPwdMfa
    from snowflake.connector.config_manager import CONFIG_MANAGER
    from snowflake.connector.constants import (
        _CONNECTIVITY_ERR_MSG,
        ENV_VAR_PARTNER,
        QueryStatus,
    )
except ImportError:
    ENV_VAR_PARTNER = "SF_PARTNER"
    QueryStatus = CONFIG_MANAGER = None

    class AuthByUsrPwdMfa(AuthByDefault):
        def __init__(self, password: str, mfa_token: str) -> None:
            pass


@pytest.fixture(autouse=True)
def mock_detect_platforms():
    with patch(
        "snowflake.connector.auth._auth.detect_platforms", return_value=[]
    ) as mock_detect:
        yield mock_detect


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


def write_temp_file(file_path: Path, contents: str) -> Path:
    """Write the given string text to the given path, chmods it to be accessible, and returns the same path."""
    file_path.write_text(contents)
    file_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return file_path


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
@pytest.mark.parametrize(
    "sys_modules,application",
    [
        ({"streamlit": None}, "streamlit"),
        (
            {"ipykernel": None, "jupyter_core": None, "jupyter_client": None},
            "jupyter_notebook",
        ),
        ({"snowbooks": None}, "snowflake_notebook"),
    ],
)
def test_imported_module(mock_post_requests, sys_modules, application):
    with patch.dict(sys.modules, sys_modules):
        assert fake_connector().application == application

    assert (
        mock_post_requests["data"]["CLIENT_ENVIRONMENT"]["APPLICATION"] == application
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

    with pytest.raises(HttpError):
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


@pytest.mark.skipolddriver
def test_ssl_error_hint(caplog):
    from snowflake.connector.vendored.requests.exceptions import SSLError

    with mock.patch(
        "snowflake.connector.vendored.requests.sessions.Session.request",
        side_effect=SSLError("SSL error"),
    ), caplog.at_level(logging.DEBUG):
        with pytest.raises(OperationalError) as exc:
            fake_connector()
    assert _CONNECTIVITY_ERR_MSG in exc.value.msg and isinstance(
        exc.value, OperationalError
    )
    assert "SSL error" in caplog.text and _CONNECTIVITY_ERR_MSG in caplog.text


def test_otel_error_message(caplog, mock_post_requests):
    """This test assumes that OpenTelemetry is not installed when tests are running."""
    with mock.patch("snowflake.connector.network.SnowflakeRestful._post_request"):
        with caplog.at_level(logging.DEBUG):
            with fake_connector():
                ...
    assert caplog.records
    important_records = [
        record
        for record in caplog.records
        if "Opentelemtry otel injection failed" in record.message
    ]
    assert len(important_records) == 1
    assert important_records[0].exc_text is not None


@pytest.mark.parametrize(
    "dependent_param,value",
    [
        ("workload_identity_provider", "AWS"),
        (
            "workload_identity_entra_resource",
            "api://0b2f151f-09a2-46eb-ad5a-39d5ebef917b",
        ),
    ],
)
def test_cannot_set_dependent_params_without_wlid_authenticator(
    mock_post_requests, dependent_param, value
):
    with pytest.raises(ProgrammingError) as excinfo:
        snowflake.connector.connect(
            user="user",
            account="account",
            password="password",
            **{dependent_param: value},
        )
    assert (
        f"{dependent_param} was set but authenticator was not set to WORKLOAD_IDENTITY"
        in str(excinfo.value)
    )


def test_cannot_set_wlid_authenticator_without_env_variable(mock_post_requests):
    with pytest.raises(ProgrammingError) as excinfo:
        snowflake.connector.connect(
            account="account", authenticator="WORKLOAD_IDENTITY"
        )
    assert (
        "Please set the 'SF_ENABLE_EXPERIMENTAL_AUTHENTICATION' environment variable true to use the 'WORKLOAD_IDENTITY' authenticator"
        in str(excinfo.value)
    )


def test_connection_params_are_plumbed_into_authbyworkloadidentity(monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(
            "snowflake.connector.SnowflakeConnection._authenticate", lambda *_: None
        )
        m.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")

        conn = snowflake.connector.connect(
            account="my_account_1",
            workload_identity_provider=AttestationProvider.AWS,
            workload_identity_entra_resource="api://0b2f151f-09a2-46eb-ad5a-39d5ebef917b",
            token="my_token",
            authenticator="WORKLOAD_IDENTITY",
        )
        assert conn.auth_class.provider == AttestationProvider.AWS
        assert (
            conn.auth_class.entra_resource
            == "api://0b2f151f-09a2-46eb-ad5a-39d5ebef917b"
        )
        assert conn.auth_class.token == "my_token"


def test_toml_connection_params_are_plumbed_into_authbyworkloadidentity(
    monkeypatch, tmp_path
):
    token_file = write_temp_file(tmp_path / "token.txt", contents="my_token")
    # On Windows, this path includes backslashes which will result in errors while parsing the TOML.
    # Escape the backslashes to ensure it parses correctly.
    token_file_path_escaped = str(token_file).replace("\\", "\\\\")
    connections_file = write_temp_file(
        tmp_path / "connections.toml",
        contents=dedent(
            f"""\
        [default]
        account = "my_account_1"
        authenticator = "WORKLOAD_IDENTITY"
        workload_identity_provider = "OIDC"
        workload_identity_entra_resource = "api://0b2f151f-09a2-46eb-ad5a-39d5ebef917b"
        token_file_path = "{token_file_path_escaped}"
        """
        ),
    )

    with monkeypatch.context() as m:
        m.setattr(
            "snowflake.connector.SnowflakeConnection._authenticate", lambda *_: None
        )
        m.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")

        conn = snowflake.connector.connect(connections_file_path=connections_file)
        assert conn.auth_class.provider == AttestationProvider.OIDC
        assert (
            conn.auth_class.entra_resource
            == "api://0b2f151f-09a2-46eb-ad5a-39d5ebef917b"
        )
        assert conn.auth_class.token == "my_token"


@pytest.mark.parametrize("rtr_enabled", [True, False])
def test_single_use_refresh_tokens_option_is_plumbed_into_authbyauthcode(
    monkeypatch, rtr_enabled: bool
):
    with monkeypatch.context() as m:
        m.setattr(
            "snowflake.connector.SnowflakeConnection._authenticate", lambda *_: None
        )
        m.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")

        conn = snowflake.connector.connect(
            account="my_account_1",
            user="user",
            oauth_client_id="client_id",
            oauth_client_secret="client_secret",
            authenticator="OAUTH_AUTHORIZATION_CODE",
            oauth_enable_single_use_refresh_tokens=rtr_enabled,
        )
        assert conn.auth_class._enable_single_use_refresh_tokens == rtr_enabled


@pytest.mark.skipolddriver
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
def test_large_query_through_proxy(
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
    proxy_env_vars,
    proxy_method,
):
    target_wm, proxy_wm = wiremock_target_proxy_pair

    password_mapping = wiremock_mapping_dir / "auth/password/successful_flow.json"
    multi_chunk_request_mapping = (
        wiremock_mapping_dir / "queries/select_large_request_successful.json"
    )
    disconnect_mapping = (
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    telemetry_mapping = wiremock_generic_mappings_dir / "telemetry.json"
    chunk_1_mapping = wiremock_mapping_dir / "queries/chunk_1.json"
    chunk_2_mapping = wiremock_mapping_dir / "queries/chunk_2.json"

    # Configure mappings with proxy header verification
    expected_headers = {"Via": {"contains": "wiremock"}}

    target_wm.import_mapping(password_mapping, expected_headers=expected_headers)
    target_wm.add_mapping_with_default_placeholders(
        multi_chunk_request_mapping, expected_headers
    )
    target_wm.add_mapping(disconnect_mapping, expected_headers=expected_headers)
    target_wm.add_mapping(telemetry_mapping, expected_headers=expected_headers)
    target_wm.add_mapping_with_default_placeholders(chunk_1_mapping, expected_headers)
    target_wm.add_mapping_with_default_placeholders(chunk_2_mapping, expected_headers)

    # Configure proxy based on test parameter
    set_proxy_env_vars, clear_proxy_env_vars = proxy_env_vars
    connect_kwargs = {
        "user": "testUser",
        "password": "testPassword",
        "account": "testAccount",
        "host": target_wm.wiremock_host,
        "port": target_wm.wiremock_http_port,
        "protocol": "http",
        "warehouse": "TEST_WH",
    }

    if proxy_method == "explicit_args":
        connect_kwargs.update(
            {
                "proxy_host": proxy_wm.wiremock_host,
                "proxy_port": str(proxy_wm.wiremock_http_port),
                "proxy_user": "proxyUser",
                "proxy_password": "proxyPass",
            }
        )
        clear_proxy_env_vars()  # Ensure no env vars interfere
    else:  # env_vars
        proxy_url = f"http://proxyUser:proxyPass@{proxy_wm.wiremock_host}:{proxy_wm.wiremock_http_port}"
        set_proxy_env_vars(proxy_url)

    row_count = 50_000
    with snowflake.connector.connect(**connect_kwargs) as conn:
        cursors = conn.execute_string(
            f"select seq4() as n from table(generator(rowcount => {row_count}));"
        )
        assert len(cursors[0]._result_set.batches) > 1  # We need to have remote results
    assert list(cursors[0])

    # Ensure proxy saw query
    proxy_reqs = requests.get(f"{proxy_wm.http_host_with_port}/__admin/requests").json()
    assert any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in proxy_reqs["requests"]
    )

    # Ensure backend saw query
    target_reqs = requests.get(
        f"{target_wm.http_host_with_port}/__admin/requests"
    ).json()
    assert any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in target_reqs["requests"]
    )
