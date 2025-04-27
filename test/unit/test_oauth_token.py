#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import logging
import pathlib
from threading import Thread
from typing import Any, Generator, Union
from unittest import mock
from unittest.mock import Mock, patch

import pytest
import requests

import snowflake.connector
from snowflake.connector.auth import AuthByOauthCredentials
from snowflake.connector.token_cache import TokenCache, TokenKey, TokenType

from ..wiremock.wiremock_utils import WiremockClient

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def wiremock_client() -> Generator[Union[WiremockClient, Any], Any, None]:
    with WiremockClient() as client:
        yield client


@pytest.fixture(scope="session")
def wiremock_oauth_authorization_code_dir() -> pathlib.Path:
    return (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "oauth"
        / "authorization_code"
    )


@pytest.fixture(scope="session")
def wiremock_oauth_client_creds_dir() -> pathlib.Path:
    return (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "oauth"
        / "client_credentials"
    )


@pytest.fixture(scope="session")
def wiremock_generic_mappings_dir() -> pathlib.Path:
    return (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "generic"
    )


@pytest.fixture(scope="session")
def wiremock_oauth_refresh_token_dir() -> pathlib.Path:
    return (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "oauth"
        / "refresh_token"
    )


def _call_auth_server(url: str):
    requests.get(url, allow_redirects=True, timeout=6)


def _webbrowser_redirect(*args):
    assert len(args) == 1, "Invalid number of arguments passed to webbrowser open"

    thread = Thread(target=_call_auth_server, args=(args[0],))
    thread.start()

    return thread.is_alive()


@pytest.fixture(scope="session")
def webbrowser_mock() -> Mock:
    webbrowser_mock = Mock()
    webbrowser_mock.open = _webbrowser_redirect
    return webbrowser_mock


@pytest.fixture()
def temp_cache():
    class TemporaryCache(TokenCache):
        def __init__(self):
            self._cache = {}

        def store(self, key: TokenKey, token: str) -> None:
            self._cache[(key.user, key.host, key.tokenType)] = token

        def retrieve(self, key: TokenKey) -> str:
            return self._cache.get((key.user, key.host, key.tokenType))

        def remove(self, key: TokenKey) -> None:
            self._cache.pop((key.user, key.host, key.tokenType))

    tmp_cache = TemporaryCache()
    with mock.patch(
        "snowflake.connector.auth._auth.Auth.get_token_cache", return_value=tmp_cache
    ):
        yield tmp_cache


@pytest.fixture()
def omit_oauth_urls_check():
    with mock.patch(
        "snowflake.connector.SnowflakeConnection._check_oauth_parameters",
        return_value=None,
    ):
        yield


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_oauth_code_successful_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    wiremock_generic_mappings_dir,
    webbrowser_mock,
    monkeypatch,
    omit_oauth_urls_check,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    wiremock_client.import_mapping(
        wiremock_oauth_authorization_code_dir / "successful_flow.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )

    with mock.patch("webbrowser.open", new=webbrowser_mock.open):
        with mock.patch("secrets.token_urlsafe", return_value="abc123"):
            cnx = snowflake.connector.connect(
                user="testUser",
                authenticator="OAUTH_AUTHORIZATION_CODE",
                oauth_client_id="123",
                account="testAccount",
                protocol="http",
                role="ANALYST",
                oauth_client_secret="testClientSecret",
                oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                oauth_redirect_uri="http://localhost:8009/snowflake/oauth-redirect",
                host=wiremock_client.wiremock_host,
                port=wiremock_client.wiremock_http_port,
            )

            assert cnx, "invalid cnx"
            cnx.close()


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_oauth_code_invalid_state(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    webbrowser_mock,
    monkeypatch,
    omit_oauth_urls_check,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    wiremock_client.import_mapping(
        wiremock_oauth_authorization_code_dir / "invalid_state_error.json"
    )

    with pytest.raises(snowflake.connector.DatabaseError) as execinfo:
        with mock.patch("webbrowser.open", new=webbrowser_mock.open):
            with mock.patch("secrets.token_urlsafe", return_value="abc123"):
                snowflake.connector.connect(
                    user="testUser",
                    authenticator="OAUTH_AUTHORIZATION_CODE",
                    oauth_client_id="123",
                    oauth_client_secret="testClientSecret",
                    account="testAccount",
                    protocol="http",
                    role="ANALYST",
                    oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                    oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                    oauth_redirect_uri="http://localhost:8009/snowflake/oauth-redirect",
                    host=wiremock_client.wiremock_host,
                    port=wiremock_client.wiremock_http_port,
                )

    assert str(execinfo.value).endswith("State changed during OAuth process.")


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_oauth_code_scope_error(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    webbrowser_mock,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    wiremock_client.import_mapping(
        wiremock_oauth_authorization_code_dir / "invalid_scope_error.json"
    )

    with pytest.raises(snowflake.connector.DatabaseError) as execinfo:
        with mock.patch("webbrowser.open", new=webbrowser_mock.open):
            with mock.patch("secrets.token_urlsafe", return_value="abc123"):
                snowflake.connector.connect(
                    user="testUser",
                    authenticator="OAUTH_AUTHORIZATION_CODE",
                    oauth_client_id="123",
                    account="testAccount",
                    protocol="http",
                    role="ANALYST",
                    oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                    oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                    oauth_redirect_uri="http://localhost:8009/snowflake/oauth-redirect",
                    host=wiremock_client.wiremock_host,
                    port=wiremock_client.wiremock_http_port,
                )

        assert str(execinfo.value).endswith(
            "Oauth callback returned an invalid_scope error: One or more scopes are not configured for the authorization server resource."
        )


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_oauth_code_token_request_error(
    wiremock_oauth_authorization_code_dir,
    webbrowser_mock,
    monkeypatch,
    omit_oauth_urls_check,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    with WiremockClient() as wiremock_client:
        wiremock_client.import_mapping(
            wiremock_oauth_authorization_code_dir / "token_request_error.json"
        )

        with pytest.raises(snowflake.connector.DatabaseError) as execinfo:
            with mock.patch("webbrowser.open", new=webbrowser_mock.open):
                with mock.patch("secrets.token_urlsafe", return_value="abc123"):
                    snowflake.connector.connect(
                        user="testUser",
                        authenticator="OAUTH_AUTHORIZATION_CODE",
                        oauth_client_id="123",
                        oauth_client_secret="testClientSecret",
                        account="testAccount",
                        protocol="http",
                        role="ANALYST",
                        oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                        oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                        oauth_redirect_uri="http://localhost:8009/snowflake/oauth-redirect",
                        host=wiremock_client.wiremock_host,
                        port=wiremock_client.wiremock_http_port,
                    )

        assert str(execinfo.value).endswith(
            "Invalid HTTP request from web browser. Idp authentication could have failed."
        )


@pytest.mark.skipolddriver
def test_oauth_code_browser_timeout(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    webbrowser_mock,
    monkeypatch,
    omit_oauth_urls_check,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    wiremock_client.import_mapping(
        wiremock_oauth_authorization_code_dir
        / "browser_timeout_authorization_error.json"
    )

    with pytest.raises(snowflake.connector.DatabaseError) as execinfo:
        with mock.patch("webbrowser.open", new=webbrowser_mock.open):
            with mock.patch("secrets.token_urlsafe", return_value="abc123"):
                snowflake.connector.connect(
                    user="testUser",
                    authenticator="OAUTH_AUTHORIZATION_CODE",
                    oauth_client_id="123",
                    oauth_client_secret="testClientSecret",
                    account="testAccount",
                    protocol="http",
                    role="ANALYST",
                    oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                    oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                    oauth_redirect_uri="http://localhost:8009/snowflake/oauth-redirect",
                    host=wiremock_client.wiremock_host,
                    port=wiremock_client.wiremock_http_port,
                    external_browser_timeout=2,
                )

    assert str(execinfo.value).endswith(
        "Unable to receive the OAuth message within a given timeout. Please check the redirect URI and try again."
    )


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_oauth_code_custom_urls(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    wiremock_generic_mappings_dir,
    webbrowser_mock,
    monkeypatch,
    omit_oauth_urls_check,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    wiremock_client.import_mapping(
        wiremock_oauth_authorization_code_dir / "external_idp_custom_urls.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )

    with mock.patch("webbrowser.open", new=webbrowser_mock.open):
        with mock.patch("secrets.token_urlsafe", return_value="abc123"):
            cnx = snowflake.connector.connect(
                user="testUser",
                authenticator="OAUTH_AUTHORIZATION_CODE",
                oauth_client_id="123",
                oauth_client_secret="testClientSecret",
                account="testAccount",
                protocol="http",
                role="ANALYST",
                oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/tokenrequest",
                oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/authorization",
                oauth_redirect_uri="http://localhost:8009/snowflake/oauth-redirect",
                host=wiremock_client.wiremock_host,
                port=wiremock_client.wiremock_http_port,
            )

            assert cnx, "invalid cnx"
            cnx.close()


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_oauth_code_successful_refresh_token_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_refresh_token_dir,
    wiremock_generic_mappings_dir,
    monkeypatch,
    temp_cache,
    omit_oauth_urls_check,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    wiremock_client.import_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_failed.json"
    )
    wiremock_client.add_mapping(
        wiremock_oauth_refresh_token_dir / "refresh_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    user = "testUser"
    access_token_key = TokenKey(
        user, wiremock_client.wiremock_host, TokenType.OAUTH_ACCESS_TOKEN
    )
    refresh_token_key = TokenKey(
        user, wiremock_client.wiremock_host, TokenType.OAUTH_REFRESH_TOKEN
    )
    temp_cache.store(access_token_key, "expired-access-token-123")
    temp_cache.store(refresh_token_key, "refresh-token-123")
    cnx = snowflake.connector.connect(
        user=user,
        authenticator="OAUTH_AUTHORIZATION_CODE",
        oauth_client_id="123",
        account="testAccount",
        protocol="http",
        role="ANALYST",
        oauth_client_secret="testClientSecret",
        oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
        oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
        oauth_redirect_uri="http://localhost:8009/snowflake/oauth-redirect",
        host=wiremock_client.wiremock_host,
        port=wiremock_client.wiremock_http_port,
        oauth_enable_refresh_tokens=True,
        client_store_temporary_credential=True,
    )
    assert cnx, "invalid cnx"
    cnx.close()
    new_access_token = temp_cache.retrieve(access_token_key)
    new_refresh_token = temp_cache.retrieve(refresh_token_key)

    assert new_access_token == "access-token-123"
    assert new_refresh_token == "refresh-token-123"


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_oauth_code_expired_refresh_token_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_refresh_token_dir,
    wiremock_oauth_authorization_code_dir,
    wiremock_generic_mappings_dir,
    webbrowser_mock,
    monkeypatch,
    temp_cache,
    omit_oauth_urls_check,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    wiremock_client.import_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_failed.json"
    )
    wiremock_client.add_mapping(
        wiremock_oauth_refresh_token_dir / "refresh_failed.json"
    )
    wiremock_client.add_mapping(
        wiremock_oauth_authorization_code_dir
        / "successful_auth_after_failed_refresh.json"
    )
    wiremock_client.add_mapping(
        wiremock_oauth_authorization_code_dir / "new_tokens_after_failed_refresh.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )

    user = "testUser"
    access_token_key = TokenKey(
        user, wiremock_client.wiremock_host, TokenType.OAUTH_ACCESS_TOKEN
    )
    refresh_token_key = TokenKey(
        user, wiremock_client.wiremock_host, TokenType.OAUTH_REFRESH_TOKEN
    )
    temp_cache.store(access_token_key, "expired-access-token-123")
    temp_cache.store(refresh_token_key, "expired-refresh-token-123")
    with mock.patch("webbrowser.open", new=webbrowser_mock.open):
        with mock.patch("secrets.token_urlsafe", return_value="abc123"):
            cnx = snowflake.connector.connect(
                user=user,
                authenticator="OAUTH_AUTHORIZATION_CODE",
                oauth_client_id="123",
                account="testAccount",
                protocol="http",
                role="ANALYST",
                oauth_client_secret="testClientSecret",
                oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                oauth_redirect_uri="http://localhost:8009/snowflake/oauth-redirect",
                host=wiremock_client.wiremock_host,
                port=wiremock_client.wiremock_http_port,
                oauth_enable_refresh_tokens=True,
                client_store_temporary_credential=True,
            )
            assert cnx, "invalid cnx"
            cnx.close()

    new_access_token = temp_cache.retrieve(access_token_key)
    new_refresh_token = temp_cache.retrieve(refresh_token_key)
    assert new_access_token == "access-token-123"
    assert new_refresh_token == "refresh-token-123"


@pytest.mark.skipolddriver
def test_client_creds_oauth_type():
    """Simple OAuth Client credentials type test."""
    auth = AuthByOauthCredentials(
        "app",
        "clientId",
        "clientSecret",
        "auth_url",
        "tokenRequestUrl",
        "scope",
    )
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["OAUTH_TYPE"] == "client_credentials"


@pytest.mark.skipolddriver
def test_client_creds_successful_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_client_creds_dir,
    wiremock_generic_mappings_dir,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")
    wiremock_client.import_mapping(
        wiremock_oauth_client_creds_dir / "successful_flow.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    with mock.patch("secrets.token_urlsafe", return_value="abc123"):
        cnx = snowflake.connector.connect(
            user="testUser",
            authenticator="OAUTH_CLIENT_CREDENTIALS",
            oauth_client_id="123",
            oauth_client_secret="123",
            account="testAccount",
            protocol="http",
            role="ANALYST",
            oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
            host=wiremock_client.wiremock_host,
            port=wiremock_client.wiremock_http_port,
        )

        assert cnx, "invalid cnx"
        cnx.close()


@pytest.mark.skipolddriver
def test_client_creds_token_request_error(
    wiremock_client: WiremockClient,
    wiremock_oauth_client_creds_dir,
    wiremock_generic_mappings_dir,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")
    wiremock_client.import_mapping(
        wiremock_oauth_client_creds_dir / "token_request_error.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )

    with pytest.raises(snowflake.connector.DatabaseError) as execinfo:
        with mock.patch("secrets.token_urlsafe", return_value="abc123"):
            snowflake.connector.connect(
                user="testUser",
                authenticator="OAUTH_CLIENT_CREDENTIALS",
                oauth_client_id="123",
                oauth_client_secret="123",
                account="testAccount",
                protocol="http",
                role="ANALYST",
                oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                host=wiremock_client.wiremock_host,
                port=wiremock_client.wiremock_http_port,
            )

        assert str(execinfo.value).endswith(
            "Invalid HTTP request from web browser. Idp authentication could have failed."
        )


@pytest.mark.skipolddriver
def test_client_creds_successful_refresh_token_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_refresh_token_dir,
    wiremock_generic_mappings_dir,
    monkeypatch,
    temp_cache,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")

    wiremock_client.import_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_failed.json"
    )
    wiremock_client.add_mapping(
        wiremock_oauth_refresh_token_dir / "refresh_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    user = "testUser"
    access_token_key = TokenKey(
        user, wiremock_client.wiremock_host, TokenType.OAUTH_ACCESS_TOKEN
    )
    refresh_token_key = TokenKey(
        user, wiremock_client.wiremock_host, TokenType.OAUTH_REFRESH_TOKEN
    )
    temp_cache.store(access_token_key, "expired-access-token-123")
    temp_cache.store(refresh_token_key, "refresh-token-123")
    cnx = snowflake.connector.connect(
        user=user,
        authenticator="OAUTH_CLIENT_CREDENTIALS",
        oauth_client_id="123",
        account="testAccount",
        protocol="http",
        role="ANALYST",
        oauth_client_secret="testClientSecret",
        oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
        host=wiremock_client.wiremock_host,
        port=wiremock_client.wiremock_http_port,
        oauth_enable_refresh_tokens=True,
        client_store_temporary_credential=True,
    )
    assert cnx, "invalid cnx"
    cnx.close()

    new_access_token = temp_cache.retrieve(access_token_key)
    new_refresh_token = temp_cache.retrieve(refresh_token_key)
    assert new_access_token == "access-token-123"
    assert new_refresh_token == "refresh-token-123"


@pytest.mark.skipolddriver
def test_client_creds_expired_refresh_token_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_refresh_token_dir,
    wiremock_oauth_client_creds_dir,
    wiremock_generic_mappings_dir,
    webbrowser_mock,
    monkeypatch,
    temp_cache,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "true")

    wiremock_client.import_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_failed.json"
    )
    wiremock_client.add_mapping(
        wiremock_oauth_refresh_token_dir / "refresh_failed.json"
    )
    wiremock_client.add_mapping(
        wiremock_oauth_client_creds_dir / "successful_auth_after_failed_refresh.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )

    user = "testUser"
    access_token_key = TokenKey(
        user, wiremock_client.wiremock_host, TokenType.OAUTH_ACCESS_TOKEN
    )
    refresh_token_key = TokenKey(
        user, wiremock_client.wiremock_host, TokenType.OAUTH_REFRESH_TOKEN
    )
    temp_cache.store(access_token_key, "expired-access-token-123")
    temp_cache.store(refresh_token_key, "expired-refresh-token-123")
    cnx = snowflake.connector.connect(
        user=user,
        authenticator="OAUTH_CLIENT_CREDENTIALS",
        oauth_client_id="123",
        account="testAccount",
        protocol="http",
        role="ANALYST",
        oauth_client_secret="testClientSecret",
        oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
        host=wiremock_client.wiremock_host,
        port=wiremock_client.wiremock_http_port,
        oauth_enable_refresh_tokens=True,
        client_store_temporary_credential=True,
    )
    assert cnx, "invalid cnx"
    cnx.close()

    new_access_token = temp_cache.retrieve(access_token_key)
    new_refresh_token = temp_cache.retrieve(refresh_token_key)
    assert new_access_token == "access-token-123"
    assert new_refresh_token == "refresh-token-123"


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "authenticator", ["OAUTH_AUTHORIZATION_CODE", "OAUTH_CLIENT_CREDENTIALS"]
)
def test_auth_is_experimental(
    authenticator,
    monkeypatch,
) -> None:
    monkeypatch.delenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", False)
    with pytest.raises(
        snowflake.connector.ProgrammingError,
        match=r"SF_ENABLE_EXPERIMENTAL_AUTHENTICATION",
    ):
        snowflake.connector.connect(
            user="testUser",
            account="testAccount",
            authenticator=authenticator,
        )


@pytest.mark.skipolddriver
@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "authenticator", ["OAUTH_AUTHORIZATION_CODE", "OAUTH_CLIENT_CREDENTIALS"]
)
def test_auth_experimental_when_variable_set_to_false(
    authenticator,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_ENABLE_EXPERIMENTAL_AUTHENTICATION", "false")
    with pytest.raises(
        snowflake.connector.ProgrammingError,
        match=r"SF_ENABLE_EXPERIMENTAL_AUTHENTICATION",
    ):
        snowflake.connector.connect(
            user="testUser",
            account="testAccount",
            authenticator="OAUTH_CLIENT_CREDENTIALS",
        )
