#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import logging
import pathlib
from threading import Thread
from unittest import mock
from unittest.mock import Mock, patch

import pytest
import requests

import snowflake.connector
from snowflake.connector.auth import AuthByOauthCredentials
from snowflake.connector.token_cache import TokenCache, TokenKey, TokenType

from ..test_utils.wiremock.wiremock_utils import WiremockClient

logger = logging.getLogger(__name__)


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
    def get_first_two_args(authorization_url: str, redirect_uri: str, *args, **kwargs):
        return authorization_url, redirect_uri

    with mock.patch(
        "snowflake.connector.auth.oauth_code.AuthByOauthCode._validate_oauth_code_uris",
        side_effect=get_first_two_args,
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
def test_oauth_code_local_application_custom_urls_successful_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    wiremock_generic_mappings_dir,
    webbrowser_mock,
    monkeypatch,
    omit_oauth_urls_check,
) -> None:
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    wiremock_client.import_mapping(
        wiremock_oauth_authorization_code_dir
        / "external_idp_custom_urls_local_application.json"
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
                oauth_client_id="",
                oauth_client_secret="",
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
    assert body["data"]["OAUTH_TYPE"] == "oauth_client_credentials"


@pytest.mark.skipolddriver
def test_client_creds_successful_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_client_creds_dir,
    wiremock_generic_mappings_dir,
    monkeypatch,
    temp_cache,
) -> None:
    wiremock_client.import_mapping(
        wiremock_oauth_client_creds_dir / "successful_flow.json"
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
    temp_cache.store(access_token_key, "unused-access-token-123")
    temp_cache.store(refresh_token_key, "unused-refresh-token-123")
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
            oauth_enable_refresh_tokens=True,
            client_store_temporary_credential=True,
        )

        assert cnx, "invalid cnx"
        cnx.close()
    # cached tokens are expected not to change since Client Credenials must not use token cache
    cached_access_token = temp_cache.retrieve(access_token_key)
    cached_refresh_token = temp_cache.retrieve(refresh_token_key)
    assert cached_access_token == "unused-access-token-123"
    assert cached_refresh_token == "unused-refresh-token-123"


@pytest.mark.skipolddriver
def test_client_creds_token_request_error(
    wiremock_client: WiremockClient,
    wiremock_oauth_client_creds_dir,
    wiremock_generic_mappings_dir,
    monkeypatch,
) -> None:
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
def test_client_creds_expired_refresh_token_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_refresh_token_dir,
    wiremock_oauth_client_creds_dir,
    wiremock_generic_mappings_dir,
    webbrowser_mock,
    monkeypatch,
    temp_cache,
) -> None:
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
    # the cache state is expected not to change, since Client Credentials must not use token caching
    cached_access_token = temp_cache.retrieve(access_token_key)
    cached_refresh_token = temp_cache.retrieve(refresh_token_key)
    assert cached_access_token == "expired-access-token-123"
    assert cached_refresh_token == "expired-refresh-token-123"


@pytest.mark.skipolddriver
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
def test_client_credentials_flow_via_explicit_proxy(
    wiremock_oauth_client_creds_dir,
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    temp_cache,
    wiremock_mapping_dir,
    proxy_env_vars,
    proxy_method,
):
    """Spin up two Wiremock instances (target & proxy) via shared fixture and run OAuth Client-Credentials flow through the proxy."""

    target_wm, proxy_wm = wiremock_target_proxy_pair

    # Configure backend (Snowflake + IdP) responses with proxy header verification
    expected_headers = {"Via": {"contains": "wiremock"}}

    target_wm.import_mapping_with_default_placeholders(
        wiremock_oauth_client_creds_dir / "successful_flow.json", expected_headers
    )
    target_wm.add_mapping_with_default_placeholders(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json",
        expected_headers,
    )
    target_wm.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json",
        expected_headers=expected_headers,
    )

    token_request_url = f"http://{target_wm.wiremock_host}:{target_wm.wiremock_http_port}/oauth/token-request"

    # Configure proxy based on test parameter
    set_proxy_env_vars, clear_proxy_env_vars = proxy_env_vars
    connect_kwargs = {
        "user": "testUser",
        "authenticator": "OAUTH_CLIENT_CREDENTIALS",
        "oauth_client_id": "cid",
        "oauth_client_secret": "secret",
        "account": "testAccount",
        "protocol": "http",
        "role": "ANALYST",
        "oauth_token_request_url": token_request_url,
        "host": target_wm.wiremock_host,
        "port": target_wm.wiremock_http_port,
        "oauth_enable_refresh_tokens": True,
        "client_store_temporary_credential": True,
        "token_cache": temp_cache,
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

    with mock.patch("secrets.token_urlsafe", return_value="abc123"):
        cnx = snowflake.connector.connect(**connect_kwargs)
        assert cnx, "Connection object should be valid"
        cnx.close()

    # Verify proxy & backend saw the token request
    proxy_requests = requests.get(
        f"{proxy_wm.http_host_with_port}/__admin/requests"
    ).json()
    assert any(
        req["request"]["url"].endswith("/oauth/token-request")
        for req in proxy_requests["requests"]
    )

    target_requests = requests.get(
        f"{target_wm.http_host_with_port}/__admin/requests"
    ).json()
    assert any(
        req["request"]["url"].endswith("/oauth/token-request")
        for req in target_requests["requests"]
    )


@pytest.mark.skipolddriver
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_oauth_code_successful_flow_through_proxy(
    wiremock_oauth_authorization_code_dir,
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    webbrowser_mock,
    monkeypatch,
    omit_oauth_urls_check,
    proxy_env_vars,
    proxy_method,
) -> None:
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")
    target_wm, proxy_wm = wiremock_target_proxy_pair

    target_wm.import_mapping_with_default_placeholders(
        wiremock_oauth_authorization_code_dir / "successful_flow.json",
    )
    target_wm.add_mapping_with_default_placeholders(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json",
    )
    target_wm.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json",
    )

    # Configure proxy based on test parameter
    set_proxy_env_vars, clear_proxy_env_vars = proxy_env_vars
    connect_kwargs = {
        "user": "testUser",
        "authenticator": "OAUTH_AUTHORIZATION_CODE",
        "oauth_client_id": "123",
        "account": "testAccount",
        "protocol": "http",
        "role": "ANALYST",
        "oauth_client_secret": "testClientSecret",
        "oauth_token_request_url": f"http://{target_wm.wiremock_host}:{target_wm.wiremock_http_port}/oauth/token-request",
        "oauth_authorization_url": f"http://{target_wm.wiremock_host}:{target_wm.wiremock_http_port}/oauth/authorize",
        "oauth_redirect_uri": "http://localhost:8009/snowflake/oauth-redirect",
        "host": target_wm.wiremock_host,
        "port": target_wm.wiremock_http_port,
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

    with mock.patch("webbrowser.open", new=webbrowser_mock.open):
        with mock.patch("secrets.token_urlsafe", return_value="abc123"):
            cnx = snowflake.connector.connect(**connect_kwargs)

            assert cnx, "invalid cnx"
            cnx.close()

        # Verify: proxy Wiremock saw the token request
        proxy_requests = requests.get(
            f"http://{proxy_wm.wiremock_host}:{proxy_wm.wiremock_http_port}/__admin/requests"
        ).json()
        assert any(
            req["request"]["url"].endswith("/oauth/token-request")
            for req in proxy_requests["requests"]
        ), "Proxy did not record token-request"

        # Verify: target Wiremock also saw it (because proxy forwarded)
        target_requests = requests.get(
            f"http://{target_wm.wiremock_host}:{target_wm.wiremock_http_port}/__admin/requests"
        ).json()
        assert any(
            req["request"]["url"].endswith("/oauth/token-request")
            for req in target_requests["requests"]
        ), "Target did not receive token-request forwarded by proxy"
