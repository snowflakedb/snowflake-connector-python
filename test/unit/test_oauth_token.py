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
from snowflake.connector.auth import AuthByOauthCode

from ..wiremock.wiremock_utils import WiremockClient

AUTH_SOCKET_PORT = 8009
logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def wiremock_client() -> Generator[Union[WiremockClient, Any], Any, None]:
    with WiremockClient(forbidden_ports=[AUTH_SOCKET_PORT]) as client:
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


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_successful_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    wiremock_generic_mappings_dir,
    webbrowser_mock,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_AUTH_SOCKET_PORT", str(AUTH_SOCKET_PORT))
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
                oauth_redirect_uri="http://localhost:{port}/snowflake/oauth-redirect",
                host=wiremock_client.wiremock_host,
                port=wiremock_client.wiremock_http_port,
            )

            assert cnx, "invalid cnx"
            cnx.close()


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_invalid_state(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    webbrowser_mock,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_AUTH_SOCKET_PORT", str(AUTH_SOCKET_PORT))
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
                    account="testAccount",
                    protocol="http",
                    role="ANALYST",
                    oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                    oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                    oauth_redirect_uri="http://localhost:{port}/snowflake/oauth-redirect",
                    host=wiremock_client.wiremock_host,
                    port=wiremock_client.wiremock_http_port,
                )

    assert str(execinfo.value).endswith("State changed during OAuth process.")


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_scope_error(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    webbrowser_mock,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_AUTH_SOCKET_PORT", str(AUTH_SOCKET_PORT))
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
                    oauth_redirect_uri="http://localhost:{port}/snowflake/oauth-redirect",
                    host=wiremock_client.wiremock_host,
                    port=wiremock_client.wiremock_http_port,
                )

        assert str(execinfo.value).endswith(
            "Oauth callback returned an invalid_scope error: One or more scopes are not configured for the authorization server resource."
        )


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_token_request_error(
    wiremock_oauth_authorization_code_dir,
    webbrowser_mock,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_AUTH_SOCKET_PORT", str(AUTH_SOCKET_PORT))
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    with WiremockClient(forbidden_ports=[AUTH_SOCKET_PORT]) as wiremock_client:
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
                        account="testAccount",
                        protocol="http",
                        role="ANALYST",
                        oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                        oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                        oauth_redirect_uri="http://localhost:{port}/snowflake/oauth-redirect",
                        host=wiremock_client.wiremock_host,
                        port=wiremock_client.wiremock_http_port,
                    )

        assert str(execinfo.value).endswith(
            "Invalid HTTP request from web browser. Idp authentication could have failed."
        )

        wiremock_client.list_received_requests()


@pytest.mark.skipolddriver
def test_browser_timeout(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    webbrowser_mock,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_AUTH_SOCKET_PORT", str(AUTH_SOCKET_PORT))
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
                    account="testAccount",
                    protocol="http",
                    role="ANALYST",
                    oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                    oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                    oauth_redirect_uri="http://localhost:{port}/snowflake/oauth-redirect",
                    host=wiremock_client.wiremock_host,
                    port=wiremock_client.wiremock_http_port,
                )

    assert str(execinfo.value).endswith(
        "Unable to receive the OAuth message within a given timeout. Please check the redirect URI and try again."
    )


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_custom_urls(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    wiremock_generic_mappings_dir,
    webbrowser_mock,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_AUTH_SOCKET_PORT", str(AUTH_SOCKET_PORT))
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
                account="testAccount",
                protocol="http",
                role="ANALYST",
                oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/tokenrequest",
                oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/authorization",
                oauth_redirect_uri="http://localhost:{port}/snowflake/oauth-redirect",
                host=wiremock_client.wiremock_host,
                port=wiremock_client.wiremock_http_port,
            )

            assert cnx, "invalid cnx"
            cnx.close()

    wiremock_client.list_received_requests()


@pytest.fixture()
def temp_cache():
    class TemporaryCache:
        def __init__(self):
            self._cache = {}

        def read_temporary_credential(
            self,
            account: str,
            user: str,
            cred_type: str,
        ) -> str | None:
            return self._cache.get((account, user, cred_type))

        def write_temporary_credential(
            self,
            account: str,
            user: str,
            cred_type: str,
            value: str,
        ) -> None:
            self._cache[(account, user, cred_type)] = value

        def delete_temporary_credential(
            self,
            account: str,
            user: str,
            cred_type: str,
        ) -> None:
            self._cache.pop((account, user, cred_type))

    tmp_cache = TemporaryCache()
    with (
        mock.patch(
            "snowflake.connector.auth._auth.Auth.write_temporary_credential",
            new=tmp_cache.write_temporary_credential,
        ),
        mock.patch(
            "snowflake.connector.auth._auth.Auth.read_temporary_credential",
            new=tmp_cache.read_temporary_credential,
        ),
        mock.patch(
            "snowflake.connector.auth._auth.Auth.delete_temporary_credential",
            new=tmp_cache.delete_temporary_credential,
        ),
    ):
        yield tmp_cache


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_successful_refresh_token_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_refresh_token_dir,
    wiremock_generic_mappings_dir,
    monkeypatch,
    temp_cache,
) -> None:
    monkeypatch.setenv("SF_AUTH_SOCKET_PORT", str(AUTH_SOCKET_PORT))
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

    account = "testAccount"
    user = "testUser"
    temp_cache.write_temporary_credential(
        account,
        user,
        AuthByOauthCode._ACCESS_TOKEN_CACHE_KEY,
        "expired-access-token-123",
    )
    temp_cache.write_temporary_credential(
        account, user, AuthByOauthCode._REFRESH_TOKEN_CACHE_KEY, "refresh-token-123"
    )
    cnx = snowflake.connector.connect(
        user=user,
        authenticator="OAUTH_AUTHORIZATION_CODE",
        oauth_client_id="123",
        account=account,
        protocol="http",
        role="ANALYST",
        oauth_client_secret="testClientSecret",
        oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
        oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
        oauth_redirect_uri="http://localhost:{port}/snowflake/oauth-redirect",
        host=wiremock_client.wiremock_host,
        port=wiremock_client.wiremock_http_port,
        oauth_security_features=("pkce", "token_cache", "refresh_token"),
    )
    assert cnx, "invalid cnx"
    cnx.close()
    new_access_token = temp_cache.read_temporary_credential(
        account, user, AuthByOauthCode._ACCESS_TOKEN_CACHE_KEY
    )
    new_refresh_token = temp_cache.read_temporary_credential(
        account, user, AuthByOauthCode._REFRESH_TOKEN_CACHE_KEY
    )
    assert new_access_token == "access-token-123"
    assert new_refresh_token == "refresh-token-123"


@pytest.mark.skipolddriver
@patch("snowflake.connector.auth._http_server.AuthHttpServer.DEFAULT_TIMEOUT", 30)
def test_expired_refresh_token_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_refresh_token_dir,
    wiremock_oauth_authorization_code_dir,
    wiremock_generic_mappings_dir,
    webbrowser_mock,
    monkeypatch,
    temp_cache,
) -> None:
    monkeypatch.setenv("SF_AUTH_SOCKET_PORT", str(AUTH_SOCKET_PORT))
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

    account = "testAccount"
    user = "testUser"
    temp_cache.write_temporary_credential(
        account,
        user,
        AuthByOauthCode._ACCESS_TOKEN_CACHE_KEY,
        "expired-access-token-123",
    )
    temp_cache.write_temporary_credential(
        account,
        user,
        AuthByOauthCode._REFRESH_TOKEN_CACHE_KEY,
        "expired-refresh-token-123",
    )
    with (
        mock.patch("webbrowser.open", new=webbrowser_mock.open),
        mock.patch("secrets.token_urlsafe", return_value="abc123"),
    ):
        cnx = snowflake.connector.connect(
            user=user,
            authenticator="OAUTH_AUTHORIZATION_CODE",
            oauth_client_id="123",
            account=account,
            protocol="http",
            role="ANALYST",
            oauth_client_secret="testClientSecret",
            oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
            oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
            oauth_redirect_uri="http://localhost:{port}/snowflake/oauth-redirect",
            host=wiremock_client.wiremock_host,
            port=wiremock_client.wiremock_http_port,
            oauth_security_features=("pkce", "token_cache", "refresh_token"),
        )
        assert cnx, "invalid cnx"
        cnx.close()

    new_access_token = temp_cache.read_temporary_credential(
        account, user, AuthByOauthCode._ACCESS_TOKEN_CACHE_KEY
    )
    new_refresh_token = temp_cache.read_temporary_credential(
        account, user, AuthByOauthCode._REFRESH_TOKEN_CACHE_KEY
    )
    assert new_access_token == "access-token-123"
    assert new_refresh_token == "refresh-token-123"
