#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pathlib
from threading import Thread
from typing import Any, Generator, Union
from unittest import mock
from unittest.mock import Mock

import pytest

try:
    from snowflake.connector.vendored import requests
except ImportError:
    import requests


import snowflake.connector

from ..wiremock.wiremock_utils import WiremockClient

AUTH_SOCKET_PORT = 8009


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


def _call_auth_server(url: str):
    response = requests.get(url, allow_redirects=True)
    assert response.status_code == 200, "Invalid status code received from auth server"


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

    # TODO: Is the DatabaseError correct? Possibly ConnectionError would make more sense?
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


# TODO: needs proper handling
@pytest.mark.skipolddriver
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
def test_token_request_error(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    webbrowser_mock,
    monkeypatch,
) -> None:
    monkeypatch.setenv("SF_AUTH_SOCKET_PORT", str(AUTH_SOCKET_PORT))
    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

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

    # TODO: possibly some more descriptive error message would make sense?
    assert str(execinfo.value).endswith(
        "Invalid HTTP request from web browser. Idp authentication could have failed."
    )


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

    # TODO: possibly some more descriptive error message would make sense?
    assert str(execinfo.value).endswith(
        "Invalid HTTP request from web browser. Idp authentication could have failed."
    )


@pytest.mark.skipolddriver
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
