#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import unittest.mock as mock
from test.helpers import apply_auth_class_update_body_async, create_mock_auth_body
from unittest.mock import PropertyMock, patch

import pytest

from snowflake.connector.aio.auth import AuthByOauthCode
from snowflake.connector.errors import ProgrammingError
from snowflake.connector.network import OAUTH_AUTHORIZATION_CODE


@pytest.fixture()
def omit_oauth_urls_check():
    def get_first_two_args(authorization_url: str, redirect_uri: str, *args, **kwargs):
        return authorization_url, redirect_uri

    with mock.patch(
        "snowflake.connector.aio.auth.AuthByOauthCode._validate_oauth_code_uris",
        side_effect=get_first_two_args,
    ):
        yield


async def test_auth_oauth_auth_code_oauth_type(omit_oauth_urls_check):
    """Simple OAuth Auth Code oauth type test."""
    auth = AuthByOauthCode(
        "app",
        "clientId",
        "clientSecret",
        "auth_url",
        "tokenRequestUrl",
        "redirectUri:{port}",
        "scope",
        "host",
    )
    body = {"data": {}}
    await auth.update_body(body)
    assert (
        body["data"]["CLIENT_ENVIRONMENT"]["OAUTH_TYPE"] == "oauth_authorization_code"
    )


async def test_auth_prepare_body_does_not_overwrite_client_environment_fields(
    omit_oauth_urls_check,
):
    auth_class = AuthByOauthCode(
        "app",
        "clientId",
        "clientSecret",
        "auth_url",
        "tokenRequestUrl",
        "redirectUri:{port}",
        "scope",
        "host",
    )

    req_body_before = create_mock_auth_body()
    req_body_after = await apply_auth_class_update_body_async(
        auth_class, req_body_before
    )

    assert all(
        [
            req_body_before["data"]["CLIENT_ENVIRONMENT"][k]
            == req_body_after["data"]["CLIENT_ENVIRONMENT"][k]
            for k in req_body_before["data"]["CLIENT_ENVIRONMENT"]
        ]
    )


@pytest.mark.parametrize("rtr_enabled", [True, False])
async def test_auth_oauth_auth_code_single_use_refresh_tokens(
    rtr_enabled: bool, omit_oauth_urls_check
):
    """Verifies that the enable_single_use_refresh_tokens option is plumbed into the authz code request."""
    auth = AuthByOauthCode(
        "app",
        "clientId",
        "clientSecret",
        "auth_url",
        "tokenRequestUrl",
        "http://127.0.0.1:8080",
        "scope",
        "host",
        pkce_enabled=False,
        enable_single_use_refresh_tokens=rtr_enabled,
    )

    # Note: This must be a sync function because it's mocking a method called from sync code
    def fake_get_request_token_response(_, fields: dict[str, str]):
        if rtr_enabled:
            assert fields.get("enable_single_use_refresh_tokens") == "true"
        else:
            assert "enable_single_use_refresh_tokens" not in fields
        return ("access_token", "refresh_token")

    with patch(
        "snowflake.connector.aio.auth.AuthByOauthCode._do_authorization_request",
        return_value="abc",
    ):
        with patch(
            "snowflake.connector.aio.auth.AuthByOauthCode._get_request_token_response",
            side_effect=fake_get_request_token_response,
        ):
            await auth.prepare(
                conn=None,
                authenticator=OAUTH_AUTHORIZATION_CODE,
                service_name=None,
                account="acc",
                user="user",
            )


@pytest.mark.parametrize(
    "name, client_id, client_secret, host, auth_url, token_url, expected_local, expected_raised_error_cls",
    [
        (
            "Client credentials not supplied and Snowflake as IdP",
            "",
            "",
            "example.snowflakecomputing.com",
            "https://example.snowflakecomputing.com/oauth/authorize",
            "https://example.snowflakecomputing.com/oauth/token",
            True,
            None,
        ),
        (
            "Client credentials not supplied and empty URLs",
            "",
            "",
            "",
            "",
            "",
            True,
            None,
        ),
        (
            "Client credentials supplied",
            "testClientID",
            "testClientSecret",
            "example.snowflakecomputing.com",
            "https://example.snowflakecomputing.com/oauth/authorize",
            "https://example.snowflakecomputing.com/oauth/token",
            False,
            None,
        ),
        (
            "Only client ID supplied",
            "testClientID",
            "",
            "example.snowflakecomputing.com",
            "https://example.snowflakecomputing.com/oauth/authorize",
            "https://example.snowflakecomputing.com/oauth/token",
            False,
            ProgrammingError,
        ),
        (
            "Non-Snowflake IdP",
            "",
            "",
            "example.snowflakecomputing.com",
            "https://example.com/oauth/authorize",
            "https://example.com/oauth/token",
            False,
            ProgrammingError,
        ),
        (
            "[China] Client credentials not supplied and Snowflake as IdP",
            "",
            "",
            "example.snowflakecomputing.cn",
            "https://example.snowflakecomputing.cn/oauth/authorize",
            "https://example.snowflakecomputing.cn/oauth/token",
            True,
            None,
        ),
        (
            "[China] Client credentials supplied",
            "testClientID",
            "testClientSecret",
            "example.snowflakecomputing.cn",
            "https://example.snowflakecomputing.cn/oauth/authorize",
            "https://example.snowflakecomputing.cn/oauth/token",
            False,
            None,
        ),
        (
            "[China] Only client ID supplied",
            "testClientID",
            "",
            "example.snowflakecomputing.cn",
            "https://example.snowflakecomputing.cn/oauth/authorize",
            "https://example.snowflakecomputing.cn/oauth/token",
            False,
            ProgrammingError,
        ),
    ],
)
def test_eligible_for_default_client_credentials_via_constructor(
    name,
    client_id,
    client_secret,
    host,
    auth_url,
    token_url,
    expected_local,
    expected_raised_error_cls,
):
    def assert_initialized_correctly() -> None:
        auth = AuthByOauthCode(
            application="app",
            client_id=client_id,
            client_secret=client_secret,
            authentication_url=auth_url,
            token_request_url=token_url,
            redirect_uri="https://redirectUri:{port}",
            scope="scope",
            host=host,
        )
        if expected_local:
            assert (
                auth._client_id == AuthByOauthCode._LOCAL_APPLICATION_CLIENT_CREDENTIALS
            ), f"{name} - expected LOCAL_APPLICATION as client_id"
            assert (
                auth._client_secret
                == AuthByOauthCode._LOCAL_APPLICATION_CLIENT_CREDENTIALS
            ), f"{name} - expected LOCAL_APPLICATION as client_secret"
        else:
            assert auth._client_id == client_id, f"{name} - expected original client_id"
            assert (
                auth._client_secret == client_secret
            ), f"{name} - expected original client_secret"

    if expected_raised_error_cls is not None:
        with pytest.raises(expected_raised_error_cls):
            assert_initialized_correctly()
    else:
        assert_initialized_correctly()


@pytest.mark.parametrize(
    "authenticator", ["OAUTH_AUTHORIZATION_CODE", "oauth_authorization_code"]
)
async def test_oauth_authorization_code_authenticator_is_case_insensitive(
    monkeypatch, authenticator
):
    """Test that OAuth authorization code authenticator is case insensitive."""
    import snowflake.connector.aio
    from snowflake.connector.aio._network import SnowflakeRestful

    async def mock_post_request(self, url, headers, json_body, **kwargs):
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

    monkeypatch.setattr(SnowflakeRestful, "_post_request", mock_post_request)

    # Mock the OAuth authorization flow to avoid opening browser and starting HTTP server
    # Note: This must be a sync function (not async) because it's called from the sync
    # parent class's prepare() method which calls _request_tokens() without await
    def mock_request_tokens(self, **kwargs):
        # Simulate successful token retrieval
        return ("mock_access_token", "mock_refresh_token")

    monkeypatch.setattr(AuthByOauthCode, "_request_tokens", mock_request_tokens)

    # Create connection with OAuth authorization code authenticator
    conn = snowflake.connector.aio.SnowflakeConnection(
        user="testuser",
        account="testaccount",
        authenticator=authenticator,
        oauth_client_id="test_client_id",
        oauth_client_secret="test_client_secret",
    )

    await conn.connect()

    # Verify that the auth_class is an instance of AuthByOauthCode
    assert isinstance(conn.auth_class, AuthByOauthCode)

    await conn.close()


def test_mro():
    """Ensure that methods from AuthByPluginAsync override those from AuthByPlugin."""
    from snowflake.connector.aio.auth import AuthByPlugin as AuthByPluginAsync
    from snowflake.connector.auth import AuthByPlugin as AuthByPluginSync

    assert AuthByOauthCode.mro().index(AuthByPluginAsync) < AuthByOauthCode.mro().index(
        AuthByPluginSync
    )


@pytest.mark.parametrize("redirect_uri", ["https://redirect/uri"])
@pytest.mark.parametrize("rtr_enabled", [True, False])
async def test_auth_oauth_auth_code_uses_redirect_uri(
    redirect_uri, rtr_enabled: bool, omit_oauth_urls_check
):
    """Test that the redirect URI is used correctly in the OAuth authorization code flow."""
    auth = AuthByOauthCode(
        "app",
        "clientId",
        "clientSecret",
        "auth_url",
        "tokenRequestUrl",
        redirect_uri,
        "scope",
        "host",
        pkce_enabled=False,
        enable_single_use_refresh_tokens=rtr_enabled,
        uri="http://localhost:0",
    )

    def fake_get_request_token_response(_, fields: dict[str, str]):
        if rtr_enabled:
            assert fields.get("enable_single_use_refresh_tokens") == "true"
        else:
            assert "enable_single_use_refresh_tokens" not in fields
        return ("access_token", "refresh_token")

    with patch(
        "snowflake.connector.aio.auth.AuthByOauthCode._construct_authorization_request",
        return_value="authorization_request",
    ) as mock_construct_authorization_request:
        with patch(
            "snowflake.connector.aio.auth.AuthByOauthCode._receive_authorization_callback",
            return_value=("code", auth._state),
        ):
            with patch(
                "snowflake.connector.aio.auth.AuthByOauthCode._ask_authorization_callback_from_user",
                return_value=("code", auth._state),
            ):
                with patch(
                    "snowflake.connector.aio.auth.AuthByOauthCode._get_request_token_response",
                    side_effect=fake_get_request_token_response,
                ) as mock_get_request_token_response:
                    with patch(
                        "snowflake.connector.auth._http_server.AuthHttpServer.redirect_uri",
                        return_value=redirect_uri,
                        new_callable=PropertyMock,
                    ):
                        await auth.prepare(
                            conn=None,
                            authenticator=OAUTH_AUTHORIZATION_CODE,
                            service_name=None,
                            account="acc",
                            user="user",
                        )
                        mock_construct_authorization_request.assert_called_once_with(
                            redirect_uri
                        )
                        assert mock_get_request_token_response.call_count == 1
                        assert (
                            mock_get_request_token_response.call_args[0][1][
                                "redirect_uri"
                            ]
                            == redirect_uri
                        )


@pytest.mark.skipolddriver
async def test_oauth_authorization_code_allows_empty_user(
    monkeypatch, omit_oauth_urls_check
):
    """Test that OAUTH_AUTHORIZATION_CODE authenticator allows connection without user parameter."""
    import snowflake.connector.aio
    from snowflake.connector.aio._network import SnowflakeRestful

    async def mock_post_request(self, url, headers, json_body, **kwargs):
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

    monkeypatch.setattr(SnowflakeRestful, "_post_request", mock_post_request)

    # Mock the OAuth authorization flow to avoid opening browser and starting HTTP server
    # Note: This must be a sync function (not async) because it's called from the sync
    # parent class's prepare() method which calls _request_tokens() without await
    def mock_request_tokens(self, **kwargs):
        # Simulate successful token retrieval
        return ("mock_access_token", "mock_refresh_token")

    monkeypatch.setattr(AuthByOauthCode, "_request_tokens", mock_request_tokens)

    # Test connection without user parameter - should succeed
    conn = snowflake.connector.aio.SnowflakeConnection(
        account="testaccount",
        authenticator="OAUTH_AUTHORIZATION_CODE",
        oauth_client_id="test_client_id",
        oauth_client_secret="test_client_secret",
    )

    await conn.connect()

    # Verify that the connection was successful
    assert conn is not None
    assert isinstance(conn.auth_class, AuthByOauthCode)

    await conn.close()


@pytest.mark.parametrize(
    "uri,redirect_uri",
    [
        ("https://example.com/server", "http://localhost:8080"),
        ("http://localhost:8080", "https://example.com/redirect"),
        ("http://127.0.0.1:9090", "https://server.com/oauth/callback"),
        (None, "https://redirect.example.com"),
    ],
)
@mock.patch(
    "snowflake.connector.aio.auth.oauth_code.AuthByOauthCode._do_authorization_request"
)
@mock.patch("snowflake.connector.aio.auth.oauth_code.AuthByOauthCode._do_token_request")
async def test_auth_oauth_auth_code_passes_uri_to_http_server(
    _, __, uri, redirect_uri, omit_oauth_urls_check
):
    """Test that uri and redirect_uri parameters are passed correctly to AuthHttpServer."""
    auth = AuthByOauthCode(
        "app",
        "clientId",
        "clientSecret",
        "https://auth_url",
        "tokenRequestUrl",
        redirect_uri,
        "scope",
        "host",
        uri=uri,
    )

    with patch(
        "snowflake.connector.auth.oauth_code.AuthHttpServer",
        # return_value=None,
    ) as mock_http_server_init:
        auth._request_tokens(
            conn=mock.MagicMock(),
            authenticator="authenticator",
            service_name="service_name",
            account="account",
            user="user",
        )
        mock_http_server_init.assert_called_once_with(
            uri=uri or redirect_uri, redirect_uri=redirect_uri
        )
