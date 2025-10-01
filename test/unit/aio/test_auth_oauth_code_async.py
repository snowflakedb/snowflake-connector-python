#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os
from test.unit.test_auth_oauth_auth_code import omit_oauth_urls_check  # noqa: F401
from unittest.mock import patch

import pytest

from snowflake.connector.aio.auth import AuthByOauthCode
from snowflake.connector.errors import ProgrammingError
from snowflake.connector.network import OAUTH_AUTHORIZATION_CODE


async def test_auth_oauth_code(omit_oauth_urls_check):  # noqa: F811
    """Simple OAuth Code test."""
    # Set experimental auth flag for the test
    os.environ["SF_ENABLE_EXPERIMENTAL_AUTHENTICATION"] = "true"

    auth = AuthByOauthCode(
        application="test_app",
        client_id="test_client_id",
        client_secret="test_client_secret",
        authentication_url="https://example.com/auth",
        token_request_url="https://example.com/token",
        redirect_uri="http://localhost:8080/callback",
        scope="session:role:test_role",
        host="test_host",
        pkce_enabled=True,
        refresh_token_enabled=False,
    )

    body = {"data": {}}
    await auth.update_body(body)

    # Check that OAuth authenticator is set
    assert body["data"]["AUTHENTICATOR"] == "OAUTH", body
    # OAuth type should be set to authorization_code
    assert body["data"]["OAUTH_TYPE"] == "oauth_authorization_code", body

    # Clean up environment variable
    del os.environ["SF_ENABLE_EXPERIMENTAL_AUTHENTICATION"]


@pytest.mark.parametrize("rtr_enabled", [True, False])
async def test_auth_oauth_auth_code_single_use_refresh_tokens(
    rtr_enabled: bool, omit_oauth_urls_check  # noqa: F811
):
    """Verifies that the enable_single_use_refresh_tokens option is plumbed into the authz code request."""
    # Set experimental auth flag for the test
    os.environ["SF_ENABLE_EXPERIMENTAL_AUTHENTICATION"] = "true"

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

    def fake_get_request_token_response(_, fields: dict[str, str]):
        if rtr_enabled:
            assert fields.get("enable_single_use_refresh_tokens") == "true"
        else:
            assert "enable_single_use_refresh_tokens" not in fields
        return ("access_token", "refresh_token")

    with patch(
        "snowflake.connector.auth.oauth_code.AuthByOauthCode._do_authorization_request",
        return_value="abc",
    ):
        with patch(
            "snowflake.connector.auth.oauth_code.AuthByOauthCode._get_request_token_response",
            side_effect=fake_get_request_token_response,
        ):
            await auth.prepare(
                conn=None,
                authenticator=OAUTH_AUTHORIZATION_CODE,
                service_name=None,
                account="acc",
                user="user",
            )

    # Clean up environment variable
    del os.environ["SF_ENABLE_EXPERIMENTAL_AUTHENTICATION"]


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


def test_mro():
    """Ensure that methods from AuthByPluginAsync override those from AuthByPlugin."""
    from snowflake.connector.aio.auth import AuthByPlugin as AuthByPluginAsync
    from snowflake.connector.auth import AuthByPlugin as AuthByPluginSync

    assert AuthByOauthCode.mro().index(AuthByPluginAsync) < AuthByOauthCode.mro().index(
        AuthByPluginSync
    )
