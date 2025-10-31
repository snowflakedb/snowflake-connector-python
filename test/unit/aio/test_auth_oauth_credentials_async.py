#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from test.helpers import apply_auth_class_update_body_async, create_mock_auth_body

import pytest

from snowflake.connector.aio.auth import AuthByOauthCredentials
from snowflake.connector.errors import ProgrammingError


async def test_auth_oauth_credentials_oauth_type():
    """Simple OAuth Client Credentials oauth type test."""
    auth = AuthByOauthCredentials(
        "app",
        "clientId",
        "clientSecret",
        "https://example.com/oauth/token",
        "scope",
    )
    body = {"data": {}}
    await auth.update_body(body)
    assert (
        body["data"]["CLIENT_ENVIRONMENT"]["OAUTH_TYPE"] == "oauth_client_credentials"
    )


async def test_auth_prepare_body_does_not_overwrite_client_environment_fields():
    auth_class = AuthByOauthCredentials(
        "app",
        "clientId",
        "clientSecret",
        "https://example.com/oauth/token",
        "scope",
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


@pytest.mark.parametrize(
    "authenticator", ["OAUTH_CLIENT_CREDENTIALS", "oauth_client_credentials"]
)
async def test_oauth_client_credentials_authenticator_is_case_insensitive(
    monkeypatch, authenticator
):
    """Test that OAuth client credentials authenticator is case insensitive."""
    import snowflake.connector.aio

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

    monkeypatch.setattr(
        snowflake.connector.aio._network.SnowflakeRestful,
        "_post_request",
        mock_post_request,
    )

    # Mock the OAuth client credentials token request to avoid making HTTP requests
    # Note: We need to mock _request_tokens which is called by the sync prepare() method
    def mock_request_tokens(self, **kwargs):
        # Simulate successful token retrieval
        # Return a tuple directly (not a coroutine) since it's called from sync code
        return (
            "mock_access_token",
            None,  # Client credentials doesn't use refresh tokens
        )

    monkeypatch.setattr(
        AuthByOauthCredentials,
        "_request_tokens",
        mock_request_tokens,
    )

    # Create connection with OAuth client credentials authenticator
    conn = snowflake.connector.aio.SnowflakeConnection(
        user="testuser",
        account="testaccount",
        authenticator=authenticator,
        oauth_client_id="test_client_id",
        oauth_client_secret="test_client_secret",
    )

    await conn.connect()

    # Verify that the auth_class is an instance of AuthByOauthCredentials
    assert isinstance(conn.auth_class, AuthByOauthCredentials)

    await conn.close()


async def test_oauth_credentials_missing_client_id_raises_error():
    """Test that missing client_id raises a ProgrammingError."""
    with pytest.raises(ProgrammingError) as excinfo:
        AuthByOauthCredentials(
            "app",
            "",  # Empty client_id
            "clientSecret",
            "https://example.com/oauth/token",
            "scope",
        )
    assert "client_id' is empty" in str(excinfo.value)


async def test_oauth_credentials_missing_client_secret_raises_error():
    """Test that missing client_secret raises a ProgrammingError."""
    with pytest.raises(ProgrammingError) as excinfo:
        AuthByOauthCredentials(
            "app",
            "clientId",
            "",  # Empty client_secret
            "https://example.com/oauth/token",
            "scope",
        )
    assert "client_secret' is empty" in str(excinfo.value)


def test_mro():
    """Ensure that methods from AuthByPluginAsync override those from AuthByPlugin."""
    from snowflake.connector.aio.auth import AuthByPlugin as AuthByPluginAsync
    from snowflake.connector.auth import AuthByPlugin as AuthByPluginSync

    assert AuthByOauthCredentials.mro().index(
        AuthByPluginAsync
    ) < AuthByOauthCredentials.mro().index(AuthByPluginSync)
