#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#


import pytest

from snowflake.connector.auth import AuthByOauthCredentials
from snowflake.connector.errors import ProgrammingError


def test_auth_oauth_credentials_oauth_type():
    """Simple OAuth Client Credentials oauth type test."""
    auth = AuthByOauthCredentials(
        "app",
        "clientId",
        "clientSecret",
        "https://example.com/oauth/token",
        "scope",
    )
    body = {"data": {}}
    auth.update_body(body)
    assert (
        body["data"]["CLIENT_ENVIRONMENT"]["OAUTH_TYPE"] == "oauth_client_credentials"
    )


@pytest.mark.parametrize(
    "authenticator", ["OAUTH_CLIENT_CREDENTIALS", "oauth_client_credentials"]
)
def test_oauth_client_credentials_authenticator_is_case_insensitive(
    monkeypatch, authenticator
):
    """Test that OAuth client credentials authenticator is case insensitive."""
    import snowflake.connector

    def mock_post_request(self, url, headers, json_body, **kwargs):
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

    # Mock the OAuth client credentials token request to avoid making HTTP requests
    def mock_get_request_token_response(self, connection, fields):
        # Simulate successful token retrieval
        return (
            "mock_access_token",
            None,
        )  # Client credentials doesn't use refresh tokens

    monkeypatch.setattr(
        AuthByOauthCredentials,
        "_get_request_token_response",
        mock_get_request_token_response,
    )

    # Create connection with OAuth client credentials authenticator
    conn = snowflake.connector.connect(
        user="testuser",
        account="testaccount",
        authenticator=authenticator,
        oauth_client_id="test_client_id",
        oauth_client_secret="test_client_secret",
    )

    # Verify that the auth_class is an instance of AuthByOauthCredentials
    assert isinstance(conn.auth_class, AuthByOauthCredentials)

    conn.close()


def test_oauth_credentials_missing_client_id_raises_error():
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


def test_oauth_credentials_missing_client_secret_raises_error():
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
