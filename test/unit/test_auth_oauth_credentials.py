#!/usr/bin/env python


from test.helpers import apply_auth_class_update_body, create_mock_auth_body

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


def test_auth_prepare_body_does_not_overwrite_client_environment_fields():
    auth_class = AuthByOauthCredentials(
        "app",
        "clientId",
        "clientSecret",
        "https://example.com/oauth/token",
        "scope",
    )

    req_body_before = create_mock_auth_body()
    req_body_after = apply_auth_class_update_body(auth_class, req_body_before)

    assert all(
        [
            req_body_before["data"]["CLIENT_ENVIRONMENT"][k]
            == req_body_after["data"]["CLIENT_ENVIRONMENT"][k]
            for k in req_body_before["data"]["CLIENT_ENVIRONMENT"]
        ]
    )


@pytest.mark.parametrize(
    "authenticator, oauth_credentials_in_body",
    [
        ("OAUTH_CLIENT_CREDENTIALS", True),
        ("oauth_client_credentials", False),
        ("Oauth_Client_Credentials", None),
    ],
)
def test_oauth_client_credentials_parameters(
    monkeypatch, authenticator, oauth_credentials_in_body
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
        # Return fields to verify they are set correctly in tests
        return (
            str(fields),
            None,
        )

    monkeypatch.setattr(
        AuthByOauthCredentials,
        "_get_request_token_response",
        mock_get_request_token_response,
    )

    oauth_credentials_in_body_arg = (
        {"oauth_credentials_in_body": oauth_credentials_in_body}
        if oauth_credentials_in_body is not None
        else {}
    )
    # Create connection with OAuth client credentials authenticator
    conn = snowflake.connector.connect(
        user="testuser",
        account="testaccount",
        authenticator=authenticator,
        oauth_client_id="test_client_id",
        oauth_client_secret="test_client_secret",
        **oauth_credentials_in_body_arg,
    )

    # Verify that the auth_class is an instance of AuthByOauthCredentials
    assert isinstance(conn.auth_class, AuthByOauthCredentials)

    # Verify that the credentials_in_body attribute is set correctly
    expected_credentials_in_body = (
        oauth_credentials_in_body if oauth_credentials_in_body is not None else False
    )
    assert conn.auth_class._credentials_in_body is expected_credentials_in_body

    str_fields, _ = conn.auth_class._request_tokens(
        conn=conn,
        authenticator=authenticator,
        account="<unused-acount>",
        user="<unused-user>",
        service_name=None,
    )
    credential_fields = (
        ", 'client_id': 'test_client_id', 'client_secret': 'test_client_secret'"
        if expected_credentials_in_body
        else ""
    )
    assert (
        str_fields
        == "{'grant_type': 'client_credentials', 'scope': ''" + credential_fields + "}"
    )

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
