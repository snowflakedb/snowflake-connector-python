#!/usr/bin/env python
from __future__ import annotations

from test.helpers import apply_auth_class_update_body, create_mock_auth_body

try:  # pragma: no cover
    from snowflake.connector.auth import AuthByOAuth
except ImportError:
    from snowflake.connector.auth_oauth import AuthByOAuth
import pytest


def test_auth_oauth():
    """Simple OAuth test."""
    token = "oAuthToken"
    auth = AuthByOAuth(token)
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["TOKEN"] == token, body
    assert body["data"]["AUTHENTICATOR"] == "OAUTH", body


def test_auth_prepare_body_does_not_overwrite_client_environment_fields():
    token = "oAuthToken"
    auth_class = AuthByOAuth(token)

    req_body_before = create_mock_auth_body()
    req_body_after = apply_auth_class_update_body(auth_class, req_body_before)

    assert all(
        [
            req_body_before["data"]["CLIENT_ENVIRONMENT"][k]
            == req_body_after["data"]["CLIENT_ENVIRONMENT"][k]
            for k in req_body_before["data"]["CLIENT_ENVIRONMENT"]
        ]
    )


@pytest.mark.parametrize("authenticator", ["oauth", "OAUTH"])
def test_oauth_authenticator_is_case_insensitive(monkeypatch, authenticator):
    """Test that oauth authenticator is case insensitive."""
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

    # Create connection with oauth authenticator - OAuth requires a token parameter
    conn = snowflake.connector.connect(
        user="testuser",
        account="testaccount",
        authenticator=authenticator,
        token="test_oauth_token",  # OAuth authentication requires a token
    )

    # Verify that the auth_class is an instance of AuthByOAuth
    assert isinstance(conn.auth_class, AuthByOAuth)

    conn.close()
