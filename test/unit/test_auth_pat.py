#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations

import pytest

from snowflake.connector.auth import AuthByPAT, AuthNoAuth
from snowflake.connector.auth.by_plugin import AuthType
from snowflake.connector.network import PROGRAMMATIC_ACCESS_TOKEN


def test_auth_pat():
    """Simple PAT test."""
    token = "patToken"
    auth = AuthByPAT(token)
    assert auth.type_ == AuthType.PAT
    assert auth.assertion_content == token
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["TOKEN"] == token, body
    assert body["data"]["AUTHENTICATOR"] == PROGRAMMATIC_ACCESS_TOKEN, body

    auth.reset_secrets()
    assert auth.assertion_content is None


def test_auth_pat_reauthenticate():
    """Test PAT reauthenticate."""
    token = "patToken"
    auth = AuthByPAT(token)
    result = auth.reauthenticate()
    assert result == {"success": False}


@pytest.mark.parametrize(
    "authenticator, expected_auth_class",
    [
        ("PROGRAMMATIC_ACCESS_TOKEN", AuthByPAT),
        ("programmatic_access_token", AuthByPAT),
        ("PAT_WITH_EXTERNAL_SESSION", AuthNoAuth),
        ("pat_with_external_session", AuthNoAuth),
    ],
)
def test_pat_authenticator_creates_auth_by_pat(
    monkeypatch, authenticator, expected_auth_class
):
    """Test that using PROGRAMMATIC_ACCESS_TOKEN authenticator creates AuthByPAT instance.
    PAT_WITH_EXTERNAL_SESSION authenticator creates AuthNoAuth instance.
    """
    import snowflake.connector

    # Mock the network request - this prevents actual network calls and connection errors
    def mock_post_request(request, url, headers, json_body, **kwargs):
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

    # Apply the mock using monkeypatch
    monkeypatch.setattr(
        snowflake.connector.network.SnowflakeRestful, "_post_request", mock_post_request
    )

    # Create connection with PAT authenticator
    conn = snowflake.connector.connect(
        user="user",
        account="account",
        database="TESTDB",
        warehouse="TESTWH",
        authenticator=authenticator,
        token="test_pat_token",
    )

    # Verify that the auth_class is an instance of AuthByPAT
    assert isinstance(conn.auth_class, expected_auth_class)

    conn.close()
