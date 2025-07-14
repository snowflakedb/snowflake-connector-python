#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from snowflake.connector.aio.auth import AuthByPAT
from snowflake.connector.auth.by_plugin import AuthType
from snowflake.connector.network import PROGRAMMATIC_ACCESS_TOKEN


async def test_auth_pat():
    """Simple test if AuthByPAT class."""
    token = "patToken"
    auth = AuthByPAT(token)
    assert auth.type_ == AuthType.PAT
    assert auth.assertion_content == token
    body = {"data": {}}
    await auth.update_body(body)
    assert body["data"]["TOKEN"] == token, body
    assert body["data"]["AUTHENTICATOR"] == PROGRAMMATIC_ACCESS_TOKEN, body

    await auth.reset_secrets()
    assert auth.assertion_content is None


async def test_auth_pat_reauthenticate():
    """Test PAT reauthenticate."""
    token = "patToken"
    auth = AuthByPAT(token)
    result = await auth.reauthenticate()
    assert result == {"success": False}


async def test_pat_authenticator_creates_auth_by_pat(monkeypatch):
    """Test that using PROGRAMMATIC_ACCESS_TOKEN authenticator creates AuthByPAT instance."""
    import snowflake.connector.aio
    from snowflake.connector.aio._network import SnowflakeRestful

    # Mock the network request - this prevents actual network calls and connection errors
    async def mock_post_request(request, url, headers, json_body, **kwargs):
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
    monkeypatch.setattr(SnowflakeRestful, "_post_request", mock_post_request)

    # Create connection with PAT authenticator
    conn = snowflake.connector.aio.SnowflakeConnection(
        user="user",
        account="account",
        database="TESTDB",
        warehouse="TESTWH",
        authenticator=PROGRAMMATIC_ACCESS_TOKEN,
        token="test_pat_token",
    )

    await conn.connect()

    # Verify that the auth_class is an instance of AuthByPAT
    assert isinstance(conn.auth_class, AuthByPAT)

    await conn.close()
