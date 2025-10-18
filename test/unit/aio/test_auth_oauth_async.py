#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

from snowflake.connector.aio.auth import AuthByOAuth


async def test_auth_oauth():
    """Simple OAuth test."""
    token = "oAuthToken"
    auth = AuthByOAuth(token)
    body = {"data": {}}
    await auth.update_body(body)
    assert body["data"]["TOKEN"] == token, body
    assert body["data"]["AUTHENTICATOR"] == "OAUTH", body


@pytest.mark.parametrize("authenticator", ["oauth", "OAUTH"])
async def test_oauth_authenticator_is_case_insensitive(monkeypatch, authenticator):
    """Test that oauth authenticator is case insensitive."""
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

    # Create connection with oauth authenticator - OAuth requires a token parameter
    conn = snowflake.connector.aio.SnowflakeConnection(
        user="testuser",
        account="testaccount",
        authenticator=authenticator,
        token="test_oauth_token",  # OAuth authentication requires a token
    )
    await conn.connect()

    # Verify that the auth_class is an instance of AuthByOAuth
    assert isinstance(conn.auth_class, AuthByOAuth)

    await conn.close()


def test_mro():
    """Ensure that methods from AuthByPluginAsync override those from AuthByPlugin."""
    from snowflake.connector.aio.auth import AuthByPlugin as AuthByPluginAsync
    from snowflake.connector.auth import AuthByPlugin as AuthByPluginSync

    assert AuthByOAuth.mro().index(AuthByPluginAsync) < AuthByOAuth.mro().index(
        AuthByPluginSync
    )
