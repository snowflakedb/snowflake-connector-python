#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os

from snowflake.connector.aio.auth import AuthByOauthCode


async def test_auth_oauth_code():
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
        pkce_enabled=True,
        refresh_token_enabled=False,
    )

    body = {"data": {}}
    await auth.update_body(body)

    # Check that OAuth authenticator is set
    assert body["data"]["AUTHENTICATOR"] == "OAUTH", body
    # OAuth type should be set to authorization_code
    assert body["data"]["OAUTH_TYPE"] == "authorization_code", body

    # Clean up environment variable
    del os.environ["SF_ENABLE_EXPERIMENTAL_AUTHENTICATION"]


def test_mro():
    """Ensure that methods from AuthByPluginAsync override those from AuthByPlugin."""
    from snowflake.connector.aio.auth import AuthByPlugin as AuthByPluginAsync
    from snowflake.connector.auth import AuthByPlugin as AuthByPluginSync

    assert AuthByOauthCode.mro().index(AuthByPluginAsync) < AuthByOauthCode.mro().index(
        AuthByPluginSync
    )
