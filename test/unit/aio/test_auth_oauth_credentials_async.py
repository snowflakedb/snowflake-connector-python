#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os

from snowflake.connector.aio.auth import AuthByOauthCredentials


async def test_auth_oauth_credentials():
    """Simple OAuth Credentials test."""
    # Set experimental auth flag for the test
    os.environ["SF_ENABLE_EXPERIMENTAL_AUTHENTICATION"] = "true"

    auth = AuthByOauthCredentials(
        application="test_app",
        client_id="test_client_id",
        client_secret="test_client_secret",
        token_request_url="https://example.com/token",
        scope="session:role:test_role",
    )

    body = {"data": {}}
    await auth.update_body(body)

    # Check that OAuth authenticator is set
    assert body["data"]["AUTHENTICATOR"] == "OAUTH", body
    # OAuth type should be set to client_credentials
    assert (
        body["data"]["CLIENT_ENVIRONMENT"]["OAUTH_TYPE"] == "oauth_client_credentials"
    ), body

    # Clean up environment variable
    del os.environ["SF_ENABLE_EXPERIMENTAL_AUTHENTICATION"]


def test_mro():
    """Ensure that methods from AuthByPluginAsync override those from AuthByPlugin."""
    from snowflake.connector.aio.auth import AuthByPlugin as AuthByPluginAsync
    from snowflake.connector.auth import AuthByPlugin as AuthByPluginSync

    assert AuthByOauthCredentials.mro().index(
        AuthByPluginAsync
    ) < AuthByOauthCredentials.mro().index(AuthByPluginSync)
