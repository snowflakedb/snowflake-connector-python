#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from snowflake.connector.aio.auth import AuthByOauthCode
from snowflake.connector.network import OAUTH_AUTHORIZATION_CODE


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


@pytest.mark.parametrize("rtr_enabled", [True, False])
async def test_auth_oauth_auth_code_single_use_refresh_tokens(rtr_enabled: bool):
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


def test_mro():
    """Ensure that methods from AuthByPluginAsync override those from AuthByPlugin."""
    from snowflake.connector.aio.auth import AuthByPlugin as AuthByPluginAsync
    from snowflake.connector.auth import AuthByPlugin as AuthByPluginSync

    assert AuthByOauthCode.mro().index(AuthByPluginAsync) < AuthByOauthCode.mro().index(
        AuthByPluginSync
    )
