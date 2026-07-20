#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from unittest.mock import patch

import pytest

from snowflake.connector.auth import AuthByOauthCode
from snowflake.connector.network import OAUTH_AUTHORIZATION_CODE


def test_auth_oauth_auth_code_oauth_type():
    """Simple OAuth Auth Code oauth type test."""
    auth = AuthByOauthCode(
        "app",
        "clientId",
        "clientSecret",
        "auth_url",
        "tokenRequestUrl",
        "redirectUri:{port}",
        "scope",
    )
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["OAUTH_TYPE"] == "authorization_code"


@pytest.mark.parametrize("rtr_enabled", [True, False])
def test_auth_oauth_auth_code_single_use_refresh_tokens(rtr_enabled: bool):
    """Verifies that the enable_single_use_refresh_tokens option is plumbed into the authz code request."""
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
        "snowflake.connector.auth.AuthByOauthCode._do_authorization_request",
        return_value="abc",
    ):
        with patch(
            "snowflake.connector.auth.AuthByOauthCode._get_request_token_response",
            side_effect=fake_get_request_token_response,
        ):
            auth.prepare(
                conn=None,
                authenticator=OAUTH_AUTHORIZATION_CODE,
                service_name=None,
                account="acc",
                user="user",
            )
