#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from snowflake.connector.auth import AuthByOauthCode


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
