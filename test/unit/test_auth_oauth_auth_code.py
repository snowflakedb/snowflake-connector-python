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


def test_eligible_for_default_client_credentials_via_constructor():
    """Tests default credential logic by checking what gets set on init."""
    tests = [
        {
            "name": "Client credentials not supplied and Snowflake as IdP",
            "client_id": "",
            "client_secret": "",
            "auth_url": "https://example.snowflakecomputing.com/oauth/authorize",
            "token_url": "https://example.snowflakecomputing.com/oauth/token",
            "expected_local": True,
        },
        {
            "name": "Client credentials not supplied and empty URLs",
            "client_id": "",
            "client_secret": "",
            "auth_url": "",
            "token_url": "",
            "expected_local": True,
        },
        {
            "name": "Client credentials supplied",
            "client_id": "testClientID",
            "client_secret": "testClientSecret",
            "auth_url": "https://example.snowflakecomputing.com/oauth/authorize",
            "token_url": "https://example.snowflakecomputing.com/oauth/token",
            "expected_local": False,
        },
        {
            "name": "Only client ID supplied",
            "client_id": "testClientID",
            "client_secret": "",
            "auth_url": "https://example.snowflakecomputing.com/oauth/authorize",
            "token_url": "https://example.snowflakecomputing.com/oauth/token",
            "expected_local": False,
        },
        {
            "name": "Non-Snowflake IdP",
            "client_id": "",
            "client_secret": "",
            "auth_url": "https://example.com/oauth/authorize",
            "token_url": "https://example.com/oauth/token",
            "expected_local": False,
        },
    ]

    for test in tests:
        auth = AuthByOauthCode(
            application="app",
            client_id=test["client_id"],
            client_secret=test["client_secret"],
            authentication_url=test["auth_url"],
            token_request_url=test["token_url"],
            redirect_uri="redirectUri:{port}",
            scope="scope",
            host="example.snowflakecomputing.com",
        )
        if test["expected_local"]:
            assert (
                auth._client_id == AuthByOauthCode._LOCAL_APPLICATION_CLIENT_CREDENTIALS
            ), f"{test['name']} - expected LOCAL_APPLICATION"
            assert (
                auth._client_secret
                == AuthByOauthCode._LOCAL_APPLICATION_CLIENT_CREDENTIALS
            )
        else:
            assert (
                auth._client_id == test["client_id"]
            ), f"{test['name']} - expected original client_id"
            assert auth._client_secret == test["client_secret"]
