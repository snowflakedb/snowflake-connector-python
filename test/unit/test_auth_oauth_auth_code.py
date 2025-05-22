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
        "host",
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
        "host",
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


@pytest.mark.parametrize(
    "name, client_id, client_secret, auth_url, token_url, expected_local",
    [
        (
            "Client credentials not supplied and Snowflake as IdP",
            "",
            "",
            "https://example.snowflakecomputing.com/oauth/authorize",
            "https://example.snowflakecomputing.com/oauth/token",
            True,
        ),
        (
            "Client credentials not supplied and empty URLs",
            "",
            "",
            "",
            "",
            True,
        ),
        (
            "Client credentials supplied",
            "testClientID",
            "testClientSecret",
            "https://example.snowflakecomputing.com/oauth/authorize",
            "https://example.snowflakecomputing.com/oauth/token",
            False,
        ),
        (
            "Only client ID supplied",
            "testClientID",
            "",
            "https://example.snowflakecomputing.com/oauth/authorize",
            "https://example.snowflakecomputing.com/oauth/token",
            False,
        ),
        (
            "Non-Snowflake IdP",
            "",
            "",
            "https://example.com/oauth/authorize",
            "https://example.com/oauth/token",
            False,
        ),
        (
            "[China] Client credentials not supplied and Snowflake as IdP",
            "",
            "",
            "https://example.snowflakecomputing.cn/oauth/authorize",
            "https://example.snowflakecomputing.cn/oauth/token",
            True,
        ),
        (
            "[China] Client credentials supplied",
            "testClientID",
            "testClientSecret",
            "https://example.snowflakecomputing.cn/oauth/authorize",
            "https://example.snowflakecomputing.cn/oauth/token",
            False,
        ),
        (
            "[China] Only client ID supplied",
            "testClientID",
            "",
            "https://example.snowflakecomputing.cn/oauth/authorize",
            "https://example.snowflakecomputing.cn/oauth/token",
            False,
        ),
    ],
)
def test_eligible_for_default_client_credentials_via_constructor(
    name, client_id, client_secret, auth_url, token_url, expected_local
):
    auth = AuthByOauthCode(
        application="app",
        client_id=client_id,
        client_secret=client_secret,
        authentication_url=auth_url,
        token_request_url=token_url,
        redirect_uri="redirectUri:{port}",
        scope="scope",
    )
    if expected_local:
        assert (
            auth._client_id == AuthByOauthCode._LOCAL_APPLICATION_CLIENT_CREDENTIALS
        ), f"{name} - expected LOCAL_APPLICATION as client_id"
        assert (
            auth._client_secret == AuthByOauthCode._LOCAL_APPLICATION_CLIENT_CREDENTIALS
        ), f"{name} - expected LOCAL_APPLICATION as client_secret"
    else:
        assert auth._client_id == client_id, f"{name} - expected original client_id"
        assert (
            auth._client_secret == client_secret
        ), f"{name} - expected original client_secret"
