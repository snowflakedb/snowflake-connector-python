#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from unittest.mock import patch

import pytest

from snowflake.connector.auth import AuthByOauthCode
from snowflake.connector.errors import ProgrammingError
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
    "name, client_id, client_secret, host, auth_url, token_url, expected_local, expected_raised_error_cls",
    [
        (
            "Client credentials not supplied and Snowflake as IdP",
            "",
            "",
            "example.snowflakecomputing.com",
            "https://example.snowflakecomputing.com/oauth/authorize",
            "https://example.snowflakecomputing.com/oauth/token",
            True,
            None,
        ),
        (
            "Client credentials not supplied and empty URLs",
            "",
            "",
            "",
            "",
            "",
            True,
            None,
        ),
        (
            "Client credentials supplied",
            "testClientID",
            "testClientSecret",
            "example.snowflakecomputing.com",
            "https://example.snowflakecomputing.com/oauth/authorize",
            "https://example.snowflakecomputing.com/oauth/token",
            False,
            None,
        ),
        (
            "Only client ID supplied",
            "testClientID",
            "",
            "example.snowflakecomputing.com",
            "https://example.snowflakecomputing.com/oauth/authorize",
            "https://example.snowflakecomputing.com/oauth/token",
            False,
            ProgrammingError,
        ),
        (
            "Non-Snowflake IdP",
            "",
            "",
            "example.snowflakecomputing.com",
            "https://example.com/oauth/authorize",
            "https://example.com/oauth/token",
            False,
            ProgrammingError,
        ),
        (
            "[China] Client credentials not supplied and Snowflake as IdP",
            "",
            "",
            "example.snowflakecomputing.cn",
            "https://example.snowflakecomputing.cn/oauth/authorize",
            "https://example.snowflakecomputing.cn/oauth/token",
            True,
            None,
        ),
        (
            "[China] Client credentials supplied",
            "testClientID",
            "testClientSecret",
            "example.snowflakecomputing.cn",
            "https://example.snowflakecomputing.cn/oauth/authorize",
            "https://example.snowflakecomputing.cn/oauth/token",
            False,
            None,
        ),
        (
            "[China] Only client ID supplied",
            "testClientID",
            "",
            "example.snowflakecomputing.cn",
            "https://example.snowflakecomputing.cn/oauth/authorize",
            "https://example.snowflakecomputing.cn/oauth/token",
            False,
            ProgrammingError,
        ),
    ],
)
def test_eligible_for_default_client_credentials_via_constructor(
    name,
    client_id,
    client_secret,
    host,
    auth_url,
    token_url,
    expected_local,
    expected_raised_error_cls,
):
    def assert_initialized_correctly() -> None:
        auth = AuthByOauthCode(
            application="app",
            client_id=client_id,
            client_secret=client_secret,
            authentication_url=auth_url,
            token_request_url=token_url,
            redirect_uri="https://redirectUri:{port}",
            scope="scope",
            host=host,
        )
        if expected_local:
            assert (
                auth._client_id == AuthByOauthCode._LOCAL_APPLICATION_CLIENT_CREDENTIALS
            ), f"{name} - expected LOCAL_APPLICATION as client_id"
            assert (
                auth._client_secret
                == AuthByOauthCode._LOCAL_APPLICATION_CLIENT_CREDENTIALS
            ), f"{name} - expected LOCAL_APPLICATION as client_secret"
        else:
            assert auth._client_id == client_id, f"{name} - expected original client_id"
            assert (
                auth._client_secret == client_secret
            ), f"{name} - expected original client_secret"

    if expected_raised_error_cls is not None:
        with pytest.raises(expected_raised_error_cls):
            assert_initialized_correctly()
    else:
        assert_initialized_correctly()
