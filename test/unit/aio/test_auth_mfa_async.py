#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from unittest import mock

import pytest

from snowflake.connector.aio import SnowflakeConnection


@pytest.mark.parametrize(
    "authenticator", ["USERNAME_PASSWORD_MFA", "username_password_mfa"]
)
async def test_mfa_token_cache(authenticator):
    with mock.patch(
        "snowflake.connector.aio._network.SnowflakeRestful.fetch",
    ):
        with mock.patch(
            "snowflake.connector.aio.auth.Auth._write_temporary_credential",
        ) as save_mock:
            async with SnowflakeConnection(
                account="account",
                user="user",
                password="password",
                authenticator=authenticator,
                client_store_temporary_credential=True,
                client_request_mfa_token=True,
            ):
                assert save_mock.called
    with mock.patch(
        "snowflake.connector.aio._network.SnowflakeRestful.fetch",
        return_value={
            "data": {
                "token": "abcd",
                "masterToken": "defg",
            },
            "success": True,
        },
    ):
        with mock.patch(
            "snowflake.connector.aio.SnowflakeCursor._init_result_and_meta",
        ):
            with mock.patch(
                "snowflake.connector.aio.auth.Auth._write_temporary_credential",
                return_value=None,
            ) as load_mock:
                async with SnowflakeConnection(
                    account="account",
                    user="user",
                    password="password",
                    authenticator=authenticator,
                    client_store_temporary_credential=True,
                    client_request_mfa_token=True,
                ):
                    assert load_mock.called
