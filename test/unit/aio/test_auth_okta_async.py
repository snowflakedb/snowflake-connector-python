#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
from test.unit.aio.mock_utils import mock_connection
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

import aiohttp
import pytest

from snowflake.connector.aio._network import SnowflakeRestful
from snowflake.connector.aio.auth import AuthByOkta
from snowflake.connector.constants import OCSPMode
from snowflake.connector.description import CLIENT_NAME, CLIENT_VERSION


async def test_auth_okta():
    """Authentication by OKTA positive test case."""
    authenticator = "https://testsso.snowflake.net/"
    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    password = "testpassword"
    service_name = ""

    ref_sso_url = "https://testsso.snowflake.net/sso"
    ref_token_url = "https://testsso.snowflake.net/token"
    rest = _init_rest(ref_sso_url, ref_token_url)

    auth = AuthByOkta(application)

    # step 1
    headers, sso_url, token_url = await auth._step1(
        rest._connection, authenticator, service_name, account, user
    )
    assert not rest._connection.errorhandler.called  # no error
    assert headers.get("accept") is not None
    assert headers.get("Content-Type") is not None
    assert headers.get("User-Agent") is not None
    assert sso_url == ref_sso_url
    assert token_url == ref_token_url

    # step 2
    await auth._step2(rest._connection, authenticator, sso_url, token_url)
    assert not rest._connection.errorhandler.called  # no error

    # step 3
    ref_one_time_token = "1token1"

    async def fake_fetch(method, full_url, headers, **kwargs):
        return {
            "cookieToken": ref_one_time_token,
        }

    rest.fetch = fake_fetch
    one_time_token = await auth._step3(
        rest._connection, headers, token_url, user, password
    )
    assert not rest._connection.errorhandler.called  # no error
    assert one_time_token == ref_one_time_token

    # step 4
    ref_response_html = """
<html><body>
<form action="https://testaccount.snowflakecomputing.com/post_back"></form>
</body></body></html>
"""

    async def fake_fetch(method, full_url, headers, **kwargs):
        return ref_response_html

    async def get_one_time_token():
        return one_time_token

    rest.fetch = fake_fetch
    response_html = await auth._step4(rest._connection, get_one_time_token, sso_url)
    assert response_html == response_html

    # step 5
    rest._protocol = "https"
    rest._host = f"{account}.snowflakecomputing.com"
    rest._port = 443
    await auth._step5(rest._connection, ref_response_html)
    assert not rest._connection.errorhandler.called  # no error
    assert ref_response_html == auth._saml_response


async def test_auth_okta_step1_negative():
    """Authentication by OKTA step1 negative test case."""
    authenticator = "https://testsso.snowflake.net/"
    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    service_name = ""

    # not success status is returned
    ref_sso_url = "https://testsso.snowflake.net/sso"
    ref_token_url = "https://testsso.snowflake.net/token"
    rest = _init_rest(ref_sso_url, ref_token_url, success=False, message="error")
    auth = AuthByOkta(application)
    # step 1
    _, _, _ = await auth._step1(
        rest._connection, authenticator, service_name, account, user
    )
    assert rest._connection.errorhandler.called  # error should be raised


async def test_auth_okta_step2_negative():
    """Authentication by OKTA step2 negative test case."""
    authenticator = "https://testsso.snowflake.net/"
    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    service_name = ""

    # invalid SSO URL
    ref_sso_url = "https://testssoinvalid.snowflake.net/sso"
    ref_token_url = "https://testsso.snowflake.net/token"
    rest = _init_rest(ref_sso_url, ref_token_url)

    auth = AuthByOkta(application)
    # step 1
    headers, sso_url, token_url = await auth._step1(
        rest._connection, authenticator, service_name, account, user
    )
    # step 2
    await auth._step2(rest._connection, authenticator, sso_url, token_url)
    assert rest._connection.errorhandler.called  # error

    # invalid TOKEN URL
    ref_sso_url = "https://testsso.snowflake.net/sso"
    ref_token_url = "https://testssoinvalid.snowflake.net/token"
    rest = _init_rest(ref_sso_url, ref_token_url)

    auth = AuthByOkta(application)
    # step 1
    headers, sso_url, token_url = await auth._step1(
        rest._connection, authenticator, service_name, account, user
    )
    # step 2
    await auth._step2(rest._connection, authenticator, sso_url, token_url)
    assert rest._connection.errorhandler.called  # error


async def test_auth_okta_step3_negative():
    """Authentication by OKTA step3 negative test case."""
    authenticator = "https://testsso.snowflake.net/"
    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    password = "testpassword"
    service_name = ""

    ref_sso_url = "https://testsso.snowflake.net/sso"
    ref_token_url = "https://testsso.snowflake.net/token"
    rest = _init_rest(ref_sso_url, ref_token_url)

    auth = AuthByOkta(application)
    # step 1
    headers, sso_url, token_url = await auth._step1(
        rest._connection, authenticator, service_name, account, user
    )
    # step 2
    await auth._step2(rest._connection, authenticator, sso_url, token_url)
    assert not rest._connection.errorhandler.called  # no error

    # step 3: authentication by IdP failed.
    async def fake_fetch(method, full_url, headers, **kwargs):
        return {
            "failed": "auth failed",
        }

    rest.fetch = fake_fetch
    _ = await auth._step3(rest._connection, headers, token_url, user, password)
    assert rest._connection.errorhandler.called  # auth failure error


async def test_auth_okta_step4_negative(caplog):
    """Authentication by OKTA step4 negative test case."""
    authenticator = "https://testsso.snowflake.net/"
    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    service_name = ""

    ref_sso_url = "https://testsso.snowflake.net/sso"
    ref_token_url = "https://testsso.snowflake.net/token"
    rest = _init_rest(ref_sso_url, ref_token_url)

    auth = AuthByOkta(application)
    # step 1
    headers, sso_url, token_url = await auth._step1(
        rest._connection, authenticator, service_name, account, user
    )
    # step 2
    await auth._step2(rest._connection, authenticator, sso_url, token_url)
    assert not rest._connection.errorhandler.called  # no error

    # step 3: authentication by IdP failed due to throttling
    raise_token_refresh_error = True
    second_token_generated = False

    async def get_one_time_token():
        nonlocal raise_token_refresh_error
        nonlocal second_token_generated
        if raise_token_refresh_error:
            assert not second_token_generated
            return "1token1"
        else:
            second_token_generated = True
            return "2token2"

    # the first time, when step4 gets executed, we return 429
    # the second time when step4 gets retried, we return 200
    async def mock_session_request(*args, **kwargs):
        nonlocal second_token_generated
        url = kwargs.get("url")
        assert url == (
            "https://testsso.snowflake.net/sso?RelayState=%2Fsome%2Fdeep%2Flink&onetimetoken=1token1"
            if not second_token_generated
            else "https://testsso.snowflake.net/sso?RelayState=%2Fsome%2Fdeep%2Flink&onetimetoken=2token2"
        )
        nonlocal raise_token_refresh_error
        if raise_token_refresh_error:
            raise_token_refresh_error = False
            return AsyncMock(status=429)
        else:
            resp = AsyncMock(status=200)
            resp.text.return_value = "success"
            return resp

    with patch.object(
        aiohttp.ClientSession,
        "request",
        new=mock_session_request,
    ):
        caplog.set_level(logging.DEBUG, "snowflake.connector")
        response_html = await auth._step4(rest._connection, get_one_time_token, sso_url)
        # make sure the RefreshToken error is caught and tried
        assert "step4: refresh token for re-authentication" in caplog.text
        # test that token generation method is called
        assert second_token_generated
        assert response_html == "success"
        assert not rest._connection.errorhandler.called


@pytest.mark.parametrize("disable_saml_url_check", [True, False])
async def test_auth_okta_step5_negative(disable_saml_url_check):
    """Authentication by OKTA step5 negative test case."""
    authenticator = "https://testsso.snowflake.net/"
    application = "testapplication"
    account = "testaccount"
    user = "testuser"
    password = "testpassword"
    service_name = ""

    ref_sso_url = "https://testsso.snowflake.net/sso"
    ref_token_url = "https://testsso.snowflake.net/token"
    rest = _init_rest(
        ref_sso_url, ref_token_url, disable_saml_url_check=disable_saml_url_check
    )

    auth = AuthByOkta(application)
    # step 1
    headers, sso_url, token_url = await auth._step1(
        rest._connection, authenticator, service_name, account, user
    )
    assert not rest._connection.errorhandler.called  # no error
    # step 2
    await auth._step2(rest._connection, authenticator, sso_url, token_url)
    assert not rest._connection.errorhandler.called  # no error
    # step 3
    ref_one_time_token = "1token1"

    async def fake_fetch(method, full_url, headers, **kwargs):
        return {
            "cookieToken": ref_one_time_token,
        }

    rest.fetch = fake_fetch
    one_time_token = await auth._step3(
        rest._connection, headers, token_url, user, password
    )
    assert not rest._connection.errorhandler.called  # no error

    # step 4
    # HTML includes invalid account name
    ref_response_html = """
<html><body>
<form action="https://invalidtestaccount.snowflakecomputing.com/post_back
"></form>
</body></body></html>
"""

    async def fake_fetch(method, full_url, headers, **kwargs):
        return ref_response_html

    async def get_one_time_token():
        return one_time_token

    rest.fetch = fake_fetch
    response_html = await auth._step4(rest._connection, get_one_time_token, sso_url)
    assert response_html == ref_response_html

    # step 5
    rest._protocol = "https"
    rest._host = f"{account}.snowflakecomputing.com"
    rest._port = 443
    await auth._step5(rest._connection, ref_response_html)
    assert disable_saml_url_check ^ rest._connection.errorhandler.called  # error


def _init_rest(
    ref_sso_url, ref_token_url, success=True, message=None, disable_saml_url_check=False
):
    async def post_request(url, headers, body, **kwargs):
        _ = url
        _ = headers
        _ = body
        _ = kwargs.get("dummy")
        return {
            "success": success,
            "message": message,
            "data": {
                "ssoUrl": ref_sso_url,
                "tokenUrl": ref_token_url,
            },
        }

    connection = mock_connection(disable_saml_url_check=disable_saml_url_check)
    connection.errorhandler = Mock(return_value=None)
    connection._ocsp_mode = Mock(return_value=OCSPMode.FAIL_OPEN)
    type(connection).application = PropertyMock(return_value=CLIENT_NAME)
    type(connection)._internal_application_name = PropertyMock(return_value=CLIENT_NAME)
    type(connection)._internal_application_version = PropertyMock(
        return_value=CLIENT_VERSION
    )

    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )
    connection._rest = rest
    rest._post_request = post_request
    return rest
