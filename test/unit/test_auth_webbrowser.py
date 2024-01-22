#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import base64
from unittest import mock
from unittest.mock import MagicMock, Mock, PropertyMock, patch

import pytest

from snowflake.connector import SnowflakeConnection
from snowflake.connector.compat import urlencode
from snowflake.connector.constants import OCSPMode
from snowflake.connector.description import CLIENT_NAME, CLIENT_VERSION
from snowflake.connector.network import (
    EXTERNAL_BROWSER_AUTHENTICATOR,
    ReauthenticationRequest,
    SnowflakeRestful,
)

from .mock_utils import mock_connection

try:  # pragma: no cover
    from snowflake.connector.auth import AuthByWebBrowser
except ImportError:
    from snowflake.connector.auth_webbrowser import AuthByWebBrowser

AUTHENTICATOR = "https://testsso.snowflake.net/"
APPLICATION = "testapplication"
ACCOUNT = "testaccount"
USER = "testuser"
PASSWORD = "testpassword"
SERVICE_NAME = ""
REF_PROOF_KEY = "MOCK_PROOF_KEY"
REF_SSO_URL = "https://testsso.snowflake.net/sso"
INVALID_SSO_URL = "this is an invalid URL"
CLIENT_PORT = 12345
SNOWFLAKE_PORT = 443
HOST = "testaccount.snowflakecomputing.com"
PROOF_KEY = b"F5mR7M2J4y0jgG9CqyyWqEpyFT2HG48HFUByOS3tGaI"
REF_CONSOLE_LOGIN_SSO_URL = (
    f"http://{HOST}:{SNOWFLAKE_PORT}/console/login?login_name={USER}&browser_mode_redirect_port={CLIENT_PORT}&"
    + urlencode({"proof_key": base64.b64encode(PROOF_KEY).decode("ascii")})
)


def mock_webserver(target_instance, application, port):
    _ = application
    _ = port
    target_instance._webserver_status = True


@pytest.mark.parametrize("disable_console_login", [True, False])
@patch("secrets.token_bytes", return_value=PROOF_KEY)
def test_auth_webbrowser_get(_, disable_console_login):
    """Authentication by WebBrowser positive test case."""
    ref_token = "MOCK_TOKEN"

    rest = _init_rest(
        REF_SSO_URL, REF_PROOF_KEY, disable_console_login=disable_console_login
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, CLIENT_PORT]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        "\r\n".join(
            [
                f"GET /?token={ref_token}&confirm=true HTTP/1.1",
                "User-Agent: snowflake-agent",
            ]
        )
    ).encode("utf-8")
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=mock_webbrowser,
        socket_pkg=mock_socket,
    )
    auth.prepare(
        conn=rest._connection,
        authenticator=AUTHENTICATOR,
        service_name=SERVICE_NAME,
        account=ACCOUNT,
        user=USER,
        password=PASSWORD,
    )
    assert not rest._connection.errorhandler.called  # no error
    assert auth.assertion_content == ref_token
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["TOKEN"] == ref_token
    assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR

    if disable_console_login:
        mock_webbrowser.open_new.assert_called_once_with(REF_SSO_URL)
        assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
    else:
        mock_webbrowser.open_new.assert_called_once_with(REF_CONSOLE_LOGIN_SSO_URL)


@pytest.mark.parametrize("disable_console_login", [True, False])
@patch("secrets.token_bytes", return_value=PROOF_KEY)
def test_auth_webbrowser_post(_, disable_console_login):
    """Authentication by WebBrowser positive test case with POST."""
    ref_token = "MOCK_TOKEN"

    rest = _init_rest(
        REF_SSO_URL, REF_PROOF_KEY, disable_console_login=disable_console_login
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, CLIENT_PORT]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        "\r\n".join(
            [
                "POST / HTTP/1.1",
                "User-Agent: snowflake-agent",
                f"Host: localhost:{CLIENT_PORT}",
                "",
                f"token={ref_token}&confirm=true",
            ]
        )
    ).encode("utf-8")
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=mock_webbrowser,
        socket_pkg=mock_socket,
    )
    auth.prepare(
        conn=rest._connection,
        authenticator=AUTHENTICATOR,
        service_name=SERVICE_NAME,
        account=ACCOUNT,
        user=USER,
        password=PASSWORD,
    )
    assert not rest._connection.errorhandler.called  # no error
    assert auth.assertion_content == ref_token
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["TOKEN"] == ref_token
    assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR

    if disable_console_login:
        mock_webbrowser.open_new.assert_called_once_with(REF_SSO_URL)
        assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
    else:
        mock_webbrowser.open_new.assert_called_once_with(REF_CONSOLE_LOGIN_SSO_URL)


@pytest.mark.parametrize("disable_console_login", [True, False])
@pytest.mark.parametrize(
    "input_text,expected_error",
    [
        ("", True),
        ("http://example.com/notokenurl", True),
        ("http://example.com/sso?token=", True),
        ("http://example.com/sso?token=MOCK_TOKEN", False),
    ],
)
@patch("secrets.token_bytes", return_value=PROOF_KEY)
def test_auth_webbrowser_fail_webbrowser(
    _, capsys, input_text, expected_error, disable_console_login
):
    """Authentication by WebBrowser with failed to start web browser case."""
    rest = _init_rest(
        REF_SSO_URL, REF_PROOF_KEY, disable_console_login=disable_console_login
    )
    ref_token = "MOCK_TOKEN"

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = False

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, CLIENT_PORT]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        "\r\n".join(["GET /?token=MOCK_TOKEN HTTP/1.1", "User-Agent: snowflake-agent"])
    ).encode("utf-8")
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=mock_webbrowser,
        socket_pkg=mock_socket,
    )
    with patch("builtins.input", return_value=input_text):
        auth.prepare(
            conn=rest._connection,
            authenticator=AUTHENTICATOR,
            service_name=SERVICE_NAME,
            account=ACCOUNT,
            user=USER,
            password=PASSWORD,
        )
    captured = capsys.readouterr()
    assert captured.out == (
        "Initiating login request with your identity provider. A browser window "
        "should have opened for you to complete the login. If you can't see it, "
        "check existing browser windows, or your OS settings. Press CTRL+C to "
        f"abort and try again...\nGoing to open: {REF_SSO_URL if disable_console_login else REF_CONSOLE_LOGIN_SSO_URL} to authenticate...\nWe were unable to open a browser window for "
        "you, please open the url above manually then paste the URL you "
        "are redirected to into the terminal.\n"
    )
    if expected_error:
        assert rest._connection.errorhandler.called  # an error
        assert auth.assertion_content is None
    else:
        assert not rest._connection.errorhandler.called  # no error
        body = {"data": {}}
        auth.update_body(body)
        assert body["data"]["TOKEN"] == ref_token
        assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR
        if disable_console_login:
            assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY


@pytest.mark.parametrize("disable_console_login", [True, False])
@patch("secrets.token_bytes", return_value=PROOF_KEY)
def test_auth_webbrowser_fail_webserver(_, capsys, disable_console_login):
    """Authentication by WebBrowser with failed to start web browser case."""
    rest = _init_rest(
        REF_SSO_URL, REF_PROOF_KEY, disable_console_login=disable_console_login
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, CLIENT_PORT]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        "\r\n".join(["GARBAGE", "User-Agent: snowflake-agent"])
    ).encode("utf-8")
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    # case 1: invalid HTTP request
    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=mock_webbrowser,
        socket_pkg=mock_socket,
    )
    auth.prepare(
        conn=rest._connection,
        authenticator=AUTHENTICATOR,
        service_name=SERVICE_NAME,
        account=ACCOUNT,
        user=USER,
        password=PASSWORD,
    )
    captured = capsys.readouterr()
    assert captured.out == (
        "Initiating login request with your identity provider. A browser window "
        "should have opened for you to complete the login. If you can't see it, "
        "check existing browser windows, or your OS settings. Press CTRL+C to "
        f"abort and try again...\nGoing to open: {REF_SSO_URL if disable_console_login else REF_CONSOLE_LOGIN_SSO_URL} to authenticate...\n"
    )
    assert rest._connection.errorhandler.called  # an error
    assert auth.assertion_content is None


def _init_rest(
    ref_sso_url, ref_proof_key, success=True, message=None, disable_console_login=False
):
    def post_request(url, headers, body, **kwargs):
        _ = url
        _ = headers
        _ = body
        _ = kwargs.get("dummy")
        return {
            "success": success,
            "message": message,
            "data": {
                "ssoUrl": ref_sso_url,
                "proofKey": ref_proof_key,
            },
        }

    connection = mock_connection()
    connection.errorhandler = Mock(return_value=None)
    connection._ocsp_mode = Mock(return_value=OCSPMode.FAIL_OPEN)
    connection._disable_console_login = disable_console_login
    type(connection).application = PropertyMock(return_value=CLIENT_NAME)
    type(connection)._internal_application_name = PropertyMock(return_value=CLIENT_NAME)
    type(connection)._internal_application_version = PropertyMock(
        return_value=CLIENT_VERSION
    )

    rest = SnowflakeRestful(host=HOST, port=SNOWFLAKE_PORT, connection=connection)
    rest._post_request = post_request
    connection._rest = rest
    return rest


def test_idtoken_reauth():
    """This test makes sure that AuthByIdToken reverts to AuthByWebBrowser.

    This happens when the initial connection fails. Such as when the saved ID
    token has expired.
    """
    from snowflake.connector.auth.idtoken import AuthByIdToken

    auth_inst = AuthByIdToken(
        id_token="token",
        application="application",
        protocol="protocol",
        host="host",
        port="port",
    )

    # We'll use this Exception to make sure AuthByWebBrowser authentication
    #  flow is called as expected
    class StopExecuting(Exception):
        pass

    with mock.patch(
        "snowflake.connector.auth.idtoken.AuthByIdToken.prepare",
        side_effect=ReauthenticationRequest(Exception()),
    ):
        with mock.patch(
            "snowflake.connector.auth.webbrowser.AuthByWebBrowser.prepare",
            side_effect=StopExecuting(),
        ):
            with pytest.raises(StopExecuting):
                SnowflakeConnection(
                    user="user",
                    account="account",
                    auth_class=auth_inst,
                )


def test_auth_webbrowser_invalid_sso(monkeypatch):
    """Authentication by WebBrowser with failed to start web browser case."""
    rest = _init_rest(INVALID_SSO_URL, REF_PROOF_KEY, disable_console_login=True)

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = False

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, CLIENT_PORT]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        "\r\n".join(["GET /?token=MOCK_TOKEN HTTP/1.1", "User-Agent: snowflake-agent"])
    ).encode("utf-8")
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=mock_webbrowser,
        socket_pkg=mock_socket,
    )
    auth.prepare(
        conn=rest._connection,
        authenticator=AUTHENTICATOR,
        service_name=SERVICE_NAME,
        account=ACCOUNT,
        user=USER,
        password=PASSWORD,
    )
    assert rest._connection.errorhandler.called  # an error
    assert auth.assertion_content is None
