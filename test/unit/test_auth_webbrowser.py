#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import base64
import socket
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

def successful_web_callback(token):
    return (
        "\r\n".join(
            [
                f"GET /?token={token}&confirm=true HTTP/1.1",
                "User-Agent: snowflake-agent",
            ]
        )
    ).encode("utf-8")


def _init_socket(recv_side_effect_func):
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, CLIENT_PORT]

    mock_socket_client = MagicMock()

    mock_socket_client.recv.side_effect = recv_side_effect_func
    mock_socket_instance.accept.return_value = (mock_socket_client, None)

    return Mock(return_value=mock_socket_instance)


class UnexpectedRecvArgs(Exception):
    pass


def recv_setup(recv_list):
    recv_call_number = 0

    def recv_side_effect(*args):
        nonlocal recv_call_number
        recv_call_number += 1

        # if we should block (default behavior), then the only arg should be BUF_SIZE
        if len(args) == 1:
            return recv_list[recv_call_number - 1]

        raise UnexpectedRecvArgs(
            f"socket_client.recv call expected a single argeument, but received: {args}"
        )

    return recv_side_effect


def recv_setup_with_msg_nowait(
    ref_token, number_of_blocking_io_errors_before_success=1
):
    call_number = 0

    def internally_scoped_function(*args):
        nonlocal call_number
        call_number += 1

        # if we should NOT block, then the MSG_DONTWAIT flag should be second arg
        if len(args) > 1 and args[1] == socket.MSG_DONTWAIT:
            if call_number <= number_of_blocking_io_errors_before_success:
                raise BlockingIOError()
            else:
                return successful_web_callback(ref_token)
        else:
            raise Exception(
                f"socket_client.recv call expected the second arg to be socket.MSG_DONTWAINT, but received: {args}"
            )

    return internally_scoped_function

@pytest.mark.parametrize("disable_console_login", [True, False])
@patch("secrets.token_bytes", return_value=PROOF_KEY)
def test_auth_webbrowser_get(_, disable_console_login):
    """Authentication by WebBrowser positive test case."""
    ref_token = "MOCK_TOKEN"

    rest = _init_rest(
        REF_SSO_URL, REF_PROOF_KEY, disable_console_login=disable_console_login
    )

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup([successful_web_callback(ref_token)])
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
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

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup(
            [
                (
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
            ]
        )
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
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

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup([successful_web_callback(ref_token)])
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = False

    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=mock_webbrowser,
        socket_pkg=mock_socket_pkg,
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

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup(
            [("\r\n".join(["GARBAGE", "User-Agent: snowflake-agent"])).encode("utf-8")]
        )
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        # case 1: invalid HTTP request
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
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


def test_auth_webbrowser_socket_recv_retries_up_to_15_times_on_empty_bytearray():
    """Authentication by WebBrowser retries on empty bytearray response from socket.recv"""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(INVALID_SSO_URL, REF_PROOF_KEY, disable_console_login=True)

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup(
            # 14th return is empty byte array, but 15th call will return successful_web_callback
            ([bytearray()] * 14)
            + [successful_web_callback(ref_token)]
        )
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch("time.sleep") as sleep:
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
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
        assert sleep.call_count == 0


def test_auth_webbrowser_socket_recv_loop_fails_after_15_attempts():
    """Authentication by WebBrowser stops trying after 15 consective socket.recv emty bytearray returns."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup(
            # 15th return is empty byte array, so successful_web_callback will never be fetched from recv
            ([bytearray()] * 15)
            + [successful_web_callback(ref_token)]
        )
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch("time.sleep") as sleep:
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
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
        assert sleep.call_count == 0


def test_auth_webbrowser_socket_recv_does_not_block_with_env_var(monkeypatch):
    """Authentication by WebBrowser socket.recv Does not block, but retries if BlockingIOError thrown."""

    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", "true")

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup_with_msg_nowait(
            ref_token, number_of_blocking_io_errors_before_success=14
        )
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch("time.sleep") as sleep:
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
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
        assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
        assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR
        sleep_times = [t[0][0] for t in sleep.call_args_list]
        assert sleep.call_count == 14
        assert sleep_times == [0.25] * 14


def test_auth_webbrowser_socket_recv_blocking_stops_retries_after_15_attempts(
    monkeypatch,
):
    """Authentication by WebBrowser socket.recv Does not block, but retries if BlockingIOError thrown."""

    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", "true")

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup_with_msg_nowait(
            ref_token, number_of_blocking_io_errors_before_success=15
        )
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch("time.sleep") as sleep:
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
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
        sleep_times = [t[0][0] for t in sleep.call_args_list]
        assert sleep.call_count == 14
        assert sleep_times == [0.25] * 14


def test_auth_webbrowser_socket_reuseport_with_env_flag(monkeypatch):
    """Authentication by WebBrowser socket.recv Does not block, but retries if BlockingIOError thrown."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup([successful_web_callback(ref_token)])
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "true")

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
        )
        auth.prepare(
            conn=rest._connection,
            authenticator=AUTHENTICATOR,
            service_name=SERVICE_NAME,
            account=ACCOUNT,
            user=USER,
            password=PASSWORD,
        )
        assert mock_socket_pkg.return_value.setsockopt.call_count == 1
        assert mock_socket_pkg.return_value.setsockopt.call_args.args == (
            socket.SOL_SOCKET,
            socket.SO_REUSEPORT,
            1,
        )

        assert not rest._connection.errorhandler.called  # no error
        assert auth.assertion_content == ref_token


def test_auth_webbrowser_socket_reuseport_option_not_set_with_false_flag(monkeypatch):
    """Authentication by WebBrowser socket.recv Does not block, but retries if BlockingIOError thrown."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup([successful_web_callback(ref_token)])
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_REUSE_PORT", "false")

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
        )
        auth.prepare(
            conn=rest._connection,
            authenticator=AUTHENTICATOR,
            service_name=SERVICE_NAME,
            account=ACCOUNT,
            user=USER,
            password=PASSWORD,
        )
        assert mock_socket_pkg.return_value.setsockopt.call_count == 0

        assert not rest._connection.errorhandler.called  # no error
        assert auth.assertion_content == ref_token


def test_auth_webbrowser_socket_reuseport_option_not_set_with_no_flag(monkeypatch):
    """Authentication by WebBrowser socket.recv Does not block, but retries if BlockingIOError thrown."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup([successful_web_callback(ref_token)])
    )

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
        )
        auth.prepare(
            conn=rest._connection,
            authenticator=AUTHENTICATOR,
            service_name=SERVICE_NAME,
            account=ACCOUNT,
            user=USER,
            password=PASSWORD,
        )
        assert mock_socket_pkg.return_value.setsockopt.call_count == 0

        assert not rest._connection.errorhandler.called  # no error
        assert auth.assertion_content == ref_token
