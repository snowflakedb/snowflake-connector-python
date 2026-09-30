#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import asyncio
import base64
import socket
from test.helpers import apply_auth_class_update_body_async, create_mock_auth_body
from test.unit.aio.mock_utils import mock_connection
from unittest import mock
from unittest.mock import MagicMock, Mock, PropertyMock, patch

import pytest

from snowflake.connector.aio import SnowflakeConnection
from snowflake.connector.aio._network import SnowflakeRestful
from snowflake.connector.aio.auth import AuthByIdToken, AuthByWebBrowser
from snowflake.connector.compat import IS_WINDOWS, urlencode
from snowflake.connector.constants import OCSPMode
from snowflake.connector.description import CLIENT_NAME, CLIENT_VERSION
from snowflake.connector.network import (
    EXTERNAL_BROWSER_AUTHENTICATOR,
    ReauthenticationRequest,
)

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


def browser_callback(request_line, *, headers=(), body="", line_ending="\r\n"):
    lines = [request_line, *headers]
    if body:
        lines.extend(["", body])
    return line_ending.join(lines).encode("utf-8")


def _init_socket():
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, CLIENT_PORT]
    mock_socket_client = MagicMock()
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    return Mock(return_value=mock_socket_instance)


def _mock_event_loop_sock_accept():
    async def mock_accept(*_):
        mock_socket_client = MagicMock()
        mock_socket_client.send.side_effect = lambda *args: None
        return mock_socket_client, None

    return mock_accept


def _mock_event_loop_sock_recv(recv_side_effect_func):
    async def mock_recv(*args):
        # first arg is socket_client, second arg is BUF_SIZE
        assert len(args) == 2
        return recv_side_effect_func(args[1])

    return mock_recv


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

        if call_number <= number_of_blocking_io_errors_before_success:
            raise BlockingIOError()
        else:
            return successful_web_callback(ref_token)

    return internally_scoped_function


@pytest.mark.parametrize("disable_console_login", [True, False])
@patch("secrets.token_bytes", return_value=PROOF_KEY)
async def test_auth_webbrowser_get(_, disable_console_login):
    """Authentication by WebBrowser positive test case."""
    ref_token = "MOCK_TOKEN"

    rest = _init_rest(
        REF_SSO_URL, REF_PROOF_KEY, disable_console_login=disable_console_login
    )

    # mock socket
    recv_func = recv_setup([successful_web_callback(ref_token)])
    mock_socket_pkg = _init_socket()

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
        with mock.patch.object(
            auth._event_loop,
            "sock_accept",
            side_effect=_mock_event_loop_sock_accept(),
        ), mock.patch.object(
            auth._event_loop, "sock_sendall", return_value=None
        ), mock.patch.object(
            auth._event_loop,
            "sock_recv",
            side_effect=_mock_event_loop_sock_recv(recv_func),
        ):
            await auth.prepare(
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
        await auth.update_body(body)
        assert body["data"]["TOKEN"] == ref_token
        assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR

        if disable_console_login:
            mock_webbrowser.open_new.assert_called_once_with(REF_SSO_URL)
            assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
        else:
            mock_webbrowser.open_new.assert_called_once_with(REF_CONSOLE_LOGIN_SSO_URL)


@pytest.mark.parametrize("disable_console_login", [True, False])
@patch("secrets.token_bytes", return_value=PROOF_KEY)
async def test_auth_webbrowser_post(_, disable_console_login):
    """Authentication by WebBrowser positive test case with POST."""
    ref_token = "MOCK_TOKEN"

    rest = _init_rest(
        REF_SSO_URL, REF_PROOF_KEY, disable_console_login=disable_console_login
    )

    # mock socket
    recv_func = recv_setup(
        [
            (
                "\r\n".join(
                    [
                        "POST / HTTP/1.1",
                        "User-Agent: snowflake-agent",
                        f"Host: localhost:{CLIENT_PORT}",
                        f"Origin: https://{HOST}",
                        "",
                        f"token={ref_token}&confirm=true",
                    ]
                )
            ).encode("utf-8")
        ]
    )
    mock_socket_pkg = _init_socket()

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
            protocol="https",
            host=HOST,
            port=SNOWFLAKE_PORT,
        )
        with mock.patch.object(
            auth._event_loop,
            "sock_accept",
            side_effect=_mock_event_loop_sock_accept(),
        ), mock.patch.object(
            auth._event_loop, "sock_sendall", return_value=None
        ), mock.patch.object(
            auth._event_loop,
            "sock_recv",
            side_effect=_mock_event_loop_sock_recv(recv_func),
        ):
            await auth.prepare(
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
        await auth.update_body(body)
        assert body["data"]["TOKEN"] == ref_token
        assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR

        if disable_console_login:
            mock_webbrowser.open_new.assert_called_once_with(REF_SSO_URL)
            assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
        else:
            mock_webbrowser.open_new.assert_called_once_with(REF_CONSOLE_LOGIN_SSO_URL)


async def test_auth_webbrowser_preflight_accepts_lf_and_case_insensitive_post():
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )
    socket_client = MagicMock()
    request = browser_callback(
        "OPTIONS / HTTP/1.1",
        headers=(
            f"Origin: https://{HOST}",
            "Access-Control-Request-Method: post",
            "Access-Control-Request-Headers: content-type",
        ),
        body="Origin: https://example.com",
        line_ending="\n",
    ).decode()

    with mock.patch.object(auth._event_loop, "sock_sendall") as sendall:
        assert await auth._process_options(request.splitlines(), socket_client)

    response = sendall.call_args.args[1].decode()
    assert "Access-Control-Allow-Origin: https://" + HOST in response
    assert "Access-Control-Allow-Headers: Content-Type" in response
    assert "example.com" not in response


@pytest.mark.parametrize(
    "request_line,origin_header,body",
    [
        ("POST / HTTP/1.1", None, "token=IGNORED"),
        ("POST / HTTP/1.1", "Origin: null", "token=IGNORED"),
        ("POST / HTTP/1.1", "Origin: https://example.com", "token=IGNORED"),
        (
            "GET /?token=IGNORED HTTP/1.1",
            "Origin: https://example.com",
            "",
        ),
    ],
)
async def test_auth_webbrowser_rejects_callback_without_account_origin(
    request_line, origin_header, body
):
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    headers = () if origin_header is None else (origin_header,)
    recv_func = recv_setup(
        [
            browser_callback(
                request_line,
                headers=headers,
                body=body,
            ),
            browser_callback(
                "GET /?token=ACCEPTED HTTP/1.1",
                headers=(f"Origin: https://{HOST}",),
            ),
        ]
    )
    mock_socket_pkg = _init_socket()
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch.object(
        auth._event_loop,
        "sock_accept",
        side_effect=_mock_event_loop_sock_accept(),
    ) as accept, mock.patch.object(
        auth._event_loop, "sock_sendall", return_value=None
    ), mock.patch.object(
        auth._event_loop,
        "sock_recv",
        side_effect=_mock_event_loop_sock_recv(recv_func),
    ):
        await auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    assert accept.call_count == 2


async def test_auth_webbrowser_rejected_preflight_keeps_listening():
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    recv_func = recv_setup(
        [
            browser_callback(
                "OPTIONS / HTTP/1.1",
                headers=(
                    "Origin: https://example.com",
                    "Access-Control-Request-Method: POST",
                    "Access-Control-Request-Headers: Content-Type",
                ),
                body="token=IGNORED",
            ),
            successful_web_callback("ACCEPTED"),
        ]
    )
    mock_socket_pkg = _init_socket()
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch.object(
        auth._event_loop,
        "sock_accept",
        side_effect=_mock_event_loop_sock_accept(),
    ) as accept, mock.patch.object(
        auth._event_loop, "sock_sendall", return_value=None
    ), mock.patch.object(
        auth._event_loop,
        "sock_recv",
        side_effect=_mock_event_loop_sock_recv(recv_func),
    ):
        await auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    assert not rest._connection.errorhandler.called
    assert accept.call_count == 2


async def test_auth_webbrowser_handles_options_method_case_insensitively():
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    recv_func = recv_setup(
        [
            browser_callback(
                "options / HTTP/1.1",
                headers=(
                    f"Origin: https://{HOST}",
                    "Access-Control-Request-Method: POST",
                    "Access-Control-Request-Headers: Content-Type",
                ),
            ),
            successful_web_callback("ACCEPTED"),
        ]
    )
    mock_socket_pkg = _init_socket()
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch.object(
        auth._event_loop,
        "sock_accept",
        side_effect=_mock_event_loop_sock_accept(),
    ) as accept, mock.patch.object(
        auth._event_loop, "sock_sendall", return_value=None
    ), mock.patch.object(
        auth._event_loop,
        "sock_recv",
        side_effect=_mock_event_loop_sock_recv(recv_func),
    ):
        await auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    assert accept.call_count == 2


@pytest.mark.parametrize("method", ["HEAD", "PATCH"])
async def test_auth_webbrowser_ignores_other_methods_and_keeps_listening(method):
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    recv_func = recv_setup(
        [
            browser_callback(f"{method} / HTTP/1.1"),
            successful_web_callback("ACCEPTED"),
        ]
    )
    mock_socket_pkg = _init_socket()
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch.object(
        auth._event_loop,
        "sock_accept",
        side_effect=_mock_event_loop_sock_accept(),
    ) as accept, mock.patch.object(
        auth._event_loop, "sock_sendall", return_value=None
    ), mock.patch.object(
        auth._event_loop,
        "sock_recv",
        side_effect=_mock_event_loop_sock_recv(recv_func),
    ):
        await auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    assert not rest._connection.errorhandler.called
    assert accept.call_count == 2


@pytest.mark.parametrize(
    "first_request",
    [
        browser_callback(
            "PATCH / HTTP/1.1",
            body="GET /?token=IGNORED HTTP/1.1",
        ),
        "\r\n".join(
            [
                "POST / HTTP/1.1",
                f"Origin: https://{HOST}",
                "token=IGNORED",
            ]
        ).encode(),
    ],
)
async def test_auth_webbrowser_uses_request_line_and_post_body_sections(
    first_request,
):
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    recv_func = recv_setup([first_request, successful_web_callback("ACCEPTED")])
    mock_socket_pkg = _init_socket()
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch.object(
        auth._event_loop,
        "sock_accept",
        side_effect=_mock_event_loop_sock_accept(),
    ) as accept, mock.patch.object(
        auth._event_loop, "sock_sendall", return_value=None
    ), mock.patch.object(
        auth._event_loop,
        "sock_recv",
        side_effect=_mock_event_loop_sock_recv(recv_func),
    ):
        await auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    assert accept.call_count == 2


async def test_auth_webbrowser_ignores_socket_shutdown_error():
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    recv_func = recv_setup([successful_web_callback("ACCEPTED")])
    mock_socket_pkg = _init_socket()
    socket_client = MagicMock()
    socket_client.shutdown.side_effect = OSError

    async def accept(*_):
        return socket_client, None

    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch.object(
        auth._event_loop, "sock_accept", side_effect=accept
    ), mock.patch.object(
        auth._event_loop, "sock_sendall", return_value=None
    ), mock.patch.object(
        auth._event_loop,
        "sock_recv",
        side_effect=_mock_event_loop_sock_recv(recv_func),
    ):
        await auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    socket_client.close.assert_called_once()


async def test_auth_webbrowser_closes_optional_socket_client():
    socket_client = MagicMock()
    socket_client.shutdown.side_effect = OSError
    socket_client.close.side_effect = OSError

    AuthByWebBrowser._close_socket_client(None)
    AuthByWebBrowser._close_socket_client(socket_client)

    socket_client.shutdown.assert_called_once_with(socket.SHUT_RDWR)
    socket_client.close.assert_called_once()


@pytest.mark.parametrize("origin_header", [None, "Origin: null"])
async def test_auth_webbrowser_accepts_browser_get_without_account_origin(
    origin_header,
):
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    headers = () if origin_header is None else (origin_header,)
    recv_func = recv_setup(
        [
            browser_callback(
                "GET /?token=ACCEPTED HTTP/1.1",
                headers=headers,
            )
        ]
    )
    mock_socket_pkg = _init_socket()
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch.object(
        auth._event_loop,
        "sock_accept",
        side_effect=_mock_event_loop_sock_accept(),
    ), mock.patch.object(
        auth._event_loop, "sock_sendall", return_value=None
    ), mock.patch.object(
        auth._event_loop,
        "sock_recv",
        side_effect=_mock_event_loop_sock_recv(recv_func),
    ):
        await auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"


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
async def test_auth_webbrowser_fail_webbrowser(
    _, capsys, input_text, expected_error, disable_console_login
):
    """Authentication by WebBrowser with failed to start web browser case."""
    rest = _init_rest(
        REF_SSO_URL, REF_PROOF_KEY, disable_console_login=disable_console_login
    )
    ref_token = "MOCK_TOKEN"

    # mock socket
    recv_func = recv_setup([successful_web_callback(ref_token)])
    mock_socket_pkg = _init_socket()

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = False

    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=mock_webbrowser,
        socket_pkg=mock_socket_pkg,
    )
    with patch("builtins.input", return_value=input_text), patch.object(
        auth._event_loop,
        "sock_accept",
        side_effect=_mock_event_loop_sock_accept(),
    ), mock.patch.object(
        auth._event_loop, "sock_sendall", return_value=None
    ), mock.patch.object(
        auth._event_loop, "sock_recv", side_effect=_mock_event_loop_sock_recv(recv_func)
    ):
        await auth.prepare(
            conn=rest._connection,
            authenticator=AUTHENTICATOR,
            service_name=SERVICE_NAME,
            account=ACCOUNT,
            user=USER,
            password=PASSWORD,
        )
    captured = capsys.readouterr()
    assert captured.out == (
        "Initiating login request with your identity provider. Press CTRL+C to "
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
        await auth.update_body(body)
        assert body["data"]["TOKEN"] == ref_token
        assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR
        if disable_console_login:
            assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY


@pytest.mark.parametrize("disable_console_login", [True, False])
@patch("secrets.token_bytes", return_value=PROOF_KEY)
async def test_auth_webbrowser_fail_webserver(_, capsys, disable_console_login):
    """Authentication by WebBrowser with failed to start web browser case."""
    rest = _init_rest(
        REF_SSO_URL, REF_PROOF_KEY, disable_console_login=disable_console_login
    )

    # mock socket
    recv_func = recv_setup(
        [
            ("\r\n".join(["GARBAGE", "User-Agent: snowflake-agent"])).encode("utf-8"),
            successful_web_callback("ACCEPTED"),
        ]
    )
    mock_socket_pkg = _init_socket()

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
        with mock.patch.object(
            auth._event_loop,
            "sock_accept",
            side_effect=_mock_event_loop_sock_accept(),
        ), mock.patch.object(
            auth._event_loop, "sock_sendall", return_value=None
        ), mock.patch.object(
            auth._event_loop,
            "sock_recv",
            side_effect=_mock_event_loop_sock_recv(recv_func),
        ):
            await auth.prepare(
                conn=rest._connection,
                authenticator=AUTHENTICATOR,
                service_name=SERVICE_NAME,
                account=ACCOUNT,
                user=USER,
                password=PASSWORD,
            )
        captured = capsys.readouterr()
        assert captured.out == (
            "Initiating login request with your identity provider. Press CTRL+C to "
            f"abort and try again...\nGoing to open: {REF_SSO_URL if disable_console_login else REF_CONSOLE_LOGIN_SSO_URL} to authenticate...\nA browser window "
            "should have opened for you to complete the login. If you can't see it, "
            "check existing browser windows, or your OS settings.\n"
        )
        assert not rest._connection.errorhandler.called
        assert auth.assertion_content == "ACCEPTED"


def _init_rest(
    ref_sso_url,
    ref_proof_key,
    success=True,
    message=None,
    disable_console_login=False,
    socket_timeout=None,
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
                "proofKey": ref_proof_key,
            },
        }

    connection = mock_connection(socket_timeout=socket_timeout)
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


async def test_idtoken_reauth():
    """This test makes sure that AuthByIdToken reverts to AuthByWebBrowser.

    This happens when the initial connection fails. Such as when the saved ID
    token has expired.
    """

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
        "snowflake.connector.aio.auth.AuthByIdToken.prepare",
        side_effect=ReauthenticationRequest(Exception()),
    ):
        with mock.patch(
            "snowflake.connector.aio.auth.AuthByWebBrowser.prepare",
            side_effect=StopExecuting(),
        ):
            with pytest.raises(StopExecuting):
                async with SnowflakeConnection(
                    user="user",
                    account="account",
                    auth_class=auth_inst,
                ):
                    pass


async def test_auth_webbrowser_invalid_sso(monkeypatch):
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
    await auth.prepare(
        conn=rest._connection,
        authenticator=AUTHENTICATOR,
        service_name=SERVICE_NAME,
        account=ACCOUNT,
        user=USER,
        password=PASSWORD,
    )
    assert rest._connection.errorhandler.called  # an error
    assert auth.assertion_content is None


async def test_auth_webbrowser_socket_recv_retries_up_to_15_times_on_empty_bytearray():
    """Authentication by WebBrowser retries on empty bytearray response from socket.recv"""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY, disable_console_login=True)

    # mock socket
    recv_func = recv_setup(
        # 14th return is empty byte array, but 15th call will return successful_web_callback
        ([bytearray()] * 14)
        + [successful_web_callback(ref_token)]
    )
    mock_socket_pkg = _init_socket()

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch("asyncio.sleep") as sleep:
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
        )
        with patch.object(
            auth._event_loop,
            "sock_accept",
            side_effect=_mock_event_loop_sock_accept(),
        ), mock.patch.object(
            auth._event_loop, "sock_sendall", return_value=None
        ), mock.patch.object(
            auth._event_loop,
            "sock_recv",
            side_effect=_mock_event_loop_sock_recv(recv_func),
        ):
            await auth.prepare(
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
        await auth.update_body(body)
        assert body["data"]["TOKEN"] == ref_token
        assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR
        assert sleep.call_count == 0


async def test_auth_webbrowser_socket_recv_loop_continues_on_empty_recv():
    """Empty recv from a preconnect probe causes the outer loop to continue to the next connection."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock socket
    recv_func = recv_setup(
        # 15 empty recvs exhaust the per-connection retry budget; the outer loop
        # then continues and accepts a fresh connection that delivers the real token.
        ([bytearray()] * 15)
        + [successful_web_callback(ref_token)]
    )
    mock_socket_pkg = _init_socket()

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch("asyncio.sleep") as sleep:
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
        )
        with mock.patch.object(
            auth._event_loop,
            "sock_accept",
            side_effect=_mock_event_loop_sock_accept(),
        ), mock.patch.object(
            auth._event_loop, "sock_sendall", return_value=None
        ), mock.patch.object(
            auth._event_loop,
            "sock_recv",
            side_effect=_mock_event_loop_sock_recv(recv_func),
        ):
            await auth.prepare(
                conn=rest._connection,
                authenticator=AUTHENTICATOR,
                service_name=SERVICE_NAME,
                account=ACCOUNT,
                user=USER,
                password=PASSWORD,
            )
        assert not rest._connection.errorhandler.called  # no error
        assert auth.assertion_content == ref_token
        assert sleep.call_count == 0


async def test_auth_webbrowser_socket_recv_does_not_block_with_env_var(monkeypatch):
    """Authentication by WebBrowser socket.recv Does not block, but retries if BlockingIOError thrown."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(
        REF_SSO_URL, REF_PROOF_KEY, disable_console_login=True, socket_timeout=1
    )

    # mock socket
    mock_socket_pkg = _init_socket()

    counting = 0

    async def sock_recv_timeout(*_):
        nonlocal counting
        if counting < 14:
            counting += 1
            raise asyncio.TimeoutError()
        return successful_web_callback(ref_token)

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch("asyncio.sleep") as sleep:
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
        )

        with mock.patch.object(
            auth._event_loop, "sock_recv", new=sock_recv_timeout
        ), mock.patch.object(
            auth._event_loop,
            "sock_accept",
            side_effect=_mock_event_loop_sock_accept(),
        ), mock.patch.object(
            auth._event_loop, "sock_sendall", return_value=None
        ):
            await auth.prepare(
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
            await auth.update_body(body)
            assert body["data"]["TOKEN"] == ref_token
            assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
            assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR
            sleep_times = [t[0][0] for t in sleep.call_args_list]
            assert sleep.call_count == counting == 14
            assert sleep_times == [0.25] * 14


async def test_auth_webbrowser_socket_recv_blocking_continues_after_15_attempts(
    monkeypatch,
):
    """After 15 TimeoutErrors the outer loop continues to the next connection."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY, disable_console_login=True)

    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", "true")

    # mock socket
    mock_socket_pkg = _init_socket()

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    counting = 0

    async def sock_recv_15_timeouts_then_success(*_):
        nonlocal counting
        if counting < 15:
            counting += 1
            raise asyncio.TimeoutError()
        return successful_web_callback(ref_token)

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ), mock.patch("asyncio.sleep") as sleep:
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
        )
        with mock.patch.object(
            auth._event_loop, "sock_recv", new=sock_recv_15_timeouts_then_success
        ), mock.patch.object(
            auth._event_loop, "sock_sendall", return_value=None
        ), mock.patch.object(
            auth._event_loop,
            "sock_accept",
            side_effect=_mock_event_loop_sock_accept(),
        ):
            await auth.prepare(
                conn=rest._connection,
                authenticator=AUTHENTICATOR,
                service_name=SERVICE_NAME,
                account=ACCOUNT,
                user=USER,
                password=PASSWORD,
            )
        assert not rest._connection.errorhandler.called  # no error
        assert auth.assertion_content == ref_token
        assert counting == 15
        sleep_times = [t[0][0] for t in sleep.call_args_list]
        assert sleep.call_count == 14
        assert sleep_times == [0.25] * 14


@pytest.mark.skipif(
    IS_WINDOWS, reason="SNOWFLAKE_AUTH_SOCKET_REUSE_PORT is not supported on Windows"
)
async def test_auth_webbrowser_socket_reuseport_with_env_flag(monkeypatch):
    """Authentication by WebBrowser socket.recv Does not block, but retries if BlockingIOError thrown."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock socket
    recv_func = recv_setup([successful_web_callback(ref_token)])
    mock_socket_pkg = _init_socket()

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
        with mock.patch.object(
            auth._event_loop,
            "sock_accept",
            side_effect=_mock_event_loop_sock_accept(),
        ), mock.patch.object(
            auth._event_loop, "sock_sendall", return_value=None
        ), mock.patch.object(
            auth._event_loop,
            "sock_recv",
            side_effect=_mock_event_loop_sock_recv(recv_func),
        ):
            await auth.prepare(
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


async def test_auth_webbrowser_socket_reuseport_option_not_set_with_false_flag(
    monkeypatch,
):
    """Authentication by WebBrowser socket.recv Does not block, but retries if BlockingIOError thrown."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock socket
    recv_func = recv_setup([successful_web_callback(ref_token)])
    mock_socket_pkg = _init_socket()

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
        with mock.patch.object(
            auth._event_loop,
            "sock_accept",
            side_effect=_mock_event_loop_sock_accept(),
        ), mock.patch.object(
            auth._event_loop, "sock_sendall", return_value=None
        ), mock.patch.object(
            auth._event_loop,
            "sock_recv",
            side_effect=_mock_event_loop_sock_recv(recv_func),
        ):
            await auth.prepare(
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


async def test_auth_webbrowser_socket_reuseport_option_not_set_with_no_flag(
    monkeypatch,
):
    """Authentication by WebBrowser socket.recv Does not block, but retries if BlockingIOError thrown."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock socket
    recv_func = recv_setup([successful_web_callback(ref_token)])
    mock_socket_pkg = _init_socket()

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
        with mock.patch.object(
            auth._event_loop,
            "sock_accept",
            side_effect=_mock_event_loop_sock_accept(),
        ), mock.patch.object(
            auth._event_loop, "sock_sendall", return_value=None
        ), mock.patch.object(
            auth._event_loop,
            "sock_recv",
            side_effect=_mock_event_loop_sock_recv(recv_func),
        ):
            await auth.prepare(
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


@pytest.mark.parametrize("force_auth_server", [True, False])
@patch("secrets.token_bytes", return_value=PROOF_KEY)
async def test_auth_webbrowser_force_auth_server(_, monkeypatch, force_auth_server):
    """Authentication by WebBrowser with SNOWFLAKE_AUTH_FORCE_SERVER environment variable."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY, disable_console_login=True)

    # Set environment variable
    if force_auth_server:
        monkeypatch.setenv("SNOWFLAKE_AUTH_FORCE_SERVER", "true")
    else:
        monkeypatch.delenv("SNOWFLAKE_AUTH_FORCE_SERVER", raising=False)

    # mock socket
    recv_func = recv_setup([successful_web_callback(ref_token)])
    mock_socket_pkg = _init_socket()

    # mock webbrowser - simulate browser failing to open
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = False

    # Mock select.select to return socket client
    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth = AuthByWebBrowser(
            application=APPLICATION,
            webbrowser_pkg=mock_webbrowser,
            socket_pkg=mock_socket_pkg,
        )

        if force_auth_server:
            # When SNOWFLAKE_AUTH_FORCE_SERVER is true, should continue with server flow even if browser fails
            with mock.patch.object(
                auth._event_loop,
                "sock_accept",
                side_effect=_mock_event_loop_sock_accept(),
            ), mock.patch.object(
                auth._event_loop, "sock_sendall", return_value=None
            ), mock.patch.object(
                auth._event_loop,
                "sock_recv",
                side_effect=_mock_event_loop_sock_recv(recv_func),
            ):
                await auth.prepare(
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
            await auth.update_body(body)
            assert body["data"]["TOKEN"] == ref_token
            assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR
            assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
        else:
            # When SNOWFLAKE_AUTH_FORCE_SERVER is false/unset, should fall back to manual URL input
            with patch(
                "builtins.input",
                return_value=f"http://example.com/sso?token={ref_token}",
            ), mock.patch.object(
                auth._event_loop,
                "sock_accept",
                side_effect=_mock_event_loop_sock_accept(),
            ), mock.patch.object(
                auth._event_loop, "sock_sendall", return_value=None
            ), mock.patch.object(
                auth._event_loop,
                "sock_recv",
                side_effect=_mock_event_loop_sock_recv(recv_func),
            ):
                await auth.prepare(
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
            await auth.update_body(body)
            assert body["data"]["TOKEN"] == ref_token
            assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR
            assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY


@pytest.mark.parametrize("authenticator", ["EXTERNALBROWSER", "externalbrowser"])
async def test_externalbrowser_authenticator_is_case_insensitive(
    monkeypatch, authenticator
):
    """Test that external browser authenticator is case insensitive."""
    import snowflake.connector.aio
    from snowflake.connector.aio._network import SnowflakeRestful

    async def mock_post_request(self, url, headers, json_body, **kwargs):
        return {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN",
                "masterToken": "MASTER_TOKEN",
                "idToken": None,
                "parameters": [{"name": "SERVICE_NAME", "value": "FAKE_SERVICE_NAME"}],
            },
        }

    monkeypatch.setattr(SnowflakeRestful, "_post_request", mock_post_request)

    # Mock the webbrowser authentication to avoid opening actual browser
    async def mock_webbrowser_auth_prepare(
        self, conn, authenticator, service_name, account, user, password
    ):
        # Just set the token directly to simulate successful browser auth
        self._token = "MOCK_TOKEN"

    monkeypatch.setattr(AuthByWebBrowser, "prepare", mock_webbrowser_auth_prepare)

    # Create connection with external browser authenticator
    conn = snowflake.connector.aio.SnowflakeConnection(
        user="testuser",
        account="testaccount",
        authenticator=authenticator,
    )
    await conn.connect()

    # Verify that the auth_class is an instance of AuthByWebBrowser
    assert isinstance(conn.auth_class, AuthByWebBrowser)

    await conn.close()


async def test_auth_prepare_body_does_not_overwrite_client_environment_fields():
    auth_class = AuthByWebBrowser(application=APPLICATION)
    req_body_before = create_mock_auth_body()
    req_body_after = await apply_auth_class_update_body_async(
        auth_class, req_body_before
    )

    assert all(
        [
            req_body_before["data"]["CLIENT_ENVIRONMENT"][k]
            == req_body_after["data"]["CLIENT_ENVIRONMENT"][k]
            for k in req_body_before["data"]["CLIENT_ENVIRONMENT"]
        ]
    )


def test_mro():
    """Ensure that methods from AuthByPluginAsync override those from AuthByPlugin."""
    from snowflake.connector.aio.auth import AuthByPlugin as AuthByPluginAsync
    from snowflake.connector.auth import AuthByPlugin as AuthByPluginSync

    assert AuthByWebBrowser.mro().index(
        AuthByPluginAsync
    ) < AuthByWebBrowser.mro().index(AuthByPluginSync)

    assert AuthByIdToken.mro().index(AuthByPluginAsync) < AuthByIdToken.mro().index(
        AuthByPluginSync
    )
