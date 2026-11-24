#!/usr/bin/env python
from __future__ import annotations

import base64
import socket
from test.helpers import apply_auth_class_update_body, create_mock_auth_body
from unittest import mock
from unittest.mock import MagicMock, Mock, PropertyMock, patch

import pytest

from snowflake.connector import SnowflakeConnection
from snowflake.connector.compat import IS_WINDOWS, urlencode
from snowflake.connector.constants import OCSPMode
from snowflake.connector.description import CLIENT_NAME, CLIENT_VERSION
from snowflake.connector.errorcode import ER_OAUTH_SERVER_TIMEOUT
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


def browser_callback(request_line, *, headers=(), body="", line_ending="\r\n"):
    lines = [request_line, *headers]
    if body:
        lines.extend(["", body])
    return line_ending.join(lines).encode("utf-8")


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
            protocol="https",
            host=HOST,
            port=SNOWFLAKE_PORT,
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
                            f"Origin: https://{HOST}",
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
            protocol="https",
            host=HOST,
            port=SNOWFLAKE_PORT,
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


@pytest.mark.parametrize(
    "origin,expected",
    [
        (f"https://{HOST}", True),
        (f"https://{HOST}:443", True),
        (f"https://{HOST}/", True),
        (f"http://{HOST}", False),
        (f"https://other.{HOST}", False),
        (f"https://{HOST}:8443", False),
    ],
)
def test_auth_webbrowser_validates_callback_origin(origin, expected):
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    assert auth._validate_origin(origin) is expected


@pytest.mark.parametrize("line_ending", ["\r\n", "\n"])
def test_auth_webbrowser_preflight_uses_headers_only(line_ending):
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
        line_ending=line_ending,
    ).decode()

    assert auth._process_options(request.splitlines(), socket_client)
    response = socket_client.sendall.call_args.args[0].decode()
    assert "Access-Control-Allow-Origin: https://" + HOST in response
    assert "Access-Control-Allow-Headers: Content-Type" in response
    assert "example.com" not in response


@pytest.mark.parametrize(
    "requested_headers,accepted",
    [
        (None, True),
        ("Content-Type", True),
        ("content-type, CONTENT-TYPE", True),
        ("Content-Type, X-Other", False),
    ],
)
def test_auth_webbrowser_preflight_limits_requested_headers(
    requested_headers, accepted
):
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )
    socket_client = MagicMock()
    headers = [
        f"Origin: https://{HOST}",
        "Access-Control-Request-Method: POST",
    ]
    if requested_headers is not None:
        headers.append(f"Access-Control-Request-Headers: {requested_headers}")

    assert auth._process_options(
        browser_callback("OPTIONS / HTTP/1.1", headers=headers).decode().splitlines(),
        socket_client,
    )
    assert socket_client.sendall.called is accepted


def test_auth_webbrowser_does_not_read_origin_from_body():
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
            "Access-Control-Request-Method: POST",
            "Access-Control-Request-Headers: Content-Type",
        ),
        body=f"Origin: https://{HOST}",
    ).decode()

    assert auth._process_options(request.splitlines(), socket_client)
    socket_client.sendall.assert_not_called()


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
def test_auth_webbrowser_rejects_callback_without_account_origin(
    request_line, origin_header, body
):
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    headers = () if origin_header is None else (origin_header,)
    requests = [
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
    mock_socket_pkg = _init_socket(recv_side_effect_func=recv_setup(requests))
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    assert mock_socket_pkg.return_value.accept.call_count == 2


def test_auth_webbrowser_rejected_preflight_keeps_listening():
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    requests = [
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
    mock_socket_pkg = _init_socket(recv_side_effect_func=recv_setup(requests))
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    assert not rest._connection.errorhandler.called
    assert mock_socket_pkg.return_value.accept.call_count == 2


def test_auth_webbrowser_handles_options_method_case_insensitively():
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    requests = [
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
    mock_socket_pkg = _init_socket(recv_side_effect_func=recv_setup(requests))
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    assert mock_socket_pkg.return_value.accept.call_count == 2


@pytest.mark.parametrize("method", ["HEAD", "PATCH"])
def test_auth_webbrowser_ignores_other_methods_and_keeps_listening(method):
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    requests = [
        browser_callback(f"{method} / HTTP/1.1"),
        successful_web_callback("ACCEPTED"),
    ]
    mock_socket_pkg = _init_socket(recv_side_effect_func=recv_setup(requests))
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    assert not rest._connection.errorhandler.called
    assert mock_socket_pkg.return_value.accept.call_count == 2


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
def test_auth_webbrowser_uses_request_line_and_post_body_sections(first_request):
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup(
            [first_request, successful_web_callback("ACCEPTED")]
        )
    )
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"
    assert mock_socket_pkg.return_value.accept.call_count == 2


def test_auth_webbrowser_ignores_socket_shutdown_error():
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup([successful_web_callback("ACCEPTED")])
    )
    mock_socket_pkg.return_value.accept.return_value[0].shutdown.side_effect = OSError
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

    assert auth.assertion_content == "ACCEPTED"


def test_auth_webbrowser_closes_optional_socket_client():
    socket_client = MagicMock()
    socket_client.shutdown.side_effect = OSError
    socket_client.close.side_effect = OSError

    AuthByWebBrowser._close_socket_client(None)
    AuthByWebBrowser._close_socket_client(socket_client)

    socket_client.shutdown.assert_called_once_with(socket.SHUT_RDWR)
    socket_client.close.assert_called_once()


@pytest.mark.parametrize("origin_header", [None, "Origin: null"])
def test_auth_webbrowser_accepts_browser_get_without_account_origin(origin_header):
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    headers = () if origin_header is None else (origin_header,)
    request = browser_callback(
        "GET /?token=ACCEPTED HTTP/1.1",
        headers=headers,
    )
    mock_socket_pkg = _init_socket(recv_side_effect_func=recv_setup([request]))
    auth = AuthByWebBrowser(
        application=APPLICATION,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch(
        "select.select", return_value=([mock_socket_pkg.return_value], [], [])
    ):
        auth._receive_saml_token(rest._connection, mock_socket_pkg.return_value)

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
            [
                ("\r\n".join(["GARBAGE", "User-Agent: snowflake-agent"])).encode(
                    "utf-8"
                ),
                successful_web_callback("ACCEPTED"),
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
    connection.cert_revocation_check_mode = "TEST_CRL_MODE"
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
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY, disable_console_login=True)

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


def test_auth_webbrowser_socket_recv_loop_continues_on_empty_recv():
    """Empty recv from a preconnect probe causes the outer loop to continue to the next connection."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup(
            # 15 empty recvs exhaust the per-connection retry budget; the outer loop
            # then continues and accepts a fresh connection that delivers the real token.
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
        assert not rest._connection.errorhandler.called  # no error
        assert auth.assertion_content == ref_token
        assert sleep.call_count == 0


@pytest.mark.skipif(IS_WINDOWS, reason="MSG_DONTWAIT is not supported on Windows")
def test_auth_webbrowser_socket_recv_does_not_block_with_env_var(monkeypatch):
    """Authentication by WebBrowser socket.recv Does not block, but retries if BlockingIOError thrown."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY, disable_console_login=True)

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


@pytest.mark.skipif(IS_WINDOWS, reason="MSG_DONTWAIT is not supported on Windows")
def test_auth_webbrowser_socket_recv_blocking_continues_after_15_attempts(
    monkeypatch,
):
    """After 15 BlockingIOErrors the outer loop continues to the next connection."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    monkeypatch.setenv("SNOWFLAKE_AUTH_SOCKET_MSG_DONTWAIT", "true")

    # mock socket: 15 BlockingIOErrors exhaust the per-connection budget; the outer
    # loop continues and the 16th recv delivers the real token.
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
        assert not rest._connection.errorhandler.called  # no error
        assert auth.assertion_content == ref_token
        sleep_times = [t[0][0] for t in sleep.call_args_list]
        assert sleep.call_count == 14
        assert sleep_times == [0.25] * 14


@pytest.mark.skipif(
    IS_WINDOWS, reason="SNOWFLAKE_AUTH_SOCKET_REUSE_PORT is not supported on Windows"
)
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


@pytest.mark.parametrize("force_auth_server", [True, False])
@patch("secrets.token_bytes", return_value=PROOF_KEY)
def test_auth_webbrowser_force_auth_server(_, monkeypatch, force_auth_server):
    """Authentication by WebBrowser with SNOWFLAKE_AUTH_FORCE_SERVER environment variable."""
    ref_token = "MOCK_TOKEN"
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY, disable_console_login=True)

    # Set environment variable
    if force_auth_server:
        monkeypatch.setenv("SNOWFLAKE_AUTH_FORCE_SERVER", "true")
    else:
        monkeypatch.delenv("SNOWFLAKE_AUTH_FORCE_SERVER", raising=False)

    # mock socket
    mock_socket_pkg = _init_socket(
        recv_side_effect_func=recv_setup([successful_web_callback(ref_token)])
    )

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
            assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
        else:
            # When SNOWFLAKE_AUTH_FORCE_SERVER is false/unset, should fall back to manual URL input
            with patch(
                "builtins.input",
                return_value=f"http://example.com/sso?token={ref_token}",
            ):
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
                assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY


@pytest.mark.parametrize("authenticator", ["EXTERNALBROWSER", "externalbrowser"])
def test_externalbrowser_authenticator_is_case_insensitive(monkeypatch, authenticator):
    """Test that external browser authenticator is case insensitive."""
    import snowflake.connector

    def mock_post_request(self, url, headers, json_body, **kwargs):
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

    monkeypatch.setattr(
        snowflake.connector.network.SnowflakeRestful, "_post_request", mock_post_request
    )

    # Mock the webbrowser authentication to avoid opening actual browser
    def mock_webbrowser_auth_prepare(
        self, conn, authenticator, service_name, account, user, password
    ):
        # Just set the token directly to simulate successful browser auth
        self._token = "MOCK_TOKEN"

    monkeypatch.setattr(AuthByWebBrowser, "prepare", mock_webbrowser_auth_prepare)

    # Create connection with external browser authenticator
    conn = snowflake.connector.connect(
        user="testuser",
        account="testaccount",
        authenticator=authenticator,
    )

    # Verify that the auth_class is an instance of AuthByWebBrowser
    assert isinstance(conn.auth_class, AuthByWebBrowser)

    conn.close()


def test_auth_prepare_body_does_not_overwrite_client_environment_fields():
    auth_class = AuthByWebBrowser(application=APPLICATION)
    req_body_before = create_mock_auth_body()
    req_body_after = apply_auth_class_update_body(auth_class, req_body_before)

    assert all(
        [
            req_body_before["data"]["CLIENT_ENVIRONMENT"][k]
            == req_body_after["data"]["CLIENT_ENVIRONMENT"][k]
            for k in req_body_before["data"]["CLIENT_ENVIRONMENT"]
        ]
    )


def test_auth_webbrowser_fails_when_browser_login_is_never_completed():
    """A browser login that is never completed must fail instead of hanging.

    ``external_browser_timeout`` is the total budget for waiting on the browser
    callback; before this was wired up an unfinished login blocked forever.
    """
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, CLIENT_PORT]
    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = successful_web_callback("MOCK_TOKEN")
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket_pkg = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=MagicMock(),
        socket_pkg=mock_socket_pkg,
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
        external_browser_timeout=1,
    )

    # select.select never reports the socket as readable: the browser callback
    # never arrives. Without a deadline this loops (and blocks) forever.
    with mock.patch("select.select", return_value=([], [], [])), mock.patch.object(
        auth, "_handle_failure"
    ) as handle_failure:
        auth._receive_saml_token(MagicMock(), mock_socket_instance)

    assert handle_failure.call_count == 1, (
        "expected the timeout to be reported once, "
        f"got {handle_failure.call_count} call(s)"
    )
    assert (
        handle_failure.call_args.kwargs["ret"]["code"] == ER_OAUTH_SERVER_TIMEOUT
    ), "expected the same errno the OAuth flow uses for a callback timeout"


def test_auth_webbrowser_without_timeout_keeps_the_wait_unbounded():
    """Without external_browser_timeout the wait stays unbounded, as before."""
    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=MagicMock(),
        socket_pkg=Mock(return_value=MagicMock()),
        protocol="https",
        host=HOST,
        port=SNOWFLAKE_PORT,
    )

    with mock.patch("select.select", return_value=([], [], [])) as select_mock, mock.patch.object(
        auth, "_handle_failure"
    ):
        auth._receive_saml_token(MagicMock(), MagicMock())

    assert (
        select_mock.call_args[0][3] is None
    ), "select should keep blocking when no timeout is configured"
