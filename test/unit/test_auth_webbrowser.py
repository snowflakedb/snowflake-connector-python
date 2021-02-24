#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from mock import MagicMock, Mock, PropertyMock

from snowflake.connector.auth_webbrowser import AuthByWebBrowser
from snowflake.connector.constants import OCSPMode
from snowflake.connector.description import CLIENT_NAME, CLIENT_VERSION
from snowflake.connector.network import EXTERNAL_BROWSER_AUTHENTICATOR, SnowflakeRestful

AUTHENTICATOR = "https://testsso.snowflake.net/"
APPLICATION = "testapplication"
ACCOUNT = "testaccount"
USER = "testuser"
PASSWORD = "testpassword"
SERVICE_NAME = ""
REF_PROOF_KEY = "MOCK_PROOF_KEY"
REF_SSO_URL = "https://testsso.snowflake.net/sso"


def mock_webserver(target_instance, application, port):
    _ = application
    _ = port
    target_instance._webserver_status = True


def test_auth_webbrowser_get():
    """Authentication by WebBrowser positive test case."""
    ref_token = "MOCK_TOKEN"

    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, 12345]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        "\r\n".join(
            [
                "GET /?token={}&confirm=true HTTP/1.1".format(ref_token),
                "User-Agent: snowflake-agent",
            ]
        )
    ).encode("utf-8")
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        rest, APPLICATION, webbrowser_pkg=mock_webbrowser, socket_pkg=mock_socket
    )
    auth.authenticate(AUTHENTICATOR, SERVICE_NAME, ACCOUNT, USER, PASSWORD)
    assert not rest._connection.errorhandler.called  # no error
    assert auth.assertion_content == ref_token
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["TOKEN"] == ref_token
    assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
    assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR


def test_auth_webbrowser_post():
    """Authentication by WebBrowser positive test case with POST."""
    ref_token = "MOCK_TOKEN"

    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, 12345]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        "\r\n".join(
            [
                "POST / HTTP/1.1",
                "User-Agent: snowflake-agent",
                "Host: localhost:12345",
                "",
                "token={}&confirm=true".format(ref_token),
            ]
        )
    ).encode("utf-8")
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        rest, APPLICATION, webbrowser_pkg=mock_webbrowser, socket_pkg=mock_socket
    )
    auth.authenticate(AUTHENTICATOR, SERVICE_NAME, ACCOUNT, USER, PASSWORD)
    assert not rest._connection.errorhandler.called  # no error
    assert auth.assertion_content == ref_token
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["TOKEN"] == ref_token
    assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
    assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR


def test_auth_webbrowser_fail_webbrowser():
    """Authentication by WebBrowser with failed to start web browser case."""
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = False

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, 12345]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        "\r\n".join(["GET /?token=MOCK_TOKEN HTTP/1.1", "User-Agent: snowflake-agent"])
    ).encode("utf-8")
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        rest, APPLICATION, webbrowser_pkg=mock_webbrowser, socket_pkg=mock_socket
    )
    auth.authenticate(AUTHENTICATOR, SERVICE_NAME, ACCOUNT, USER, PASSWORD)
    assert rest._connection.errorhandler.called  # an error
    assert auth.assertion_content is None


def test_auth_webbrowser_fail_webserver():
    """Authentication by WebBrowser with failed to start web browser case."""
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, 12345]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        "\r\n".join(["GARBAGE", "User-Agent: snowflake-agent"])
    ).encode("utf-8")
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    # case 1: invalid HTTP request
    auth = AuthByWebBrowser(
        rest, APPLICATION, webbrowser_pkg=mock_webbrowser, socket_pkg=mock_socket
    )
    auth.authenticate(AUTHENTICATOR, SERVICE_NAME, ACCOUNT, USER, PASSWORD)
    assert rest._connection.errorhandler.called  # an error
    assert auth.assertion_content is None


def _init_rest(ref_sso_url, ref_proof_key, success=True, message=None):
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

    connection = MagicMock()
    connection._login_timeout = 120
    connection._network_timeout = None
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
    rest._post_request = post_request
    return rest
