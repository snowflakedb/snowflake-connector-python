#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import time
from threading import Thread

from snowflake.connector import auth_webbrowser
from snowflake.connector.auth_webbrowser import AuthByWebBrowser
from snowflake.connector.compat import PY2

if PY2:
    from mock import MagicMock, Mock
else:
    from unittest.mock import MagicMock, Mock


def mock_webserver(target_instance, application, port):
    _ = application
    _ = port
    target_instance._webserver_status = True


def test_auth_webbrowser():
    """
    Authentication by WebBrowser positive test case
    """
    authenticator = 'https://testsso.snowflake.net/'
    application = 'testapplication'
    account = 'testaccount'
    user = 'testuser'
    password = 'testpassword'
    ref_proof_key = 'MOCK_PROOF_KEY'
    ref_token = "MOCK_TOKEN"

    ref_sso_url = 'https://testsso.snowflake.net/sso'
    rest = _init_rest(ref_sso_url, ref_proof_key)

    def stop_web_server():
        time.sleep(2)
        auth_webbrowser.token = ref_token
        auth_webbrowser.force_to_stop = True

    th = Thread(target=stop_web_server, args=[])
    th.daemon = True
    th.start()

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    auth = AuthByWebBrowser(
        rest, application,
        webbrowser_pkg=mock_webbrowser, webserver_handler=mock_webserver)
    auth.authenticate(authenticator, account, user, password)
    assert not rest._connection.errorhandler.called  # no error
    assert auth.assertion_content == ref_token
    body = {u'data': {}}
    auth.update_body(body)
    assert body[u'data'][u'SAML_RESPONSE'] == ref_token
    assert body[u'data'][u'PROOF_KEY'] == ref_proof_key


def test_auth_webbrowser_fail_webbrowser():
    """
    Authentication by WebBrowser. fail to start web browser
    """
    authenticator = 'https://testsso.snowflake.net/'
    application = 'testapplication'
    account = 'testaccount'
    user = 'testuser'
    password = 'testpassword'
    ref_proof_key = 'MOCK_PROOF_KEY'

    ref_sso_url = 'https://testsso.snowflake.net/sso'
    rest = _init_rest(ref_sso_url, ref_proof_key)

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = False
    auth = AuthByWebBrowser(
        rest, application,
        webbrowser_pkg=mock_webbrowser, webserver_handler=mock_webserver)
    auth.authenticate(authenticator, account, user, password)
    assert rest._connection.errorhandler.called  # an error
    assert auth.assertion_content is None


def test_auth_webbrowser_fail_webserver():
    """
    Authentication by WebBrowser. fail to start web browser
    """
    authenticator = 'https://testsso.snowflake.net/'
    application = 'testapplication'
    account = 'testaccount'
    user = 'testuser'
    password = 'testpassword'
    ref_proof_key = 'MOCK_PROOF_KEY'

    ref_sso_url = 'https://testsso.snowflake.net/sso'
    rest = _init_rest(ref_sso_url, ref_proof_key)

    # case 1: Address In Use. Retry N times and eventually fail
    def mock_webserver_address_in_use(target_instance, application, port):
        _ = application
        _ = port
        err = IOError("Address in Use")
        err.errno = 98
        target_instance._webserver_status = err

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True
    auth = AuthByWebBrowser(
        rest, application,
        webbrowser_pkg=mock_webbrowser,
        webserver_handler=mock_webserver_address_in_use)
    auth.authenticate(authenticator, account, user, password)
    assert rest._connection.errorhandler.called  # an error
    assert auth.assertion_content is None

    # Case 2: some error will raise an exception immediately
    def mock_webserver_other_error(target_instance, application, port):
        _ = application
        _ = port
        err = IOError("some kind of IO error")
        err.errno = 123
        target_instance._webserver_status = err

    auth = AuthByWebBrowser(
        rest, application,
        webbrowser_pkg=mock_webbrowser,
        webserver_handler=mock_webserver_address_in_use)
    auth.authenticate(authenticator, account, user, password)


def _init_rest(ref_sso_url, ref_proof_key, success=True, message=None):
    rest = MagicMock()
    rest._post_request.return_value = {
        'success': success,
        'message': message,
        'data': {
            'ssoUrl': ref_sso_url,
            'proofKey': ref_proof_key,
        }
    }
    rest._connection = MagicMock()
    rest._connection._login_timeout = 120
    rest._connection.errorhandler = Mock(return_value=None)
    return rest
