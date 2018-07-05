#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import time

from snowflake.connector.auth import Auth
from snowflake.connector.auth_default import AuthByDefault
from snowflake.connector.compat import PY2
from snowflake.connector.network import (
    CLIENT_NAME, CLIENT_VERSION, SnowflakeRestful)

if PY2:
    from mock import MagicMock, Mock, PropertyMock
else:
    from unittest.mock import MagicMock, Mock, PropertyMock


def _init_rest(application, post_requset):
    connection = MagicMock()
    connection._login_timeout = 120
    connection.errorhandler = Mock(return_value=None)
    type(connection).application = PropertyMock(return_value=application)
    type(connection)._internal_application_name = PropertyMock(
        return_value=CLIENT_NAME
    )
    type(connection)._internal_application_version = PropertyMock(
        return_value=CLIENT_VERSION
    )

    rest = SnowflakeRestful(host='testaccount.snowflakecomputing.com',
                            port=443,
                            connection=connection)
    rest._post_request = post_requset
    return rest


def _mock_auth_mfa_rest_response(url, headers, body, **kwargs):
    """
    Success case
    """
    global mock_cnt
    _ = url
    _ = headers
    _ = body
    _ = kwargs.get('dummy')
    if mock_cnt == 0:
        ret = {
            u'success': True,
            u'message': None,
            u'data': {
                u'nextAction': u'EXT_AUTHN_DUO_ALL',
                u'inFlightCtx': u'inFlightCtx',
            }
        }
    elif mock_cnt == 1:
        ret = {
            u'success': True,
            u'message': None,
            u'data': {
                u'token': u'TOKEN',
                u'masterToken': u'MASTER_TOKEN',
            }
        }

    mock_cnt += 1
    return ret


def _mock_auth_mfa_rest_response_failure(url, headers, body, **kwargs):
    """
    Failure case
    """
    global mock_cnt
    _ = url
    _ = headers
    _ = body
    _ = kwargs.get('dummy')

    if mock_cnt == 0:
        ret = {
            u'success': True,
            u'message': None,
            u'data': {
                u'nextAction': u'EXT_AUTHN_DUO_ALL',
                u'inFlightCtx': u'inFlightCtx',
            }
        }
    elif mock_cnt == 1:
        ret = {
            u'success': True,
            u'message': None,
            u'data': {
                u'nextAction': u'BAD',
                u'inFlightCtx': u'inFlightCtx',
            }
        }

    mock_cnt += 1
    return ret


def _mock_auth_mfa_rest_response_timeout(url, headers, body, **kwargs):
    """
    Timeout case
    """
    global mock_cnt
    _ = url
    _ = headers
    _ = body
    _ = kwargs.get('dummy')
    if mock_cnt == 0:
        ret = {
            u'success': True,
            u'message': None,
            u'data': {
                u'nextAction': u'EXT_AUTHN_DUO_ALL',
                u'inFlightCtx': u'inFlightCtx',
            }
        }
    elif mock_cnt == 1:
        time.sleep(10)  # should timeout while here
        ret = {}

    mock_cnt += 1
    return ret


def test_auth_mfa():
    """
    Authentication by MFA
    """
    global mock_cnt
    application = 'testapplication'
    account = 'testaccount'
    user = 'testuser'
    password = 'testpassword'

    # success test case
    mock_cnt = 0
    rest = _init_rest(application, _mock_auth_mfa_rest_response)
    auth = Auth(rest)
    auth_instance = AuthByDefault(password)
    auth.authenticate(auth_instance, account, user)
    assert not rest._connection.errorhandler.called  # not error
    assert rest.token == 'TOKEN'
    assert rest.master_token == 'MASTER_TOKEN'

    # failure test case
    mock_cnt = 0
    rest = _init_rest(application, _mock_auth_mfa_rest_response_failure)
    auth = Auth(rest)
    auth_instance = AuthByDefault(password)
    auth.authenticate(auth_instance, account, user)
    assert rest._connection.errorhandler.called  # error

    # timeout 1 second
    mock_cnt = 0
    rest = _init_rest(application, _mock_auth_mfa_rest_response_timeout)
    auth = Auth(rest)
    auth_instance = AuthByDefault(password)
    auth.authenticate(auth_instance, account, user, timeout=1)
    assert rest._connection.errorhandler.called  # error


def _mock_auth_password_change_rest_response(url, headers, body, **kwargs):
    """
    Success case
    """
    global mock_cnt
    _ = url
    _ = headers
    _ = body
    _ = kwargs.get('dummy')
    if mock_cnt == 0:
        ret = {
            u'success': True,
            u'message': None,
            u'data': {
                u'nextAction': u'PWD_CHANGE',
                u'inFlightCtx': u'inFlightCtx',
            }
        }
    elif mock_cnt == 1:
        ret = {
            u'success': True,
            u'message': None,
            u'data': {
                u'token': u'TOKEN',
                u'masterToken': u'MASTER_TOKEN',
            }
        }

    mock_cnt += 1
    return ret


def test_auth_password_change():
    """
    Password change
    """
    global mock_cnt

    def _password_callback():
        return "NEW_PASSWORD"

    application = 'testapplication'
    account = 'testaccount'
    user = 'testuser'
    password = 'testpassword'

    # success test case
    mock_cnt = 0
    rest = _init_rest(application, _mock_auth_password_change_rest_response)
    auth = Auth(rest)
    auth_instance = AuthByDefault(password)
    auth.authenticate(auth_instance, account, user,
                      password_callback=_password_callback)
    assert not rest._connection.errorhandler.called  # not error
