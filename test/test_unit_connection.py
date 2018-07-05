#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import os

import snowflake.connector
from snowflake.connector.auth import (
    delete_temporary_credential_file,
)
from snowflake.connector.compat import PY2

if PY2:
    from mock import patch
else:
    from unittest.mock import patch


@patch(
    'snowflake.connector.auth_webbrowser.AuthByWebBrowser.authenticate')
@patch(
    'snowflake.connector.network.SnowflakeRestful._post_request'
)
def test_connect_externalbrowser(
        mockSnowflakeRestfulPostRequest,
        mockAuthByBrowserAuthenticate):
    """
    Connect with authentictor=externalbrowser mock.
    """

    os.environ['SF_TEMPORARY_CREDENTIAL_CACHE_DIR'] = os.getenv(
        "WORKSPACE", os.path.expanduser("~"))

    def mock_post_request(url, headers, json_body, **kwargs):
        global mock_cnt
        ret = None
        if mock_cnt == 0:
            # return from /v1/login-request
            ret = {
                u'success': True,
                u'message': None,
                u'data': {
                    u'token': u'TOKEN',
                    u'masterToken': u'MASTER_TOKEN',
                    u'idToken': u'ID_TOKEN',
                    u'idTokenPassword': u'ID_TOKEN_PASSWORD',
                }}
        elif mock_cnt == 1:
            # return from /token-request
            ret = {
                u'success': True,
                u'message': None,
                u'data': {
                    u'sessionToken': u'NEW_TOKEN',
                }}
        elif mock_cnt == 2:
            # return from USE DATABASE testdb
            ret = {
                u'success': True,
                u'message': None,
                u'data': {
                }}
        elif mock_cnt == 3:
            # return from SELECT 1
            ret = {
                u'success': True,
                u'message': None,
                u'data': {
                }}
        mock_cnt += 1
        return ret

    mock_cnt = 0

    # pre-authentication doesn't matter
    mockAuthByBrowserAuthenticate.return_value = None

    # POST requests mock
    mockSnowflakeRestfulPostRequest.side_effect = mock_post_request

    delete_temporary_credential_file()

    global mock_cnt
    mock_cnt = 0

    account = 'testaccount'
    user = 'testuser'
    authenticator = 'externalbrowser'

    # first connection
    con = snowflake.connector.connect(
        account=account,
        user=user,
        authenticator=authenticator,
    )
    assert con._rest.token == u'TOKEN'
    assert con._rest.master_token == u'MASTER_TOKEN'
    assert con._rest.id_token == u'ID_TOKEN'
    assert con._rest.id_token_password == u'ID_TOKEN_PASSWORD'

    # second connection that uses the id token to get the session token
    con = snowflake.connector.connect(
        account=account,
        user=user,
        authenticator=authenticator,
        database='testdb'  # override the database
    )

    assert con._rest.token == u'NEW_TOKEN'
    assert con._rest.master_token is None
    assert con._rest.id_token is None
    assert con._rest.id_token_password is None
