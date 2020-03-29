#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import pytest
import os
import snowflake.connector
from mock import patch
from snowflake.connector.auth import delete_temporary_credential
from snowflake.connector.compat import IS_MACOS


@pytest.mark.skipif(
    IS_MACOS,
    reason="Due to some reason, we need to mock keyring function on Mac. The mock will be done later."
)
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
            # return from USE WAREHOUSE TESTWH_NEW
            ret = {
                u'success': True,
                u'message': None,
                u'data': {
                    u'finalDatabase': 'TESTDB',
                    u'finalWarehouse': 'TESTWH_NEW',
                }}
        elif mock_cnt == 3:
            # return from USE DATABASE TESTDB_NEW
            ret = {
                u'success': True,
                u'message': None,
                u'data': {
                    u'finalDatabase': 'TESTDB_NEW',
                    u'finalWarehouse': 'TESTWH_NEW',
                }}
        elif mock_cnt == 4:
            # return from SELECT 1
            ret = {
                u'success': True,
                u'message': None,
                u'data': {
                    u'finalDatabase': 'TESTDB_NEW',
                    u'finalWarehouse': 'TESTWH_NEW',
                }}
        mock_cnt += 1
        return ret

    global mock_cnt
    mock_cnt = 0

    # pre-authentication doesn't matter
    mockAuthByBrowserAuthenticate.return_value = None

    # POST requests mock
    mockSnowflakeRestfulPostRequest.side_effect = mock_post_request

    mock_cnt = 0

    account = 'testaccount'
    user = 'testuser'
    authenticator = 'externalbrowser'
    host = 'testaccount.snowflakecomputing.com'

    delete_temporary_credential(
        host=host, user=user, store_temporary_credential=True)

    # first connection
    con = snowflake.connector.connect(
        account=account,
        user=user,
        host=host,
        authenticator=authenticator,
        database='TESTDB',
        warehouse='TESTWH',
        enable_sso_temporary_credential='True',
    )
    assert con._rest.token == u'TOKEN'
    assert con._rest.master_token == u'MASTER_TOKEN'
    assert con._rest.id_token == u'ID_TOKEN'

    # second connection that uses the id token to get the session token
    con = snowflake.connector.connect(
        account=account,
        user=user,
        host=host,
        authenticator=authenticator,
        database='TESTDB_NEW',  # override the database
        warehouse='TESTWH_NEW',  # override the warehouse
        enable_sso_temporary_credential='True',
    )

    assert con._rest.token == u'NEW_TOKEN'
    assert con._rest.master_token is None
    assert con._rest.id_token == 'ID_TOKEN'
    assert con.database == 'TESTDB_NEW'
    assert con.warehouse == 'TESTWH_NEW'
