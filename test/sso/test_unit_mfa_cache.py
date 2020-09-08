#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import os

from mock import Mock, patch

import json
import snowflake.connector
from snowflake.connector.auth import delete_temporary_mfa_token
from snowflake.connector.compat import IS_MACOS


@patch('snowflake.connector.network.SnowflakeRestful._post_request')
def test_mfa_cache(
        mockSnowflakeRestfulPostRequest):
    """Connects with (username, pwd, mfa) mock."""
    os.environ['SF_TEMPORARY_CREDENTIAL_CACHE_DIR'] = os.getenv(
        "WORKSPACE", os.path.expanduser("~"))

    def mock_post_request(url, headers, json_body, **kwargs):
        global mock_post_req_cnt
        ret = None
        body = json.loads(json_body)
        if mock_post_req_cnt == 0:
            assert body['data']['SESSION_PARAMETERS'].get('CLIENT_REQUEST_MFA_TOKEN') is True
            ret = {
                'success': True,
                'message': None,
                'data': {
                    'token': 'TOKEN',
                    'masterToken': 'MASTER_TOKEN',
                    'mfaToken': 'MFA_TOKEN',
                }}
        elif mock_post_req_cnt == 1:
            assert body['data']['TOKEN'] == 'MFA_TOKEN'
            ret = {
                'success': True,
                'message': None,
                'data': {
                    'token': 'NEW_TOKEN',
                    'masterToken': 'NEW_MASTER_TOKEN',
                }}
        elif mock_post_req_cnt == 2:
            # return from USE WAREHOUSE TESTWH_NEW
            ret = {
                'success': True,
                'message': None,
                'data': {
                    'finalDatabase': 'TESTDB',
                    'finalWarehouse': 'TESTWH_NEW',
                }}
        elif mock_post_req_cnt == 3:
            # return from USE DATABASE TESTDB_NEW
            ret = {
                'success': True,
                'message': None,
                'data': {
                    'finalDatabase': 'TESTDB_NEW',
                    'finalWarehouse': 'TESTWH_NEW',
                }}
        elif mock_post_req_cnt == 4:
            # return from SELECT 1
            ret = {
                'success': True,
                'message': None,
                'data': {
                    'finalDatabase': 'TESTDB_NEW',
                    'finalWarehouse': 'TESTWH_NEW',
                }}
        mock_post_req_cnt += 1
        return ret

    def mock_get_password(service, user):
        global mock_get_pwd_cnt
        ret = None
        if mock_get_pwd_cnt == 1:
            # second connection
            ret = 'MFA_TOKEN'
        mock_get_pwd_cnt += 1
        return ret

    global mock_post_req_cnt, mock_get_pwd_cnt
    mock_post_req_cnt, mock_get_pwd_cnt = 0, 0

    # POST requests mock
    mockSnowflakeRestfulPostRequest.side_effect = mock_post_request

    def test_body():
        account = 'testaccount'
        user = 'testuser'
        pwd = 'testpwd'
        authenticator = 'username_password_mfa'
        host = 'testaccount.snowflakecomputing.com'

        delete_temporary_mfa_token(host=host, user=user)

        # first connection
        con = snowflake.connector.connect(
            account=account,
            user=user,
            password=pwd,
            host=host,
            authenticator=authenticator,
            database='TESTDB',
            warehouse='TESTWH',
            client_request_mfa_token=True,
        )
        assert con._rest.mfa_token == 'MFA_TOKEN'

        # second connection that uses the id token to get the session token
        con = snowflake.connector.connect(
            account=account,
            user=user,
            password=pwd,
            host=host,
            authenticator=authenticator,
            database='TESTDB_NEW',  # override the database
            warehouse='TESTWH_NEW',  # override the warehouse
            client_request_mfa_token=True,
        )

        """
        assert con._rest.token == 'NEW_TOKEN'
        assert con._rest.master_token == 'NEW_MASTER_TOKEN'
        assert con._rest.id_token is None
        assert con.database == 'TESTDB_NEW'
        assert con.warehouse == 'TESTWH_NEW'
        """

    if IS_MACOS:
        with patch('keyring.delete_password', Mock(return_value=None)
                   ), patch('keyring.set_password', Mock(return_value=None)
                            ), patch('keyring.get_password', Mock(side_effect=mock_get_password)):
            test_body()
    else:
        test_body()
