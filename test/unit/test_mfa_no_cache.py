#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import json

import pytest
from mock import patch

import snowflake.connector

try:
    from snowflake.connector.compat import IS_LINUX  # NOQA
    from snowflake.connector.options import installed_keyring
except ImportError:
	import platform
    IS_LINUX = (platform.system() == 'Linux')
    installed_keyring = False

MFA_TOKEN = "MFATOKEN"


@pytest.mark.skipif(IS_LINUX or not installed_keyring,
                    reason="Skip linux platform or (IS_LINUX or installed_keyring) is not available.")
@patch('snowflake.connector.network.SnowflakeRestful._post_request')
def test_mfa_no_local_secure_storage(mockSnowflakeRestfulPostRequest):
    """Test whether username_password_mfa authenticator can work when no local secure storage is available."""
    global mock_post_req_cnt
    mock_post_req_cnt = 0

    # This test requires Mac/Win and no keyring lib is installed
    assert not installed_keyring

    def mock_post_request(url, headers, json_body, **kwargs):
        global mock_post_req_cnt
        ret = None
        body = json.loads(json_body)
        if mock_post_req_cnt == 0:
            # issue MFA token for a succeeded login
            assert body['data']['SESSION_PARAMETERS'].get('CLIENT_REQUEST_MFA_TOKEN') is True
            ret = {
                'success': True,
                'message': None,
                'data': {
                    'token': 'TOKEN',
                    'masterToken': 'MASTER_TOKEN',
                    'mfaToken': 'MFA_TOKEN',
                }}
        elif mock_post_req_cnt == 2:
            # No local secure storage available, so no mfa cache token should be provided
            assert body['data']['SESSION_PARAMETERS'].get('CLIENT_REQUEST_MFA_TOKEN') is True
            assert 'TOKEN' not in body['data']
            ret = {
                'success': True,
                'message': None,
                'data': {
                    'token': 'NEW_TOKEN',
                    'masterToken': 'NEW_MASTER_TOKEN',
                }}
        elif mock_post_req_cnt in [1, 3]:
            # connection.close()
            ret = {'success': True}
        mock_post_req_cnt += 1
        return ret

    # POST requests mock
    mockSnowflakeRestfulPostRequest.side_effect = mock_post_request

    def test_body():
        account = 'testaccount'
        user = 'testuser'
        pwd = 'testpwd'
        authenticator = 'username_password_mfa'
        host = 'testaccount.snowflakecomputing.com'

        # first connection, no mfa token cache
        con = snowflake.connector.connect(
            account=account,
            user=user,
            password=pwd,
            host=host,
            authenticator=authenticator,
            client_request_mfa_token=True,
        )
        assert con._rest.token == 'TOKEN'
        assert con._rest.master_token == 'MASTER_TOKEN'
        assert con._rest.mfa_token == 'MFA_TOKEN'
        con.close()

        # second connection, no mfa token should be issued as well since no available local secure storage
        con = snowflake.connector.connect(
            account=account,
            user=user,
            password=pwd,
            host=host,
            authenticator=authenticator,
            client_request_mfa_token=True,
        )
        assert con._rest.token == 'NEW_TOKEN'
        assert con._rest.master_token == 'NEW_MASTER_TOKEN'
        assert not con._rest.mfa_token
        con.close()

    test_body()
