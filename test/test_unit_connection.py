#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import pytest
from mock import patch

import snowflake.connector


@patch(
    'snowflake.connector.network.SnowflakeRestful._post_request'
)
def test_connect_with_service_name(mockSnowflakeRestfulPostRequest):
    def mock_post_request(url, headers, json_body, **kwargs):
        global mock_cnt
        ret = None
        if mock_cnt == 0:
            # return from /v1/login-request
            ret = {
                'success': True,
                'message': None,
                'data': {
                    'token': 'TOKEN',
                    'masterToken': 'MASTER_TOKEN',
                    'idToken': None,
                    'parameters': [
                        {'name': 'SERVICE_NAME', 'value': "FAKE_SERVICE_NAME"}
                    ],
                }}
        return ret

    # POST requests mock
    mockSnowflakeRestfulPostRequest.side_effect = mock_post_request

    global mock_cnt
    mock_cnt = 0

    account = 'testaccount'
    user = 'testuser'

    # connection
    con = snowflake.connector.connect(
        account=account,
        user=user,
        password='testpassword',
        database='TESTDB',
        warehouse='TESTWH',
    )
    assert con.service_name == 'FAKE_SERVICE_NAME'


@pytest.mark.skip(reason="Mock doesn't work as expected.")
@patch(
    'snowflake.connector.network.SnowflakeRestful._post_request'
)
def test_connection_ignore_exception(mockSnowflakeRestfulPostRequest):
    def mock_post_request(url, headers, json_body, **kwargs):
        global mock_cnt
        ret = None
        if mock_cnt == 0:
            # return from /v1/login-request
            ret = {
                'success': True,
                'message': None,
                'data': {
                    'token': 'TOKEN',
                    'masterToken': 'MASTER_TOKEN',
                    'idToken': None,
                    'parameters': [
                        {'name': 'SERVICE_NAME', 'value': "FAKE_SERVICE_NAME"}
                    ],
                }}
        elif mock_cnt == 1:
            ret = {
                'success': False,
                'message': "Session gone",
                'data': None,
                'code': 390111
            }
        mock_cnt += 1
        return ret

    # POST requests mock
    mockSnowflakeRestfulPostRequest.side_effect = mock_post_request

    global mock_cnt
    mock_cnt = 0

    account = 'testaccount'
    user = 'testuser'

    # connection
    con = snowflake.connector.connect(
        account=account,
        user=user,
        password='testpassword',
        database='TESTDB',
        warehouse='TESTWH',
    )
    # Test to see if closing connection works or raises an exception. If an exception is raised, test will fail.
    con.close()
