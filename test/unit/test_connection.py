#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
import os
import queue
import threading

import pytest
from mock import patch

import snowflake.connector
from snowflake.connector import SnowflakeConnection
from snowflake.connector.description import CLIENT_NAME
from snowflake.connector.network import APPLICATION_SNOWSQL

try:  # pragma: no cover
    from snowflake.connector.constants import QueryStatus
except ImportError:
    QueryStatus = None


@patch("snowflake.connector.network.SnowflakeRestful._post_request")
def test_connect_with_service_name(mockSnowflakeRestfulPostRequest):
    def mock_post_request(url, headers, json_body, **kwargs):
        global mock_cnt
        ret = None
        if mock_cnt == 0:
            # return from /v1/login-request
            ret = {
                "success": True,
                "message": None,
                "data": {
                    "token": "TOKEN",
                    "masterToken": "MASTER_TOKEN",
                    "idToken": None,
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "FAKE_SERVICE_NAME"}
                    ],
                },
            }
        return ret

    # POST requests mock
    mockSnowflakeRestfulPostRequest.side_effect = mock_post_request

    global mock_cnt
    mock_cnt = 0

    account = "testaccount"
    user = "testuser"

    # connection
    con = snowflake.connector.connect(
        account=account,
        user=user,
        password="testpassword",
        database="TESTDB",
        warehouse="TESTWH",
    )
    assert con.service_name == "FAKE_SERVICE_NAME"


@pytest.mark.skip(reason="Mock doesn't work as expected.")
@patch("snowflake.connector.network.SnowflakeRestful._post_request")
def test_connection_ignore_exception(mockSnowflakeRestfulPostRequest):
    def mock_post_request(url, headers, json_body, **kwargs):
        global mock_cnt
        ret = None
        if mock_cnt == 0:
            # return from /v1/login-request
            ret = {
                "success": True,
                "message": None,
                "data": {
                    "token": "TOKEN",
                    "masterToken": "MASTER_TOKEN",
                    "idToken": None,
                    "parameters": [
                        {"name": "SERVICE_NAME", "value": "FAKE_SERVICE_NAME"}
                    ],
                },
            }
        elif mock_cnt == 1:
            ret = {
                "success": False,
                "message": "Session gone",
                "data": None,
                "code": 390111,
            }
        mock_cnt += 1
        return ret

    # POST requests mock
    mockSnowflakeRestfulPostRequest.side_effect = mock_post_request

    global mock_cnt
    mock_cnt = 0

    account = "testaccount"
    user = "testuser"

    # connection
    con = snowflake.connector.connect(
        account=account,
        user=user,
        password="testpassword",
        database="TESTDB",
        warehouse="TESTWH",
    )
    # Test to see if closing connection works or raises an exception. If an exception is raised, test will fail.
    con.close()


@pytest.mark.skipolddriver
def test_is_still_running():
    """Checks that is_still_running returns expected results."""
    statuses = [
        (QueryStatus.RUNNING, True),
        (QueryStatus.ABORTING, False),
        (QueryStatus.SUCCESS, False),
        (QueryStatus.FAILED_WITH_ERROR, False),
        (QueryStatus.ABORTED, False),
        (QueryStatus.QUEUED, True),
        (QueryStatus.FAILED_WITH_INCIDENT, False),
        (QueryStatus.DISCONNECTED, False),
        (QueryStatus.RESUMING_WAREHOUSE, True),
        (QueryStatus.QUEUED_REPAIRING_WAREHOUSE, True),
        (QueryStatus.RESTARTED, False),
        (QueryStatus.BLOCKED, False),
        (QueryStatus.NO_DATA, True),
    ]
    for status, expected_result in statuses:
        assert (
            snowflake.connector.SnowflakeConnection.is_still_running(status)
            == expected_result
        )


def test_privatelink_ocsp_url_creation():
    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    SnowflakeConnection.setup_ocsp_privatelink(APPLICATION_SNOWSQL, hostname)

    ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
    assert (
        ocsp_cache_server
        == "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    )

    del os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"]

    SnowflakeConnection.setup_ocsp_privatelink(CLIENT_NAME, hostname)
    ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
    assert (
        ocsp_cache_server
        == "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    )


class ExecPrivatelinkThread(threading.Thread):
    def __init__(self, bucket, hostname, expectation, client_name):
        threading.Thread.__init__(self)
        self.bucket = bucket
        self.hostname = hostname
        self.expectation = expectation
        self.client_name = client_name

    def run(self):
        SnowflakeConnection.setup_ocsp_privatelink(self.client_name, self.hostname)
        ocsp_cache_server = os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None)
        if ocsp_cache_server is not None and ocsp_cache_server != self.expectation:
            print("Got {} Expected {}".format(ocsp_cache_server, self.expectation))
            self.bucket.put("Fail")
        else:
            self.bucket.put("Success")


def test_privatelink_ocsp_url_multithreaded():
    bucket = queue.Queue()

    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    expectation = "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    thread_obj = []
    for _ in range(15):
        thread_obj.append(
            ExecPrivatelinkThread(bucket, hostname, expectation, CLIENT_NAME)
        )

    for t in thread_obj:
        t.start()

    fail_flag = False
    for t in thread_obj:
        t.join()
        exc = bucket.get(block=False)
        if exc != "Success" and not fail_flag:
            fail_flag = True

    if fail_flag:
        raise AssertionError()

    if os.getenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", None) is not None:
        del os.environ["SF_OCSP_RESPONSE_CACHE_SERVER_URL"]


def test_privatelink_ocsp_url_multithreaded_snowsql():
    bucket = queue.Queue()

    hostname = "testaccount.us-east-1.privatelink.snowflakecomputing.com"
    expectation = "http://ocsp.testaccount.us-east-1.privatelink.snowflakecomputing.com/ocsp_response_cache.json"
    thread_obj = []
    for _ in range(15):
        thread_obj.append(
            ExecPrivatelinkThread(bucket, hostname, expectation, APPLICATION_SNOWSQL)
        )

    for t in thread_obj:
        t.start()

    fail_flag = False
    for i in range(15):
        thread_obj[i].join()
        exc = bucket.get(block=False)
        if exc != "Success" and not fail_flag:
            fail_flag = True

    if fail_flag:
        raise AssertionError()
