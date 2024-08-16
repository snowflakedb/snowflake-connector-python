#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import unittest.mock
from logging import getLogger

import pytest

import snowflake.connector
from snowflake.connector import errorcode, errors
from snowflake.connector.network import (
    QUERY_IN_PROGRESS_ASYNC_CODE,
    QUERY_IN_PROGRESS_CODE,
    SnowflakeRestful,
)

logger = getLogger(__name__)


def test_no_auth(db_parameters):
    """SNOW-13588: No auth Rest API test."""
    rest = SnowflakeRestful(host=db_parameters["host"], port=db_parameters["port"])
    try:
        # no auth
        # show warehouse
        rest.request(
            url="/queries",
            body={
                "sequenceId": 10000,
                "sqlText": "show warehouses",
                "parameters": {
                    "ui_mode": True,
                },
            },
            method="post",
            client="rest",
        )
        raise Exception("Must fail with auth error")
    except errors.Error as e:
        assert e.errno == errorcode.ER_CONNECTION_IS_CLOSED
    finally:
        rest.close()


@pytest.mark.parametrize(
    "query_return_code", [QUERY_IN_PROGRESS_CODE, QUERY_IN_PROGRESS_ASYNC_CODE]
)
def test_none_object_when_querying_result(db_parameters, caplog, query_return_code):
    # this test simulate the case where the response from the server is None
    # the following events happen in sequence:
    # 1. we send a simple query to the server which is a post request
    # 2. we record the query result in a global variable
    # 3. we mock return a query in progress code and an url to fetch the query result
    # 4. we return None for the fetching query result request for the first time
    # 5. for the second time, we return the code for the query result
    # 6. in the end, we assert the result, and retry has taken place when result is None by checking logging

    original_request_exec = SnowflakeRestful._request_exec
    expected_ret = None
    get_executed_time = 0

    def side_effect_request_exec(self, *args, **kwargs):
        nonlocal expected_ret, get_executed_time
        # 1. we send a simple query to the server which is a post request
        if "queries/v1/query-request" in kwargs["full_url"]:
            ret = original_request_exec(self, *args, **kwargs)
            expected_ret = ret  # 2. we record the query result in a global variable
            # 3. we mock return a query in progress code and an url to fetch the query result
            return {
                "code": query_return_code,
                "data": {"getResultUrl": "/queries/123/result"},
            }

        if "/queries/123/result" in kwargs["full_url"]:
            if get_executed_time == 0:
                # 4. we return None for the 1st time fetching query result request, this should trigger retry
                get_executed_time += 1
                return None
            else:
                # 5. for the second time, we return the code for the query result, this indicates retry success
                return expected_ret

    with snowflake.connector.connect(
        **db_parameters
    ) as conn, conn.cursor() as cursor, caplog.at_level(logging.INFO):
        with unittest.mock.patch.object(
            SnowflakeRestful, "_request_exec", new=side_effect_request_exec
        ):
            # 6. in the end, we assert the result, and retry has taken place when result is None by checking logging
            assert cursor.execute("select 1").fetchone() == (1,)
            assert (
                "fetch query status failed and http request returned None, this is usually caused by transient network failures, retrying"
                in caplog.text
            )
