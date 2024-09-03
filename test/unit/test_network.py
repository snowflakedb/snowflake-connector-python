#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import io
import unittest.mock
from test.unit.mock_utils import mock_connection

import pytest

try:
    from snowflake.connector import Error
    from snowflake.connector.network import SnowflakeRestful
    from snowflake.connector.vendored.requests import HTTPError, Response
except ImportError:
    # skipping old driver test
    pass

pytestmark = pytest.mark.skipolddriver


def test_fetch():
    connection = mock_connection()
    connection.errorhandler = Error.default_errorhandler
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com",
        port=443,
        connection=connection,
    )

    default_parameters = {
        "method": "POST",
        "full_url": "https://testaccount.snowflakecomputing.com/",
        "headers": {},
        "data": '{"code": 12345}',
        "token": None,
    }

    failed_response = Response()
    failed_response.status_code = 409
    failed_response.raw = io.StringIO("error")
    failed_response.url = default_parameters["full_url"]
    failed_response.reason = "conflict"
    with unittest.mock.patch(
        "snowflake.connector.vendored.requests.sessions.Session.request",
        return_value=failed_response,
    ):
        with pytest.raises(HTTPError) as exc:
            rest.fetch(**default_parameters, raise_raw_http_failure=True)
        assert exc.value.response.status_code == failed_response.status_code
        assert exc.value.response.reason == failed_response.reason
