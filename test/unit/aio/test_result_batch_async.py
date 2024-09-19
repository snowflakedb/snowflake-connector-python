#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from collections import namedtuple
from http import HTTPStatus
from test.helpers import create_async_mock_response
from unittest import mock

import pytest

from snowflake.connector import DatabaseError, InterfaceError
from snowflake.connector.compat import (
    BAD_GATEWAY,
    BAD_REQUEST,
    FORBIDDEN,
    GATEWAY_TIMEOUT,
    INTERNAL_SERVER_ERROR,
    METHOD_NOT_ALLOWED,
    OK,
    REQUEST_TIMEOUT,
    SERVICE_UNAVAILABLE,
    UNAUTHORIZED,
)
from snowflake.connector.errorcode import (
    ER_FAILED_TO_CONNECT_TO_DB,
    ER_FAILED_TO_REQUEST,
)
from snowflake.connector.errors import (
    BadGatewayError,
    BadRequest,
    ForbiddenError,
    GatewayTimeoutError,
    InternalServerError,
    MethodNotAllowed,
    OtherHTTPRetryableError,
    ServiceUnavailableError,
)

try:
    from snowflake.connector.aio._result_batch import (
        MAX_DOWNLOAD_RETRY,
        JSONResultBatch,
    )
    from snowflake.connector.compat import TOO_MANY_REQUESTS
    from snowflake.connector.errors import TooManyRequests

    REQUEST_MODULE_PATH = "aiohttp.ClientSession"
except ImportError:
    MAX_DOWNLOAD_RETRY = None
    JSONResultBatch = None
    REQUEST_MODULE_PATH = "aiohttp.ClientSession"
    TooManyRequests = None
    TOO_MANY_REQUESTS = None
from snowflake.connector.sqlstate import (
    SQLSTATE_CONNECTION_REJECTED,
    SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
)

MockRemoteChunkInfo = namedtuple("MockRemoteChunkInfo", "url")
chunk_info = MockRemoteChunkInfo("http://www.chunk-url.com")
result_batch = (
    JSONResultBatch(100, None, chunk_info, [], [], True) if JSONResultBatch else None
)


pytestmark = pytest.mark.asyncio


@mock.patch(REQUEST_MODULE_PATH + ".get")
async def test_ok_response_download(mock_get):
    mock_get.side_effect = create_async_mock_response(200)

    content, encoding = await result_batch._download()

    # successful on first try
    assert mock_get.call_count == 1 and content == "success"


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "errcode,error_class",
    [
        (BAD_REQUEST, BadRequest),  # 400
        (FORBIDDEN, ForbiddenError),  # 403
        (METHOD_NOT_ALLOWED, MethodNotAllowed),  # 405
        (REQUEST_TIMEOUT, OtherHTTPRetryableError),  # 408
        (TOO_MANY_REQUESTS, TooManyRequests),  # 429
        (INTERNAL_SERVER_ERROR, InternalServerError),  # 500
        (BAD_GATEWAY, BadGatewayError),  # 502
        (SERVICE_UNAVAILABLE, ServiceUnavailableError),  # 503
        (GATEWAY_TIMEOUT, GatewayTimeoutError),  # 504
        (555, OtherHTTPRetryableError),  # random 5xx error
    ],
)
async def test_retryable_response_download(errcode, error_class):
    """This test checks that responses which are deemed 'retryable' are handled correctly."""
    # retryable exceptions
    with mock.patch(
        REQUEST_MODULE_PATH + ".get", side_effect=create_async_mock_response(errcode)
    ) as mock_get:
        # mock_get.return_value = create_async_mock_response(errcode)

        with mock.patch("asyncio.sleep", return_value=None):
            with pytest.raises(error_class) as ex:
                _ = await result_batch._download()
            err_msg = ex.value.msg
            if isinstance(errcode, HTTPStatus):
                assert str(errcode.value) in err_msg
            else:
                assert str(errcode) in err_msg
        assert mock_get.call_count == MAX_DOWNLOAD_RETRY


async def test_unauthorized_response_download():
    """This tests that the Unauthorized response (401 status code) is handled correctly."""
    with mock.patch(
        REQUEST_MODULE_PATH + ".get",
        side_effect=create_async_mock_response(UNAUTHORIZED),
    ) as mock_get:
        with mock.patch("asyncio.sleep", return_value=None):
            with pytest.raises(DatabaseError) as ex:
                _ = await result_batch._download()
            error = ex.value
            assert error.errno == ER_FAILED_TO_CONNECT_TO_DB
            assert error.sqlstate == SQLSTATE_CONNECTION_REJECTED
            assert "401" in error.msg
        assert mock_get.call_count == MAX_DOWNLOAD_RETRY


@pytest.mark.parametrize("status_code", [201, 302])
async def test_non_200_response_download(status_code):
    """This test checks that "success" codes which are not 200 still retry."""
    with mock.patch(
        REQUEST_MODULE_PATH + ".get",
        side_effect=create_async_mock_response(status_code),
    ) as mock_get:
        with mock.patch("asyncio.sleep", return_value=None):
            with pytest.raises(InterfaceError) as ex:
                _ = await result_batch._download()
            error = ex.value
            assert error.errno == ER_FAILED_TO_REQUEST
            assert error.sqlstate == SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
        assert mock_get.call_count == MAX_DOWNLOAD_RETRY


async def test_retries_until_success():
    with mock.patch(REQUEST_MODULE_PATH + ".get") as mock_get:
        error_codes = [BAD_REQUEST, UNAUTHORIZED, 201]
        # There is an OK added to the list of responses so that there is a success
        # and the retry loop ends.
        mock_responses = [
            create_async_mock_response(code)("") for code in error_codes + [OK]
        ]
        mock_get.side_effect = mock_responses

        with mock.patch("asyncio.sleep", return_value=None):
            res, _ = await result_batch._download()
            assert res == "success"
        # call `get` once for each error and one last time when it succeeds
        assert mock_get.call_count == len(error_codes) + 1
