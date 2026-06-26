#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
from collections import namedtuple
from http import HTTPStatus
from test.helpers import create_async_mock_response
from unittest import mock

import pytest

from snowflake.connector import DatabaseError
from snowflake.connector.aio import connect as async_connect
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
    ER_HTTP_GENERAL_ERROR,
)
from snowflake.connector.errors import (
    BadGatewayError,
    BadRequest,
    ForbiddenError,
    GatewayTimeoutError,
    HttpError,
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
            with pytest.raises(HttpError) as ex:
                _ = await result_batch._download()
            error = ex.value
            assert error.errno == ER_HTTP_GENERAL_ERROR + status_code
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


@pytest.mark.skipolddriver
async def test_create_batches_does_not_log_chunk_header_values_async(caplog):
    """SNOW-3675590: async twin of test_result_batch.test_create_batches_does_not_log_chunk_header_values."""
    from snowflake.connector.aio._result_batch import create_batches_from_response

    secret_value = "U1NFLUMtY3VzdG9tZXIta2V5LXNlY3JldA=="
    data = {
        "rowtype": [],
        "total": 1,
        "rowset": [],
        "chunks": [
            {
                "url": "https://example.invalid/chunk0",
                "rowCount": 1,
                "uncompressedSize": 10,
                "compressedSize": 5,
            }
        ],
        "chunkHeaders": {
            "Accept-Encoding": "gzip",
            "x-amz-server-side-encryption-customer-key": secret_value,
        },
    }

    cursor = mock.MagicMock()
    with caplog.at_level(logging.DEBUG, logger="snowflake.connector.aio._result_batch"):
        create_batches_from_response(cursor, "json", data, schema=[])

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "added chunk header: key=Accept-Encoding" in logged
    assert "value=str len=4" in logged
    assert "gzip" not in logged
    assert secret_value not in logged


@pytest.mark.skipolddriver
async def test_create_batches_error_logs_shape_not_raw_response_async(caplog):
    """SNOW-3675590: async twin of test_result_batch.test_create_batches_error_logs_shape_not_raw_response."""
    from snowflake.connector.aio._result_batch import create_batches_from_response

    secret_qrmk = "U0VDUkVULXFybWstdmFsdWU="
    secret_url = "https://x.invalid/c?X-Amz-Signature=DEADBEEFsignature"
    data = {"rowtype": [], "total": 0, "qrmk": secret_qrmk, "extra": secret_url}

    cursor = mock.MagicMock()
    cursor._connection._session_parameters = {}
    with caplog.at_level(logging.ERROR, logger="snowflake.connector.aio._result_batch"):
        try:
            create_batches_from_response(cursor, "arrow", data, schema=[])
        except Exception:
            pass

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "Don't know how to construct ResultBatches" in logged
    assert "format='arrow'" in logged and "shape=" in logged
    assert secret_qrmk not in logged
    assert secret_url not in logged


@pytest.mark.skipolddriver
async def test_create_batches_does_not_log_qrmk_value_async(caplog):
    """SNOW-3675590 (async): the bare-qrmk path must not log the key.

    Async twin of test_result_batch.test_create_batches_does_not_log_qrmk_value.
    """
    from snowflake.connector.aio._result_batch import (
        SSE_C_ALGORITHM,
        SSE_C_KEY,
        create_batches_from_response,
    )

    secret_qrmk = "U1NFLUMtYWVzMjU2LXFybWstc2VjcmV0LWtleQ=="
    data = {
        "rowtype": [],
        "total": 1,
        "rowset": [],
        "qrmk": secret_qrmk,
        "chunks": [
            {
                "url": "https://example.invalid/chunk0",
                "rowCount": 1,
                "uncompressedSize": 10,
                "compressedSize": 5,
            }
        ],
    }

    cursor = mock.MagicMock()
    with caplog.at_level(logging.DEBUG, logger="snowflake.connector.aio._result_batch"):
        batches = create_batches_from_response(cursor, "json", data, schema=[])

    remote_batch = batches[1]
    assert remote_batch._chunk_headers[SSE_C_ALGORITHM] == "AES256"
    assert remote_batch._chunk_headers[SSE_C_KEY] == secret_qrmk

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert secret_qrmk not in logged


@pytest.mark.skipolddriver
@pytest.mark.timeout(20)
async def test_qrmk_branch_does_not_log_qrmk_value_e2e_async(
    caplog,
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
):
    """SNOW-3675590 (async): drive the connector into the ``elif qrmk`` branch.

    Async twin of test_result_batch.test_qrmk_branch_does_not_log_qrmk_value_e2e.
    """
    target_wm, _proxy_wm = wiremock_target_proxy_pair
    qrmk_secret = "QRMKsecretAES256keyDoNotLogXYZ0123456789abcd="

    password_mapping = wiremock_mapping_dir / "auth/password/successful_flow.json"
    qrmk_query_mapping = (
        wiremock_mapping_dir / "queries/select_qrmk_only_successful.json"
    )
    disconnect_mapping = (
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    telemetry_mapping = wiremock_generic_mappings_dir / "telemetry.json"
    chunk_1_mapping = wiremock_mapping_dir / "queries/chunk_1.json"

    target_wm.import_mapping_with_default_placeholders(password_mapping)
    target_wm.add_mapping(
        qrmk_query_mapping,
        placeholders={
            "{{STORAGE_WIREMOCK_HTTP_HOST_WITH_PORT}}": target_wm.http_host_with_port,
            "{{QRMK_SECRET}}": qrmk_secret,
        },
    )
    target_wm.add_mapping(disconnect_mapping)
    target_wm.add_mapping(telemetry_mapping)
    target_wm.add_mapping_with_default_placeholders(chunk_1_mapping)

    connect_kwargs = {
        "user": "testUser",
        "password": "testPassword",
        "account": "testAccount",
        "host": target_wm.wiremock_host,
        "port": target_wm.wiremock_http_port,
        "protocol": "http",
        "warehouse": "TEST_WH",
        "platform_detection_timeout_seconds": 0,
    }

    caplog.set_level(logging.DEBUG, "snowflake.connector")
    conn = await async_connect(**connect_kwargs)
    try:
        cur = conn.cursor()
        await cur.execute("SELECT * FROM large_table")
        rows = [r async for r in cur]
        assert len(cur._result_set.batches) > 1
    finally:
        await conn.close()

    assert len(rows) > 0

    assert (
        "qrmk is present" in caplog.text
    ), "qrmk branch did not run; secret-absence check below would be meaningless"
    assert qrmk_secret not in caplog.text
    assert "MaskedMessageData" not in caplog.text

    chunk_requests = [
        r
        for r in target_wm.get_requests()["requests"]
        if "/amazonaws/" in r["request"]["url"]
    ]
    assert chunk_requests, "expected at least one chunk download request"
    lower_headers = {
        k.lower(): v for k, v in chunk_requests[0]["request"]["headers"].items()
    }
    assert (
        lower_headers.get("x-amz-server-side-encryption-customer-algorithm") == "AES256"
    )
    assert qrmk_secret == lower_headers.get("x-amz-server-side-encryption-customer-key")
