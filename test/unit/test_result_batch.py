#!/usr/bin/env python
from __future__ import annotations

import gzip
import json
import logging
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from http import HTTPStatus
from test.helpers import create_mock_response
from unittest import mock

import pytest

import snowflake.connector
from snowflake.connector import DatabaseError
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
    from snowflake.connector.compat import TOO_MANY_REQUESTS
    from snowflake.connector.errors import TooManyRequests
    from snowflake.connector.result_batch import (
        MAX_DOWNLOAD_RETRY,
        JSONResultBatch,
        RemoteChunkInfo,
        _ensure_decompressed,
    )
    from snowflake.connector.vendored import requests

    SESSION_FROM_REQUEST_MODULE_PATH = (
        "snowflake.connector.vendored.requests.sessions.Session"
    )
except ImportError:
    MAX_DOWNLOAD_RETRY = None
    JSONResultBatch = None
    RemoteChunkInfo = None
    _ensure_decompressed = None
    SESSION_FROM_REQUEST_MODULE_PATH = "requests.sessions.Session"
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


@mock.patch(SESSION_FROM_REQUEST_MODULE_PATH + ".get")
def test_ok_response_download(mock_get):
    mock_get.return_value = create_mock_response(200)

    response = result_batch._download()

    # successful on first try
    assert mock_get.call_count == 1
    assert response.status_code == 200


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
def test_retryable_response_download(errcode, error_class):
    """This test checks that responses which are deemed 'retryable' are handled correctly."""
    # retryable exceptions
    with mock.patch(SESSION_FROM_REQUEST_MODULE_PATH + ".get") as mock_get:
        mock_get.return_value = create_mock_response(errcode)

        with mock.patch("time.sleep", return_value=None):
            with pytest.raises(error_class) as ex:
                _ = result_batch._download()
            err_msg = ex.value.msg
            if isinstance(errcode, HTTPStatus):
                assert str(errcode.value) in err_msg
            else:
                assert str(errcode) in err_msg
        assert mock_get.call_count == MAX_DOWNLOAD_RETRY


def test_unauthorized_response_download():
    """This tests that the Unauthorized response (401 status code) is handled correctly."""
    with mock.patch(SESSION_FROM_REQUEST_MODULE_PATH + ".get") as mock_get:
        mock_get.return_value = create_mock_response(UNAUTHORIZED)

        with mock.patch("time.sleep", return_value=None):
            with pytest.raises(DatabaseError) as ex:
                _ = result_batch._download()
            error = ex.value
            assert error.errno == ER_FAILED_TO_CONNECT_TO_DB
            assert error.sqlstate == SQLSTATE_CONNECTION_REJECTED
            assert "401" in error.msg
        assert mock_get.call_count == MAX_DOWNLOAD_RETRY


@pytest.mark.parametrize("status_code", [201, 302])
def test_non_200_response_download(status_code):
    """This test checks that "success" codes which are not 200 still retry."""
    with mock.patch(SESSION_FROM_REQUEST_MODULE_PATH + ".get") as mock_get:
        mock_get.return_value = create_mock_response(status_code)

        with mock.patch("time.sleep", return_value=None):
            with pytest.raises(HttpError) as ex:
                _ = result_batch._download()
            error = ex.value
            assert error.errno == ER_HTTP_GENERAL_ERROR + status_code
            assert error.sqlstate == SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
        assert mock_get.call_count == MAX_DOWNLOAD_RETRY


def test_retries_until_success():
    with mock.patch(SESSION_FROM_REQUEST_MODULE_PATH + ".get") as mock_get:
        error_codes = [BAD_REQUEST, UNAUTHORIZED, 201]
        # There is an OK added to the list of responses so that there is a success
        # and the retry loop ends.
        mock_responses = [create_mock_response(code) for code in error_codes + [OK]]
        mock_get.side_effect = mock_responses

        with mock.patch("time.sleep", return_value=None):
            res = result_batch._download()
            assert res.raw == "success"
        # call `get` once for each error and one last time when it succeeds
        assert mock_get.call_count == len(error_codes) + 1


# ---------------------------------------------------------------------------
# Gzip decompression fallback tests
#
# These reproduce the JSONDecodeError observed when cloud storage serves
# result-set chunks as raw gzip blobs *without* a Content-Encoding: gzip
# header.  urllib3 v2 only triggers transparent decompression when that
# header is present, so the raw \x1f\x8b bytes leak into response.text.
# ---------------------------------------------------------------------------


def _make_gzip_json_rows(*rows):
    """Encode rows as Snowflake-style comma-separated JSON and gzip-compress."""
    payload = ",\n".join(json.dumps(row) for row in rows)
    return gzip.compress(payload.encode("utf-8"))


def _make_gzip_response(compressed_body: bytes):
    """Build a fake requests.Response whose .content is raw gzip bytes.

    This simulates what happens when cloud storage returns gzip data
    without setting Content-Encoding: gzip -- the requests/urllib3 stack
    skips decompression and .content returns the raw compressed bytes.
    """
    resp = requests.Response()
    resp.status_code = 200
    resp._content = compressed_body
    resp.headers["Content-Type"] = "application/json"
    return resp


@pytest.mark.skipif(JSONResultBatch is None, reason="vendored requests unavailable")
class TestGzipDecompressionFallback:
    """Verify _ensure_decompressed fixes responses that were not decoded by urllib3."""

    def test_ensure_decompressed_unpacks_gzip_content(self):
        """_ensure_decompressed should replace raw gzip bytes with decompressed content."""
        rows = [["Alice", 30], ["Bob", 25]]
        raw_gz = _make_gzip_json_rows(*rows)
        assert raw_gz[:2] == b"\x1f\x8b", "sanity: payload is gzip"

        resp = _make_gzip_response(raw_gz)
        assert resp.content[:2] == b"\x1f\x8b", "before fix: content is raw gzip"

        _ensure_decompressed(resp)

        assert resp.content[:2] != b"\x1f\x8b", "after fix: gzip magic gone"
        recovered = json.loads("[" + resp.content.decode("utf-8") + "]")
        assert recovered == rows

    def test_ensure_decompressed_leaves_plain_json_alone(self):
        """_ensure_decompressed should be a no-op for already-decoded responses."""
        plain = b'["Alice", 30],\n["Bob", 25]'
        resp = requests.Response()
        resp.status_code = 200
        resp._content = plain
        original_id = id(resp._content)

        _ensure_decompressed(resp)

        assert resp.content is plain or resp.content == plain
        assert id(resp._content) == original_id

    def test_json_result_batch_load_with_gzip_response(self):
        """JSONResultBatch._load should succeed even when the HTTP layer didn't decompress."""
        rows = [["val1", 1], ["val2", 2], ["val3", 3]]
        raw_gz = _make_gzip_json_rows(*rows)

        resp = _make_gzip_response(raw_gz)
        _ensure_decompressed(resp)

        batch = JSONResultBatch(
            rowcount=len(rows),
            chunk_headers=None,
            remote_chunk_info=None,
            schema=[],
            column_converters=[],
            use_dict_result=False,
        )
        loaded = batch._load(resp)
        assert loaded == rows

    def test_concurrent_multichunk_download_with_gzip_responses(self):
        """Reproduce the reported issue: concurrent ThreadPoolExecutor downloads
        where each chunk response is raw gzip (no Content-Encoding header).

        Without the _ensure_decompressed fix, json.loads() in _load() would
        receive \\x1f\\x8b... garbage and raise JSONDecodeError.
        """
        num_chunks = 6
        rows_per_chunk = 50
        chunks_data = {}
        url_to_response = {}

        for chunk_idx in range(num_chunks):
            rows = [
                [f"chunk{chunk_idx}_row{r}", chunk_idx * 100 + r]
                for r in range(rows_per_chunk)
            ]
            chunk_url = f"http://fake-s3.example.com/results/chunk_{chunk_idx}"
            body = _make_gzip_json_rows(*rows)
            chunks_data[chunk_idx] = rows
            url_to_response[chunk_url] = _make_gzip_response(body)

        batches = []
        for chunk_idx in range(num_chunks):
            chunk_url = f"http://fake-s3.example.com/results/chunk_{chunk_idx}"
            body = url_to_response[chunk_url].content
            batch = JSONResultBatch(
                rowcount=rows_per_chunk,
                chunk_headers=None,
                remote_chunk_info=RemoteChunkInfo(
                    url=chunk_url, uncompressedSize=0, compressedSize=len(body)
                ),
                schema=[],
                column_converters=[],
                use_dict_result=False,
            )
            batches.append((chunk_idx, batch))

        def mock_get(url, **kwargs):
            return url_to_response[url]

        def fetch_batch(idx_and_batch):
            idx, batch = idx_and_batch
            response = batch._download()
            return idx, batch._load(response)

        all_results = {}
        with mock.patch(
            SESSION_FROM_REQUEST_MODULE_PATH + ".get", side_effect=mock_get
        ):
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = [pool.submit(fetch_batch, ib) for ib in batches]
                for future in as_completed(futures):
                    chunk_idx, loaded = future.result()
                    all_results[chunk_idx] = loaded

        assert len(all_results) == num_chunks
        for chunk_idx in range(num_chunks):
            assert all_results[chunk_idx] == chunks_data[chunk_idx], (
                f"Chunk {chunk_idx}: expected valid JSON rows but got corrupted data. "
                f"This indicates gzip decompression was not applied."
            )

    def test_concurrent_multichunk_with_session_manager_clone(self):
        """End-to-end reproduction using a cloned SessionManager, mirroring the
        real download path where result batches use a cloned manager without
        connection pooling.
        """
        from snowflake.connector.session_manager import SessionManager

        base_manager = SessionManager()
        cloned_manager = base_manager.clone(use_pooling=False)

        rows = [["hello", 42], ["world", 99]]
        raw_gz = _make_gzip_json_rows(*rows)
        chunk_url = "http://fake-s3.example.com/results/chunk_0"

        batch = JSONResultBatch(
            rowcount=len(rows),
            chunk_headers={},
            remote_chunk_info=RemoteChunkInfo(
                url=chunk_url, uncompressedSize=0, compressedSize=len(raw_gz)
            ),
            schema=[],
            column_converters=[],
            use_dict_result=False,
            session_manager=cloned_manager,
        )

        resp = _make_gzip_response(raw_gz)

        with mock.patch(
            SESSION_FROM_REQUEST_MODULE_PATH + ".request", return_value=resp
        ):
            response = batch._download()

        loaded = batch._load(response)
        assert loaded == rows


@pytest.mark.skipolddriver
def test_create_batches_does_not_log_qrmk_value(caplog):
    """SNOW-3675590: the bare-qrmk (no chunkHeaders) path must not log the key.

    Drives the real create_batches_from_response into the `elif qrmk` branch and
    asserts it ran (SSE-C key plumbed into chunk headers) while the key is not
    logged.
    """
    from snowflake.connector.result_batch import (
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
        # no chunkHeaders -> the elif qrmk branch is taken
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
    with caplog.at_level(logging.DEBUG, logger="snowflake.connector.result_batch"):
        batches = create_batches_from_response(cursor, "json", data, schema=[])

    # Prove the elif-qrmk branch actually ran: the SSE-C key is plumbed from
    # qrmk into the remote chunk's headers (so this is really testing that path).
    remote_batch = batches[1]
    assert remote_batch._chunk_headers[SSE_C_ALGORITHM] == "AES256"
    assert remote_batch._chunk_headers[SSE_C_KEY] == secret_qrmk

    # ...but the key is never written to the log.
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "qrmk is present" in logged
    assert secret_qrmk not in logged
    assert "MaskedMessageData" not in logged


@pytest.mark.skipolddriver
def test_qrmk_branch_does_not_log_qrmk_value_e2e(
    caplog,
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
):
    """SNOW-3675590: end-to-end check that the qrmk value never reaches the logs.

    Drives the real connector into the ``elif qrmk`` branch via Wiremock: the
    query response carries a bare ``qrmk`` but no ``chunkHeaders``, so
    ``create_batches_from_response`` builds the SSE-C headers from the qrmk and
    downloads the chunk. Asserts:

    * the connector logged that a qrmk is present (branch ran),
    * the literal qrmk value is absent from DEBUG logs,
    * the chunk GET carried the SSE-C headers (key was correctly plumbed through).
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
    with snowflake.connector.connect(**connect_kwargs) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM large_table")
            rows = cur.fetchall()
            assert len(cur._result_set.batches) > 1

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
