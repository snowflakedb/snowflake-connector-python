#!/usr/bin/env python
from __future__ import annotations

import gzip
import json
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from http import HTTPStatus
from test.helpers import create_mock_response
from unittest import mock

import pytest

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
