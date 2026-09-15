#!/usr/bin/env python
from __future__ import annotations

import base64
import gzip
import json
import logging
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from http import HTTPStatus
from io import BytesIO
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
    from snowflake.connector.arrow_context import ArrowConverterContext
    from snowflake.connector.compat import TOO_MANY_REQUESTS
    from snowflake.connector.errorcode import ER_INCOMPLETE_RESULT_CHUNK
    from snowflake.connector.errors import OperationalError, TooManyRequests
    from snowflake.connector.result_batch import (
        MAX_DOWNLOAD_RETRY,
        ArrowResultBatch,
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
    ArrowConverterContext = None
    ArrowResultBatch = None
    JSONResultBatch = None
    RemoteChunkInfo = None
    _ensure_decompressed = None
    SESSION_FROM_REQUEST_MODULE_PATH = "requests.sessions.Session"
    TooManyRequests = None
    TOO_MANY_REQUESTS = None
    OperationalError = None
    ER_INCOMPLETE_RESULT_CHUNK = None

try:
    import pyarrow

    from snowflake.connector import nanoarrow_arrow_iterator  # noqa: F401

    _have_arrow = True
except ImportError:
    _have_arrow = False
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


def _make_remote_json_batch(rowcount: int, rows: list[list]) -> tuple:
    """A remote JSON batch plus the decompressed response its download returns."""
    batch = JSONResultBatch(
        rowcount=rowcount,
        chunk_headers=None,
        remote_chunk_info=RemoteChunkInfo(
            url="http://fake-s3.example.com/results/chunk_0",
            uncompressedSize=0,
            compressedSize=0,
        ),
        schema=[],
        column_converters=[],
        use_dict_result=False,
    )
    response = _make_gzip_response(_make_gzip_json_rows(*rows))
    _ensure_decompressed(response)
    return batch, response


@pytest.mark.skipolddriver
@pytest.mark.skipif(JSONResultBatch is None, reason="vendored requests unavailable")
def test_short_remote_chunk_raises_instead_of_ending_iteration():
    """SNOW-4109042: a chunk holding fewer rows than promised must not look like EOF.

    Such a chunk used to simply stop producing rows, and the fetch methods treat
    a stopped iterator as a normal end of results, so callers silently received
    an incomplete result set.
    """
    rows = [["val1", 1], ["val2", 2]]
    batch, response = _make_remote_json_batch(len(rows) + 1, rows)

    with mock.patch.object(batch, "_download", return_value=response):
        with pytest.raises(OperationalError) as ex:
            list(batch.create_iter())

    assert ex.value.errno == ER_INCOMPLETE_RESULT_CHUNK
    assert "holds 2 row(s) but the server reported 3" in ex.value.msg


@pytest.mark.skipolddriver
@pytest.mark.skipif(JSONResultBatch is None, reason="vendored requests unavailable")
def test_complete_remote_chunk_iterates_without_error():
    rows = [["val1", 1], ["val2", 2]]
    batch, response = _make_remote_json_batch(len(rows), rows)

    with mock.patch.object(batch, "_download", return_value=response):
        assert len(list(batch.create_iter())) == len(rows)


CHUNKS = [
    (954, 79),
    (520, 64),
    (1716, 60),
    (288, 97),
    (98, 31),
    (36, 36),
]


def _arrow_text_column_ipc(values: list[str]) -> bytes:
    """A single-column Arrow IPC stream shaped like a Snowflake TEXT result chunk."""
    stream = BytesIO()
    field = pyarrow.field(
        "C1", pyarrow.string(), True, {"logicalType": "TEXT", "charLength": "16777216"}
    )
    writer = pyarrow.RecordBatchStreamWriter(stream, pyarrow.schema([field]))
    writer.write_batch(
        pyarrow.RecordBatch.from_arrays(
            [pyarrow.array(values, type=pyarrow.string())], ["C1"]
        )
    )
    writer.close()
    return stream.getvalue()


def _inline_arrow_batch(rowset_b64: str, first_chunk_len: int) -> ArrowResultBatch:
    """The inline first chunk, built the way ``create_batches_from_response`` builds it."""
    return ArrowResultBatch.from_data(
        rowset_b64,
        first_chunk_len,
        ArrowConverterContext(session_parameters={}),
        False,
        False,
        [],
        False,
    )


@pytest.mark.skipolddriver
@pytest.mark.skipif(ArrowResultBatch is None, reason="connector build unavailable")
@pytest.mark.parametrize("total,first_chunk_len", CHUNKS, ids=str)
def test_empty_inline_arrow_chunk_raises(total, first_chunk_len):
    """SNOW-4109042: an empty ``rowsetBase64`` promising rows must not read as EOF.

    ``create_batches_from_response`` derives the inline chunk's rowcount as
    ``total`` minus the back-end's per-chunk counts, so it is server metadata --
    and nanoarrow treats zero bytes as a clean end of stream, which is how the
    customer lost exactly ``total - first chunk rows`` rows without an error.
    """
    batch = _inline_arrow_batch(base64.b64encode(b"").decode("ascii"), first_chunk_len)

    with pytest.raises(OperationalError) as ex:
        list(batch.create_iter())

    assert ex.value.errno == ER_INCOMPLETE_RESULT_CHUNK
    assert f"holds 0 row(s) but the server reported {first_chunk_len}" in ex.value.msg


@pytest.mark.skipolddriver
@pytest.mark.skipif(not _have_arrow, reason="pyarrow or nanoarrow extension missing")
def test_short_inline_arrow_chunk_raises():
    """A partially delivered inline chunk is as silent as an empty one was."""
    rowset = base64.b64encode(_arrow_text_column_ipc(["0", "1", "2"])).decode("ascii")
    batch = _inline_arrow_batch(rowset, 5)

    with pytest.raises(OperationalError) as ex:
        list(batch.create_iter())

    assert ex.value.errno == ER_INCOMPLETE_RESULT_CHUNK


@pytest.mark.skipolddriver
@pytest.mark.skipif(not _have_arrow, reason="pyarrow or nanoarrow extension missing")
def test_complete_inline_arrow_chunk_iterates_without_error():
    rows = ["0", "1", "2", "3", "4"]
    rowset = base64.b64encode(_arrow_text_column_ipc(rows)).decode("ascii")
    batch = _inline_arrow_batch(rowset, len(rows))

    assert list(batch.create_iter()) == [(v,) for v in rows]


@pytest.mark.skipolddriver
@pytest.mark.skipif(not _have_arrow, reason="pyarrow or nanoarrow extension missing")
def test_partially_consumed_inline_arrow_chunk_does_not_raise():
    """Stopping early is normal usage; only an exhausted chunk is verified."""
    rowset = base64.b64encode(_arrow_text_column_ipc(["0", "1", "2"])).decode("ascii")
    batch = _inline_arrow_batch(rowset, 3)

    rows = []
    for row in batch.create_iter():
        rows.append(row)
        break

    assert rows == [("0",)]


def _mock_cursor_for_batches():
    cursor = mock.MagicMock()
    cursor._use_dict_result = False
    cursor._connection._numpy = False
    cursor._connection._arrow_number_to_decimal = False
    cursor._connection._json_result_force_utf8_decoding = False
    cursor._connection._session_parameters = {}
    cursor._connection.converter.to_python_method.return_value = None
    return cursor


@pytest.mark.skipolddriver
@pytest.mark.skipif(not _have_arrow, reason="pyarrow or nanoarrow extension missing")
def test_inline_arrow_chunk_without_declared_total_does_not_raise():
    """``data.get("total", 0)`` defaults to 0, which is not a promise of any rows.

    Without ``total`` the subtraction that yields the inline chunk's rowcount is
    zero (or negative once remote chunks are declared), so there is nothing to
    hold the back-end to and the rows present must be handed over as they are.
    """
    from snowflake.connector.result_batch import create_batches_from_response

    rows = ["0", "1", "2"]
    data = {
        "rowtype": [],
        "rowsetBase64": base64.b64encode(_arrow_text_column_ipc(rows)).decode("ascii"),
    }

    batches = create_batches_from_response(
        _mock_cursor_for_batches(), "arrow", data, schema=[]
    )

    assert batches[0].rowcount == 0
    assert len(list(batches[0].create_iter())) == len(rows)


@pytest.mark.skipolddriver
@pytest.mark.skipif(JSONResultBatch is None, reason="vendored requests unavailable")
def test_empty_inline_json_chunk_is_self_consistent():
    """SNOW-4109042: the JSON path has no batch-level mismatch to detect.

    ``JSONResultBatch.from_data`` takes its rowcount from ``len(rowset)``, so an
    empty inline rowset is a perfectly consistent zero-row batch no matter what
    ``total`` said. Only the result-set-level check can catch that one.
    """
    from snowflake.connector.result_batch import create_batches_from_response

    data = {
        "rowtype": [],
        "total": 954,
        "rowset": [],
        "chunks": [
            {
                "url": "https://example.invalid/chunk0",
                "rowCount": 875,
                "uncompressedSize": 10,
                "compressedSize": 5,
            }
        ],
    }

    batches = create_batches_from_response(
        _mock_cursor_for_batches(), "json", data, schema=[]
    )

    assert batches[0].rowcount == 0
    assert list(batches[0].create_iter()) == []


@pytest.mark.skipolddriver
def test_create_batches_does_not_log_chunk_header_values(caplog):
    """SNOW-3675590: chunk header *values* can be secrets (e.g. the SSE-C
    customer key), so create_batches_from_response must log only header names.

    The previous guard ``if "encryption" not in header_key`` was a fragile
    case-sensitive substring check: it suppressed names containing the lowercase
    substring "encryption" but logged the value of every other header, including
    ones whose name merely differed in case (e.g. "Accept-Encoding").
    """
    from snowflake.connector.result_batch import create_batches_from_response

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
            # header name that does not contain "encryption"
            "Accept-Encoding": "gzip",
            # the real SSE-C key
            "x-amz-server-side-encryption-customer-key": secret_value,
        },
    }

    cursor = mock.MagicMock()
    with caplog.at_level(logging.DEBUG, logger="snowflake.connector.result_batch"):
        create_batches_from_response(cursor, "json", data, schema=[])

    logged = "\n".join(record.getMessage() for record in caplog.records)
    # header NAMES are safe to log, plus non-sensitive value metadata (type/len)
    assert "added chunk header: key=Accept-Encoding" in logged
    assert "value=str len=4" in logged  # metadata for "gzip" (len 4), not the value
    # but no header VALUE is ever logged (neither the benign one nor the secret)
    assert "gzip" not in logged
    assert secret_value not in logged


def test_describe_value_hides_secrets_in_response_dict():
    """SNOW-3675590: describe_value on a response dict must expose keys/types/sizes
    only, never the values (which can include secrets like qrmk or presigned URLs)."""
    from snowflake.connector.secret_detector import SecretDetector

    secret = "U0VDUkVULXFybWstdmFsdWU="
    result = SecretDetector.describe_value(
        {
            "rowtype": [],
            "total": 5,
            "qrmk": secret,
            "chunkHeaders": {"x-amz-...": "secret-header-value"},
            "chunks": [{"url": "https://x.invalid?X-Amz-Signature=sig"}],
        }
    )
    assert "qrmk: str len=24" in result
    assert "chunks: list len=1" in result
    assert "chunkHeaders: dict{x-amz-...: str len=19}" in result
    assert "total: int" in result
    # no value (secret or otherwise) leaks into the summary
    assert secret not in result
    assert "secret-header-value" not in result
    assert "X-Amz-Signature" not in result


@pytest.mark.skipolddriver
def test_create_batches_error_logs_shape_not_raw_response(caplog):
    """SNOW-3675590: the malformed-response ERROR must log the structural shape
    rather than the response object — and it fires at ERROR level regardless of
    DEBUG."""
    from snowflake.connector.result_batch import create_batches_from_response

    secret_qrmk = "U0VDUkVULXFybWstdmFsdWU="
    secret_url = "https://x.invalid/c?X-Amz-Signature=DEADBEEFsignature"
    # arrow format with neither rowsetBase64 nor chunks -> malformed -> else branch
    data = {"rowtype": [], "total": 0, "qrmk": secret_qrmk, "extra": secret_url}

    cursor = mock.MagicMock()
    cursor._connection._session_parameters = {}
    with caplog.at_level(logging.ERROR, logger="snowflake.connector.result_batch"):
        try:
            create_batches_from_response(cursor, "arrow", data, schema=[])
        except Exception:
            # the empty-arrow fallback may raise under a mock cursor; the ERROR
            # line is emitted before it, which is what we are asserting on.
            pass

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "Don't know how to construct ResultBatches" in logged
    assert "format='arrow'" in logged and "shape=" in logged
    assert secret_qrmk not in logged
    assert secret_url not in logged


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
