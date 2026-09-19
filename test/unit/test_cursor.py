from __future__ import annotations

import base64
import gzip
import json
import time
from io import BytesIO
from unittest import TestCase
from unittest.mock import MagicMock, patch

import pytest

import snowflake.connector
from snowflake.connector.connection import SnowflakeConnection
from snowflake.connector.cursor import ResultState, SnowflakeCursor
from snowflake.connector.errors import OperationalError, ServiceUnavailableError

try:
    from snowflake.connector.errorcode import ER_INCOMPLETE_RESULT_CHUNK
except ImportError:
    ER_INCOMPLETE_RESULT_CHUNK = None

try:
    from snowflake.connector.arrow_context import ArrowConverterContext
    from snowflake.connector.result_batch import (
        ArrowResultBatch,
        JSONResultBatch,
        RemoteChunkInfo,
    )
    from snowflake.connector.result_set import ResultSet
    from snowflake.connector.vendored import requests

    _have_result_set = True
except ImportError:
    _have_result_set = False

try:
    from snowflake.connector.constants import FileTransferType
except ImportError:
    from enum import Enum

    class FileTransferType(Enum):
        GET = "get"
        PUT = "put"


try:
    import pyarrow

    from snowflake.connector import nanoarrow_arrow_iterator  # noqa: F401

    _have_arrow = True
except ImportError:
    pyarrow = None
    _have_arrow = False

_RESULT_FORMATS = [
    "json",
    pytest.param(
        "arrow",
        marks=pytest.mark.skipif(
            not _have_arrow, reason="pyarrow or nanoarrow extension missing"
        ),
    ),
]


class FakeConnection(SnowflakeConnection):
    def __init__(self):
        self._log_max_query_length = 0
        self._reuse_results = None
        self._reraise_error_in_file_transfer_work_function = False
        self._enable_stage_s3_privatelink_for_us_east_1 = False
        self._iobound_tpe_limit = None
        self._unsafe_file_write = False
        self._check_arrow_conversion_error_on_every_column = True


@pytest.mark.parametrize(
    "sql,_type",
    (
        ("", None),
        ("select 1;", None),
        ("PUT file:///tmp/data/mydata.csv @my_int_stage;", FileTransferType.PUT),
        ("GET @%mytable file:///tmp/data/;", FileTransferType.GET),
        ("/**/PUT file:///tmp/data/mydata.csv @my_int_stage;", FileTransferType.PUT),
        ("/**/ GET @%mytable file:///tmp/data/;", FileTransferType.GET),
        pytest.param(
            "/**/\n"
            + "\t/*/get\t*/\t/**/\n" * 10000
            + "\t*/get @~/test.csv file:///tmp\n",
            None,
            id="long_incorrect",
        ),
        pytest.param(
            "/**/\n" + "\t/*/put\t*/\t/**/\n" * 10000 + "put file:///tmp/data.csv @~",
            FileTransferType.PUT,
            id="long_correct",
        ),
    ),
)
def test_get_filetransfer_type(sql, _type):
    assert SnowflakeCursor.get_file_transfer_type(sql) == _type


def test_cursor_attribute():
    fake_conn = FakeConnection()
    cursor = SnowflakeCursor(fake_conn)
    assert cursor.lastrowid is None


def test_query_can_be_empty_with_dataframe_ast():
    def mock_is_closed(*args, **kwargs):
        return False

    fake_conn = FakeConnection()
    fake_conn.is_closed = mock_is_closed
    cursor = SnowflakeCursor(fake_conn)
    # when `dataframe_ast` is not presented, the execute function return None
    assert cursor.execute("") is None
    # when `dataframe_ast` is presented, it should not return `None`
    # but raise `AttributeError` since `_paramstyle` is not set in FakeConnection.
    with pytest.raises(AttributeError):
        cursor.execute("", _dataframe_ast="ABCD")


@patch("snowflake.connector.cursor.SnowflakeCursor._SnowflakeCursorBase__cancel_query")
def test_cursor_execute_timeout(mockCancelQuery):
    def mock_cmd_query(*args, **kwargs):
        time.sleep(10)
        raise ServiceUnavailableError()

    fake_conn = FakeConnection()
    fake_conn.cmd_query = mock_cmd_query
    fake_conn._rest = MagicMock()
    fake_conn._paramstyle = MagicMock()
    fake_conn._next_sequence_counter = MagicMock()

    cursor = SnowflakeCursor(fake_conn)

    with pytest.raises(ServiceUnavailableError):
        cursor.execute(
            command="SELECT * FROM nonexistent",
            timeout=1,
        )

    # query cancel request should be sent upon timeout
    assert mockCancelQuery.called


# The _upload/_download/_upload_stream/_download_stream are newly introduced
# and therefore should not be tested in old drivers.
@pytest.mark.skipolddriver
class TestUploadDownloadMethods(TestCase):
    """Test the _upload/_download/_upload_stream/_download_stream methods."""

    @patch("snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent")
    def test_download(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _download method
        cursor._download("@st", "/tmp/test.txt", {})

        # In the process of _download execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - execute in SnowflakeFileTransferAgent
        # And we do not expect this method to be involved
        #   - download_as_stream of connection._stream_downloader
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_not_called()
        MockFileTransferAgent.assert_called_once()
        assert MockFileTransferAgent.call_args.kwargs.get("use_s3_regional_url", False)
        mock_file_transfer_agent_instance.execute.assert_called_once()

    @patch("snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent")
    def test_upload(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _upload method
        cursor._upload("/tmp/test.txt", "@st", {})

        # In the process of _upload execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - execute in SnowflakeFileTransferAgent
        # And we do not expect this method to be involved
        #   - download_as_stream of connection._stream_downloader
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_not_called()
        MockFileTransferAgent.assert_called_once()
        assert MockFileTransferAgent.call_args.kwargs.get("use_s3_regional_url", False)
        mock_file_transfer_agent_instance.execute.assert_called_once()

    @patch("snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent")
    def test_download_stream(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _download_stream method
        cursor._download_stream("@st/test.txt", decompress=True)

        # In the process of _download_stream execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - download_as_stream of connection._stream_downloader
        # And we do not expect this method to be involved
        #   - execute in SnowflakeFileTransferAgent
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_called_once()
        MockFileTransferAgent.assert_not_called()
        mock_file_transfer_agent_instance.execute.assert_not_called()

    @patch("snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent")
    def test_upload_stream(self, MockFileTransferAgent):
        cursor, fake_conn, mock_file_transfer_agent_instance = self._setup_mocks(
            MockFileTransferAgent
        )

        # Call _upload_stream method
        fd = MagicMock()
        cursor._upload_stream(fd, "@st/test.txt", {})

        # In the process of _upload_stream execution, we expect these methods to be called
        #   - parse_file_operation in connection._file_operation_parser
        #   - execute in SnowflakeFileTransferAgent
        # And we do not expect this method to be involved
        #   - download_as_stream of connection._stream_downloader
        fake_conn._file_operation_parser.parse_file_operation.assert_called_once()
        fake_conn._stream_downloader.download_as_stream.assert_not_called()
        MockFileTransferAgent.assert_called_once()
        assert MockFileTransferAgent.call_args.kwargs.get("use_s3_regional_url", False)
        mock_file_transfer_agent_instance.execute.assert_called_once()

    def _setup_mocks(self, MockFileTransferAgent):
        mock_file_transfer_agent_instance = MockFileTransferAgent.return_value
        mock_file_transfer_agent_instance.execute.return_value = None

        fake_conn = FakeConnection()
        fake_conn._file_operation_parser = MagicMock()
        fake_conn._stream_downloader = MagicMock()
        # this should be true on all new AWS deployments to use regional endpoints for staging operations
        fake_conn._enable_stage_s3_privatelink_for_us_east_1 = True
        fake_conn._iobound_tpe_limit = 1
        fake_conn._unsafe_file_write = False

        cursor = SnowflakeCursor(fake_conn)
        cursor.reset = MagicMock()
        cursor._init_result_and_meta = MagicMock()
        return cursor, fake_conn, mock_file_transfer_agent_instance

    def _run_dop_cap_test(self, task, dop_cap):
        """A helper to run dop cap test.

        It mainly verifies that when performing the specified task, we are using a FileTransferAgent with DoP cap as specified.
        """
        from snowflake.connector._utils import (
            _VARIABLE_NAME_SERVER_DOP_CAP_FOR_FILE_TRANSFER,
        )

        mock_conn = FakeConnection()
        setattr(
            mock_conn, f"_{_VARIABLE_NAME_SERVER_DOP_CAP_FOR_FILE_TRANSFER}", dop_cap
        )

        class FakeFileOperationParser:
            def parse_file_operation(
                self,
                stage_location,
                local_file_name,
                target_directory,
                command_type,
                options,
                has_source_from_stream=False,
            ):
                return {}

        mock_cursor = SnowflakeCursor(mock_conn)
        mock_conn._file_operation_parser = FakeFileOperationParser()
        with patch.object(
            mock_cursor, "_init_result_and_meta", return_value=None
        ), patch(
            "snowflake.connector.file_transfer_agent.SnowflakeFileTransferAgent"
        ) as MockFileTransferAgent:
            task(mock_cursor)
            # Verify that when running the file operation, we are using FileTransferAgent with server DoP cap as 1.
            _, kwargs = MockFileTransferAgent.call_args
            assert dop_cap == kwargs["snowflake_server_dop_cap_for_file_transfer"]

    def test_dop_cap_for_upload(self):
        def task(cursor):
            cursor._upload("/tmp/test.txt", "@st", {})

        self._run_dop_cap_test(task, dop_cap=1)

    def test_dop_cap_for_upload_stream(self):
        def task(cursor):
            mock_input_stream = MagicMock()
            cursor._upload_stream(mock_input_stream, "@st", {})

        self._run_dop_cap_test(task, dop_cap=1)

    def test_dop_cap_for_download(self):
        def task(cursor):
            cursor._download("@st", "/tmp", {})

        self._run_dop_cap_test(task, dop_cap=1)


def _rows_via_fetchmany(cursor, size=100):
    """Customer pattern from SNOW-4109042: drain with fetchmany until empty."""
    rows = []
    while True:
        batch = cursor.fetchmany(size)
        if not batch:
            break
        rows.extend(batch)
    return rows


def test_fetchmany_typeerror_during_iteration_is_not_eof():
    """SNOW-4109042: TypeError from the result iterator must not become silent EOF.

    ``_fetchone`` catches TypeError while ``_result_state`` is VALID and returns
    None. ``fetchmany`` treats None as end-of-results, so a conversion/parse
    TypeError mid-stream looks like a successful short read.
    """

    def exploding_rows():
        yield (1,)
        yield (2,)
        raise TypeError("simulated arrow/json conversion failure")
        yield (3,)

    cursor = SnowflakeCursor(FakeConnection())
    cursor._result = exploding_rows()
    cursor._result_state = ResultState.VALID
    cursor._rownumber = -1
    cursor._total_rowcount = 3

    with pytest.raises(TypeError, match="simulated arrow/json conversion failure"):
        _rows_via_fetchmany(cursor, size=100)


def test_fetchmany_on_reset_cursor_still_reports_end_of_results():
    """A cursor that was reset has no rows left, which is not an error."""
    cursor = SnowflakeCursor(FakeConnection())
    cursor._result_state = ResultState.RESET

    assert cursor.fetchmany(100) == []


# Short remote chunk: server produced 954 rows, fetchmany(100) returned 875.
_SHORT_REMOTE_TOTAL = 954
_SHORT_REMOTE_INLINE_ROWS = 75
_SHORT_REMOTE_DECLARED = 879
_SHORT_REMOTE_ACTUAL = 800  # 75 + 800 = 875

# GS log shape: "total rows = 954, first chunk rows = 79" → client got 875.
_INCOMPLETE_INLINE_TOTAL = 954
_INCOMPLETE_INLINE_ROWS = 79
_INCOMPLETE_REMOTE_ROWS = _INCOMPLETE_INLINE_TOTAL - _INCOMPLETE_INLINE_ROWS  # 875


def _gzip_json_result_chunk(rows: list[list[str]]) -> str:
    """Snowflake JSON chunks are concatenated row arrays; the client wraps them in ``[]``."""
    payload = ",".join(json.dumps(row) for row in rows).encode()
    return base64.b64encode(gzip.compress(payload)).decode("ascii")


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


def _gzip_arrow_result_chunk(values: list[str]) -> str:
    return base64.b64encode(gzip.compress(_arrow_text_column_ipc(values))).decode(
        "ascii"
    )


def _gzip_remote_chunk(rows: list[list[str]], result_format: str) -> str:
    if result_format == "arrow":
        return _gzip_arrow_result_chunk([row[0] for row in rows])
    return _gzip_json_result_chunk(rows)


def _set_inline_payload(
    data: dict, rows: list[list[str]] | None, result_format: str
) -> None:
    data["queryResultFormat"] = result_format
    if result_format == "arrow":
        data.pop("rowset", None)
        data["rowtype"] = [
            {
                "name": "C1",
                "database": "",
                "schema": "",
                "table": "",
                "nullable": True,
                "length": 16777216,
                "type": "text",
                "scale": None,
                "precision": None,
                "byteLength": 16777216,
                "collation": None,
            }
        ]
        if rows:
            data["rowsetBase64"] = base64.b64encode(
                _arrow_text_column_ipc([row[0] for row in rows])
            ).decode("ascii")
        else:
            data["rowsetBase64"] = ""
    else:
        data.pop("rowsetBase64", None)
        data["rowset"] = rows if rows is not None else []


_TEST_QUERY_ID = "01ba13b4-0104-e9fd-0000-0111029ca00e"
_INLINE_ONLY_TOTAL = 36


def _base_select_query_mapping(
    wiremock_mapping_dir, result_format: str = "json"
) -> dict:
    mapping = json.loads(
        (wiremock_mapping_dir / "queries/select_1_successful.json").read_text()
    )
    data = mapping["response"]["jsonBody"]["data"]
    data["queryId"] = _TEST_QUERY_ID
    data["queryResultFormat"] = result_format
    return mapping


def _wiremock_connect(target_wm):
    return snowflake.connector.connect(
        user="testUser",
        password="testPassword",
        account="testAccount",
        host=target_wm.wiremock_host,
        port=target_wm.wiremock_http_port,
        protocol="http",
        warehouse="TEST_WH",
        platform_detection_timeout_seconds=0,
    )


def _storage_placeholders(target_wm) -> dict[str, str]:
    return {"{{STORAGE_WIREMOCK_HTTP_HOST_WITH_PORT}}": target_wm.http_host_with_port}


def _configure_wiremock_session(
    target_wm,
    wiremock_mapping_dir,
    wiremock_generic_mappings_dir,
    middle_mappings,
):
    """Password auth, then the test's core mappings, then disconnect + telemetry.

    ``middle_mappings`` entries are either a mapping dict or
    ``(mapping, placeholders)``.
    """
    target_wm.import_mapping_with_default_placeholders(
        wiremock_mapping_dir / "auth/password/successful_flow.json"
    )
    for item in middle_mappings:
        if isinstance(item, tuple):
            mapping, placeholders = item
            target_wm.add_mapping(mapping, placeholders=placeholders)
        else:
            target_wm.add_mapping(item)
    target_wm.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    target_wm.add_mapping(wiremock_generic_mappings_dir / "telemetry.json")


def _count_urls_matching(target_wm, pattern: str) -> int:
    return sum(
        1
        for r in target_wm.get_requests()["requests"]
        if pattern in r["request"]["url"]
    )


@pytest.mark.skipolddriver
def test_fetchmany_short_remote_chunk_is_not_silent_eof(
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
):
    """SNOW-4109042: Wiremock stand-in for a remote result chunk that is shorter than advertised.

    Live Snowflake cannot force a truncated blob. Here the query response says
    ``total=954`` and the remote chunk claims ``rowCount=879``, but the gzip
    body only contains 800 JSON rows. Draining with ``fetchmany(100)`` used to
    stop at 875 rows and report that as a clean EOF; the missing rows must be
    reported instead.
    """
    target_wm, _proxy_wm = wiremock_target_proxy_pair
    chunk_url_path = (
        "/amazonaws/test/s3testaccount/stage/results/short-remote-chunk/"
        "data_0_0_0_1?response-content-encoding=gzip"
    )

    query_mapping = json.loads(
        (wiremock_mapping_dir / "queries/select_1_successful.json").read_text()
    )
    data = query_mapping["response"]["jsonBody"]["data"]
    data["rowset"] = [[str(i)] for i in range(_SHORT_REMOTE_INLINE_ROWS)]
    data["total"] = _SHORT_REMOTE_TOTAL
    data["returned"] = _SHORT_REMOTE_TOTAL
    data["queryResultFormat"] = "json"
    data["chunks"] = [
        {
            "url": "{{STORAGE_WIREMOCK_HTTP_HOST_WITH_PORT}}" + chunk_url_path,
            "rowCount": _SHORT_REMOTE_DECLARED,
            "uncompressedSize": 1,
            "compressedSize": 1,
        }
    ]

    remote_rows = [
        [str(i)]
        for i in range(
            _SHORT_REMOTE_INLINE_ROWS,
            _SHORT_REMOTE_INLINE_ROWS + _SHORT_REMOTE_ACTUAL,
        )
    ]
    chunk_mapping = {
        "request": {"method": "GET", "url": chunk_url_path},
        "response": {
            "status": 200,
            "headers": {"Content-Encoding": "gzip"},
            "base64Body": _gzip_json_result_chunk(remote_rows),
        },
    }

    _configure_wiremock_session(
        target_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
        [
            (query_mapping, _storage_placeholders(target_wm)),
            chunk_mapping,
        ],
    )

    with _wiremock_connect(target_wm) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM large_table")
            assert cur.rowcount == _SHORT_REMOTE_TOTAL
            assert len(cur._result_set.batches) == 2
            with pytest.raises(OperationalError) as ex:
                _rows_via_fetchmany(cur, size=100)

    assert target_wm.saw_urls_matching(
        ["short-remote-chunk"]
    ), "remote chunk was never downloaded; this would not mimic the ticket"
    assert ex.value.errno == ER_INCOMPLETE_RESULT_CHUNK
    assert (
        f"holds {_SHORT_REMOTE_ACTUAL} row(s) but the server reported "
        f"{_SHORT_REMOTE_DECLARED}" in ex.value.msg
    )


@pytest.mark.skipolddriver
@pytest.mark.parametrize("result_format", _RESULT_FORMATS)
def test_empty_inline_result_is_recovered_via_query_result_get(
    result_format,
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
):
    target_wm, _proxy_wm = wiremock_target_proxy_pair
    result_url = f"/queries/{_TEST_QUERY_ID}/result"
    recovered_rows = [[str(i)] for i in range(_INLINE_ONLY_TOTAL)]

    # query-request: success with total=36 but an empty inline chunk (all rows
    # were supposed to be inline; client used to see 0 rows and stop quietly)
    empty_inline = _base_select_query_mapping(wiremock_mapping_dir, result_format)
    empty_data = empty_inline["response"]["jsonBody"]["data"]
    _set_inline_payload(empty_data, [], result_format)
    empty_data["total"] = _INLINE_ONLY_TOTAL
    empty_data["returned"] = _INLINE_ONLY_TOTAL
    empty_data.pop("chunks", None)

    # GET /queries/{qid}/result: return the full inline payload so recovery works
    recovered = _base_select_query_mapping(wiremock_mapping_dir, result_format)
    recovered_data = recovered["response"]["jsonBody"]["data"]
    _set_inline_payload(recovered_data, recovered_rows, result_format)
    recovered_data["total"] = _INLINE_ONLY_TOTAL
    recovered_data["returned"] = _INLINE_ONLY_TOTAL
    recovered_data.pop("chunks", None)

    result_mapping = {
        "request": {"method": "GET", "urlPathPattern": f"{result_url}.*"},
        "response": recovered["response"],
    }

    _configure_wiremock_session(
        target_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
        [empty_inline, result_mapping],
    )

    # execute sees the empty inline, re-GETs the result, then fetchmany gets all rows
    with _wiremock_connect(target_wm) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM inline_only")
            rows = _rows_via_fetchmany(cur, size=100)

    assert len(rows) == _INLINE_ONLY_TOTAL
    assert _count_urls_matching(target_wm, result_url) == 1


@pytest.mark.skipolddriver
def test_short_nonempty_json_inline_is_recovered_via_query_result_get(
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
):
    """JSON recovers short non-empty inline; Arrow deliberately does not."""
    target_wm, _proxy_wm = wiremock_target_proxy_pair
    result_url = f"/queries/{_TEST_QUERY_ID}/result"
    short_rows = [[str(i)] for i in range(10)]
    recovered_rows = [[str(i)] for i in range(_INLINE_ONLY_TOTAL)]

    short_inline = _base_select_query_mapping(wiremock_mapping_dir, "json")
    short_data = short_inline["response"]["jsonBody"]["data"]
    _set_inline_payload(short_data, short_rows, "json")
    short_data["total"] = _INLINE_ONLY_TOTAL
    short_data["returned"] = _INLINE_ONLY_TOTAL
    short_data.pop("chunks", None)

    recovered = _base_select_query_mapping(wiremock_mapping_dir, "json")
    recovered_data = recovered["response"]["jsonBody"]["data"]
    _set_inline_payload(recovered_data, recovered_rows, "json")
    recovered_data["total"] = _INLINE_ONLY_TOTAL
    recovered_data["returned"] = _INLINE_ONLY_TOTAL
    recovered_data.pop("chunks", None)

    result_mapping = {
        "request": {"method": "GET", "urlPathPattern": f"{result_url}.*"},
        "response": recovered["response"],
    }

    _configure_wiremock_session(
        target_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
        [short_inline, result_mapping],
    )

    with _wiremock_connect(target_wm) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM inline_only")
            rows = _rows_via_fetchmany(cur, size=100)

    assert len(rows) == _INLINE_ONLY_TOTAL
    assert _count_urls_matching(target_wm, result_url) == 1


@pytest.mark.skipolddriver
def test_query_result_recovers_empty_inline_via_second_get(
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
):
    """query_result is GET-then-maybe-GET-again; recover when the first GET is short."""
    target_wm, _proxy_wm = wiremock_target_proxy_pair
    result_url = f"/queries/{_TEST_QUERY_ID}/result"
    recovered_rows = [[str(i)] for i in range(_INLINE_ONLY_TOTAL)]
    scenario = "query-result-incomplete-then-recover"

    empty = _base_select_query_mapping(wiremock_mapping_dir, "json")
    empty_data = empty["response"]["jsonBody"]["data"]
    _set_inline_payload(empty_data, [], "json")
    empty_data["total"] = _INLINE_ONLY_TOTAL
    empty_data["returned"] = _INLINE_ONLY_TOTAL
    empty_data.pop("chunks", None)

    recovered = _base_select_query_mapping(wiremock_mapping_dir, "json")
    recovered_data = recovered["response"]["jsonBody"]["data"]
    _set_inline_payload(recovered_data, recovered_rows, "json")
    recovered_data["total"] = _INLINE_ONLY_TOTAL
    recovered_data["returned"] = _INLINE_ONLY_TOTAL
    recovered_data.pop("chunks", None)

    # query-request stub so connection teardown COMMIT does not 404 (same
    # pattern as the execute()-based recovery tests above)
    query_request = _base_select_query_mapping(wiremock_mapping_dir, "json")

    first_get = {
        "scenarioName": scenario,
        "requiredScenarioState": "Started",
        "newScenarioState": "Recovered",
        "request": {"method": "GET", "urlPathPattern": f"{result_url}.*"},
        "response": empty["response"],
    }
    second_get = {
        "scenarioName": scenario,
        "requiredScenarioState": "Recovered",
        "request": {"method": "GET", "urlPathPattern": f"{result_url}.*"},
        "response": recovered["response"],
    }

    _configure_wiremock_session(
        target_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
        [query_request, first_get, second_get],
    )

    with _wiremock_connect(target_wm) as conn:
        with conn.cursor() as cur:
            cur.query_result(_TEST_QUERY_ID)
            rows = _rows_via_fetchmany(cur, size=100)

    assert len(rows) == _INLINE_ONLY_TOTAL
    assert _count_urls_matching(target_wm, result_url) == 2


@pytest.mark.skipolddriver
@pytest.mark.parametrize("result_format", _RESULT_FORMATS)
def test_empty_inline_with_remote_chunks_is_recovered_via_query_result_get(
    result_format,
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
):
    target_wm, _proxy_wm = wiremock_target_proxy_pair
    result_url = f"/queries/{_TEST_QUERY_ID}/result"
    chunk_url_path = (
        "/amazonaws/test/s3testaccount/stage/results/incomplete-inline-recover/"
        "data_0_0_0_1?response-content-encoding=gzip"
    )
    inline_rows = [[str(i)] for i in range(_INCOMPLETE_INLINE_ROWS)]
    remote_rows = [
        [str(i)] for i in range(_INCOMPLETE_INLINE_ROWS, _INCOMPLETE_INLINE_TOTAL)
    ]

    # Shared response shape: total=954, remote chunk declares 875 rows, so the
    # inline first chunk is expected to hold the remaining 79.
    def _query_body(rowset):
        mapping = _base_select_query_mapping(wiremock_mapping_dir, result_format)
        data = mapping["response"]["jsonBody"]["data"]
        _set_inline_payload(data, rowset, result_format)
        data["total"] = _INCOMPLETE_INLINE_TOTAL
        data["returned"] = _INCOMPLETE_INLINE_TOTAL
        data["chunks"] = [
            {
                "url": "{{STORAGE_WIREMOCK_HTTP_HOST_WITH_PORT}}" + chunk_url_path,
                "rowCount": _INCOMPLETE_REMOTE_ROWS,
                "uncompressedSize": 1,
                "compressedSize": 1,
            }
        ]
        return mapping

    # query-request: empty inline; remote chunk metadata still healthy
    empty_inline = _query_body([])
    # GET /queries/{qid}/result: restore the 79 inline rows
    recovered = _query_body(inline_rows)
    result_mapping = {
        "request": {"method": "GET", "urlPathPattern": f"{result_url}.*"},
        "response": recovered["response"],
    }
    # Remote chunk body holds the other 875 rows
    chunk_mapping = {
        "request": {"method": "GET", "url": chunk_url_path},
        "response": {
            "status": 200,
            "headers": {"Content-Encoding": "gzip"},
            "base64Body": _gzip_remote_chunk(remote_rows, result_format),
        },
    }

    storage = _storage_placeholders(target_wm)
    _configure_wiremock_session(
        target_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
        [
            (empty_inline, storage),
            (result_mapping, storage),
            chunk_mapping,
        ],
    )

    # After recovery, fetchmany should yield inline + remote = full total
    with _wiremock_connect(target_wm) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM large_table")
            rows = _rows_via_fetchmany(cur, size=100)

    assert len(rows) == _INCOMPLETE_INLINE_TOTAL
    assert _count_urls_matching(target_wm, result_url) == 1
    assert target_wm.saw_urls_matching(["incomplete-inline-recover"])


@pytest.mark.skipolddriver
@pytest.mark.parametrize("result_format", _RESULT_FORMATS)
def test_empty_inline_still_raises_when_result_get_also_incomplete(
    result_format,
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
):
    target_wm, _proxy_wm = wiremock_target_proxy_pair
    result_url = f"/queries/{_TEST_QUERY_ID}/result"

    # query-request and the recovery GET both return empty inline / total=36
    empty_inline = _base_select_query_mapping(wiremock_mapping_dir, result_format)
    empty_data = empty_inline["response"]["jsonBody"]["data"]
    _set_inline_payload(empty_data, [], result_format)
    empty_data["total"] = _INLINE_ONLY_TOTAL
    empty_data["returned"] = _INLINE_ONLY_TOTAL
    empty_data.pop("chunks", None)

    result_mapping = {
        "request": {"method": "GET", "urlPathPattern": f"{result_url}.*"},
        "response": empty_inline["response"],
    }

    _configure_wiremock_session(
        target_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
        [empty_inline, result_mapping],
    )

    # Recovery is attempted once; when it still fails, surface 252013 (not silent EOF)
    with _wiremock_connect(target_wm) as conn:
        with conn.cursor() as cur:
            with pytest.raises(OperationalError) as ex:
                cur.execute("SELECT * FROM inline_only")
                _rows_via_fetchmany(cur, size=100)

    assert ex.value.errno == ER_INCOMPLETE_RESULT_CHUNK
    assert _count_urls_matching(target_wm, result_url) == 1


@pytest.mark.skipolddriver
def test_refetch_keeps_original_when_result_get_raises():
    """A retryable/transport recovery GET failure must keep the original payload."""
    fake_conn = FakeConnection()
    fake_conn._rest = MagicMock()
    fake_conn._rest.request.side_effect = ServiceUnavailableError(errno=503)
    cursor = SnowflakeCursor(fake_conn)
    cursor._sfqid = _TEST_QUERY_ID
    cursor._is_file_transfer = False
    original = {"total": 36, "rowset": [], "queryResultFormat": "json"}

    assert cursor._refetch(original) is original
    fake_conn._rest.request.assert_called_once()


@pytest.mark.skipolddriver
def test_refetch_keeps_original_when_result_get_success_false():
    """A successful HTTP response with success:false must keep the original payload."""
    fake_conn = FakeConnection()
    fake_conn._rest = MagicMock()
    fake_conn._rest.request.return_value = {
        "success": False,
        "message": "query failed",
        "code": "000000",
        "data": {"queryId": _TEST_QUERY_ID},
    }
    cursor = SnowflakeCursor(fake_conn)
    cursor._sfqid = _TEST_QUERY_ID
    cursor._is_file_transfer = False
    original = {"total": 36, "rowset": [], "queryResultFormat": "json"}

    assert cursor._refetch(original) is original
    fake_conn._rest.request.assert_called_once()


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "ret",
    [
        {"success": True},  # missing data
        {"success": True, "data": None},
        {"success": True, "data": "not-a-dict"},
    ],
)
def test_refetch_keeps_original_when_result_get_success_with_non_dict_data(ret):
    """success:true with missing/non-dict data must keep the original payload."""
    fake_conn = FakeConnection()
    fake_conn._rest = MagicMock()
    fake_conn._rest.request.return_value = ret
    cursor = SnowflakeCursor(fake_conn)
    cursor._sfqid = _TEST_QUERY_ID
    cursor._is_file_transfer = False
    original = {"total": 36, "rowset": [], "queryResultFormat": "json"}

    assert cursor._refetch(original) is original
    fake_conn._rest.request.assert_called_once()


@pytest.mark.skipolddriver
def test_refetch_reraises_connection_closed():
    """Closed-connection must not become keep-original + later 252013."""
    from snowflake.connector.errorcode import ER_CONNECTION_IS_CLOSED

    fake_conn = FakeConnection()
    fake_conn._rest = MagicMock()
    fake_conn._rest.request.side_effect = OperationalError(
        msg="Connection is closed",
        errno=ER_CONNECTION_IS_CLOSED,
    )
    cursor = SnowflakeCursor(fake_conn)
    cursor._sfqid = _TEST_QUERY_ID
    cursor._is_file_transfer = False
    original = {"total": 36, "rowset": [], "queryResultFormat": "json"}

    with pytest.raises(OperationalError) as ex:
        cursor._refetch(original)
    assert ex.value.errno == ER_CONNECTION_IS_CLOSED
    fake_conn._rest.request.assert_called_once()


@pytest.mark.skipolddriver
def test_is_inline_chunk_incomplete_skips_dml_and_file_transfer():
    from snowflake.connector.cursor import STATEMENT_TYPE_ID_INSERT

    fake_conn = FakeConnection()
    cursor = SnowflakeCursor(fake_conn)
    cursor._sfqid = _TEST_QUERY_ID
    incomplete = {"total": 36, "rowset": [], "queryResultFormat": "json"}

    cursor._is_file_transfer = False
    assert cursor._is_inline_chunk_incomplete(incomplete) is True
    assert cursor._is_inline_chunk_incomplete(None) is False
    assert cursor._is_inline_chunk_incomplete("not-a-dict") is False

    dml = {
        **incomplete,
        "statementTypeId": STATEMENT_TYPE_ID_INSERT,
    }
    assert cursor._is_inline_chunk_incomplete(dml) is False

    cursor._is_file_transfer = True
    assert cursor._is_inline_chunk_incomplete(incomplete) is False


@pytest.mark.skipolddriver
def test_truncated_query_response_body_is_retried(
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
):
    """network.py retries ValueError from raw_ret.json(); not the _refetch path.

    A failure here is a truncated-body / network retry regression, not a
    SNOW-4109042 incomplete-inline recovery regression.
    """
    target_wm, _proxy_wm = wiremock_target_proxy_pair
    healthy = _base_select_query_mapping(wiremock_mapping_dir)
    scenario = "truncated-query-request-body"

    # First query-request: HTTP 200 with a cut-off JSON body (decode fails)
    truncated = {
        "scenarioName": scenario,
        "requiredScenarioState": "Started",
        "newScenarioState": "Retried",
        "request": {
            "urlPathPattern": "/queries/v1/query-request.*",
            "method": "POST",
            "headers": {
                "Authorization": {"equalTo": 'Snowflake Token="session token"'}
            },
        },
        "response": {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"data":{"queryId":"01ba13b4-0104-e9fd-0000-0111029ca00e","rowset"',
        },
    }
    # Second query-request (same Wiremock scenario): healthy SELECT 1 payload
    recovered = {
        "scenarioName": scenario,
        "requiredScenarioState": "Retried",
        "request": healthy["request"],
        "response": healthy["response"],
    }

    _configure_wiremock_session(
        target_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
        [truncated, recovered],
    )

    # network.py retries the failed JSON decode; the second POST succeeds
    with _wiremock_connect(target_wm) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            assert cur.fetchall() == [(1,)]

    assert _count_urls_matching(target_wm, "/queries/v1/query-request") == 2


# ---------------------------------------------------------------------------
# SNOW-4109042: the result set as a whole is checked against the back-end's
# "total". The inline first chunk of the query-request response can arrive empty
# while the response still declares the full total, and on the JSON path that
# batch is internally consistent (its rowcount is len(rowset)), so the declared
# total is the only thing left to compare the delivered rows against.
# ---------------------------------------------------------------------------

pytestmark_result_set = pytest.mark.skipif(
    not _have_result_set, reason="connector build unavailable"
)


def _json_rows(count: int, start: int = 0) -> list[list[str]]:
    return [[str(i)] for i in range(start, start + count)]


def _local_json_batch(rows: list[list[str]]) -> JSONResultBatch:
    """The inline first chunk: ``from_data`` always takes its rowcount from the rows."""
    return JSONResultBatch.from_data(rows, len(rows), [], [], False)


def _remote_json_batch(declared: int, rows: list[list[str]]):
    """A remote chunk plus the response its (mocked) download returns."""
    batch = JSONResultBatch(
        rowcount=declared,
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
    response = requests.Response()
    response.status_code = 200
    response._content = ",".join(json.dumps(row) for row in rows).encode()
    return batch, response


def _empty_inline_arrow_batch(first_chunk_len: int) -> ArrowResultBatch:
    return ArrowResultBatch.from_data(
        base64.b64encode(b"").decode("ascii"),
        first_chunk_len,
        ArrowConverterContext(session_parameters={}),
        False,
        False,
        [],
        False,
    )


def _cursor_over_batches(batches, total_row_count) -> SnowflakeCursor:
    """A cursor wired to a result set the way ``_init_result_and_meta`` wires one."""
    cursor = SnowflakeCursor(FakeConnection())
    cursor._result_set = ResultSet(
        cursor,
        batches,
        prefetch_thread_num=1,
        use_mp=False,
        total_row_count=total_row_count,
    )
    cursor._result_state = ResultState.VALID
    cursor._rownumber = -1
    return cursor


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_empty_inline_json_chunk_is_caught_by_the_total_check():
    """Every batch is self-consistent, yet 79 of the 954 rows never arrive.

    This is the JSON shape of the ticket: the inline rowset came back empty, the
    remote chunk delivered exactly what it promised, and the client used to
    report the 875 rows it had as a complete result set.
    """
    remote, response = _remote_json_batch(
        _INCOMPLETE_REMOTE_ROWS,
        _json_rows(_INCOMPLETE_REMOTE_ROWS, _INCOMPLETE_INLINE_ROWS),
    )
    cursor = _cursor_over_batches(
        [_local_json_batch([]), remote], _INCOMPLETE_INLINE_TOTAL
    )

    with patch.object(remote, "_download", return_value=response):
        with pytest.raises(OperationalError) as ex:
            _rows_via_fetchmany(cursor, size=100)

    assert ex.value.errno == ER_INCOMPLETE_RESULT_CHUNK
    assert (
        f"the result set produced {_INCOMPLETE_REMOTE_ROWS} row(s) but the server "
        f"reported {_INCOMPLETE_INLINE_TOTAL}" in ex.value.msg
    )


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_empty_inline_arrow_chunk_with_healthy_remote_chunk_is_loud():
    """End to end on the Arrow path: 954 declared, 875 delivered, no silence.

    The inline chunk's own rowcount is server metadata here, so the batch-level
    check fires first -- either way the caller must not walk away with 875 rows.
    """
    remote, response = _remote_json_batch(
        _INCOMPLETE_REMOTE_ROWS,
        _json_rows(_INCOMPLETE_REMOTE_ROWS, _INCOMPLETE_INLINE_ROWS),
    )
    cursor = _cursor_over_batches(
        [_empty_inline_arrow_batch(_INCOMPLETE_INLINE_ROWS), remote],
        _INCOMPLETE_INLINE_TOTAL,
    )

    with patch.object(remote, "_download", return_value=response):
        with pytest.raises(OperationalError) as ex:
            _rows_via_fetchmany(cursor, size=100)

    assert ex.value.errno == ER_INCOMPLETE_RESULT_CHUNK


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_complete_result_set_does_not_raise():
    remote, response = _remote_json_batch(
        _INCOMPLETE_REMOTE_ROWS,
        _json_rows(_INCOMPLETE_REMOTE_ROWS, _INCOMPLETE_INLINE_ROWS),
    )
    cursor = _cursor_over_batches(
        [_local_json_batch(_json_rows(_INCOMPLETE_INLINE_ROWS)), remote],
        _INCOMPLETE_INLINE_TOTAL,
    )

    with patch.object(remote, "_download", return_value=response):
        assert len(_rows_via_fetchmany(cursor, size=100)) == _INCOMPLETE_INLINE_TOTAL


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_empty_result_set_does_not_raise():
    """A query that legitimately returned nothing declares total = 0."""
    cursor = _cursor_over_batches([_local_json_batch([])], 0)

    assert cursor.fetchall() == []


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_result_set_without_declared_total_does_not_raise():
    """Responses that carry no ``total`` promise nothing to compare against."""
    cursor = _cursor_over_batches([_local_json_batch(_json_rows(3))], None)

    assert len(cursor.fetchall()) == 3


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_fetchmany_stopping_early_does_not_raise():
    """Reading part of a healthy result set is normal usage, not a short read."""
    remote, response = _remote_json_batch(
        _INCOMPLETE_REMOTE_ROWS,
        _json_rows(_INCOMPLETE_REMOTE_ROWS, _INCOMPLETE_INLINE_ROWS),
    )
    cursor = _cursor_over_batches(
        [_local_json_batch(_json_rows(_INCOMPLETE_INLINE_ROWS)), remote],
        _INCOMPLETE_INLINE_TOTAL,
    )

    with patch.object(remote, "_download", return_value=response):
        assert len(cursor.fetchmany(10)) == 10
        # Dropping the half-consumed iterator is what closing a cursor does.
        cursor.reset()


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_breaking_out_of_cursor_iteration_does_not_raise():
    remote, response = _remote_json_batch(
        _INCOMPLETE_REMOTE_ROWS,
        _json_rows(_INCOMPLETE_REMOTE_ROWS, _INCOMPLETE_INLINE_ROWS),
    )
    cursor = _cursor_over_batches(
        [_local_json_batch(_json_rows(_INCOMPLETE_INLINE_ROWS)), remote],
        _INCOMPLETE_INLINE_TOTAL,
    )

    rows = []
    with patch.object(remote, "_download", return_value=response):
        for row in cursor:
            rows.append(row)
            if len(rows) == 5:
                break
        cursor.reset()

    assert len(rows) == 5


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_result_batches_are_not_row_counted_against_the_total():
    """``get_result_batches()`` hands out batches the user drives themselves."""
    cursor = _cursor_over_batches(
        [_local_json_batch(_json_rows(_INCOMPLETE_INLINE_ROWS))],
        _INCOMPLETE_INLINE_TOTAL,
    )

    (batch,) = cursor.get_result_batches()

    assert len(list(batch)) == _INCOMPLETE_INLINE_ROWS
