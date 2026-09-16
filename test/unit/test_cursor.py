from __future__ import annotations

import base64
import gzip
import json
import time
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


# Ticket Query 1: server produced 954 rows, fetchmany(100) returned 875.
_SNOW_4109042_SERVER_ROWS = 954
_SNOW_4109042_FIRST_CHUNK_ROWS = 75
_SNOW_4109042_REMOTE_CHUNK_DECLARED = 879
_SNOW_4109042_REMOTE_CHUNK_ACTUAL = 800  # 75 + 800 = 875


def _gzip_json_result_chunk(rows: list[list[str]]) -> str:
    """Snowflake JSON chunks are concatenated row arrays; the client wraps them in ``[]``."""
    payload = ",".join(json.dumps(row) for row in rows).encode()
    return base64.b64encode(gzip.compress(payload)).decode("ascii")


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
        "/amazonaws/test/s3testaccount/stage/results/snow-4109042/"
        "data_0_0_0_1?response-content-encoding=gzip"
    )

    query_mapping = json.loads(
        (wiremock_mapping_dir / "queries/select_1_successful.json").read_text()
    )
    data = query_mapping["response"]["jsonBody"]["data"]
    data["rowset"] = [[str(i)] for i in range(_SNOW_4109042_FIRST_CHUNK_ROWS)]
    data["total"] = _SNOW_4109042_SERVER_ROWS
    data["returned"] = _SNOW_4109042_SERVER_ROWS
    data["queryResultFormat"] = "json"
    data["chunks"] = [
        {
            "url": "{{STORAGE_WIREMOCK_HTTP_HOST_WITH_PORT}}" + chunk_url_path,
            "rowCount": _SNOW_4109042_REMOTE_CHUNK_DECLARED,
            "uncompressedSize": 1,
            "compressedSize": 1,
        }
    ]

    remote_rows = [
        [str(i)]
        for i in range(
            _SNOW_4109042_FIRST_CHUNK_ROWS,
            _SNOW_4109042_FIRST_CHUNK_ROWS + _SNOW_4109042_REMOTE_CHUNK_ACTUAL,
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

    target_wm.import_mapping_with_default_placeholders(
        wiremock_mapping_dir / "auth/password/successful_flow.json"
    )
    target_wm.add_mapping(
        query_mapping,
        placeholders={
            "{{STORAGE_WIREMOCK_HTTP_HOST_WITH_PORT}}": target_wm.http_host_with_port,
        },
    )
    target_wm.add_mapping(chunk_mapping)
    target_wm.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    target_wm.add_mapping(wiremock_generic_mappings_dir / "telemetry.json")

    with snowflake.connector.connect(
        user="testUser",
        password="testPassword",
        account="testAccount",
        host=target_wm.wiremock_host,
        port=target_wm.wiremock_http_port,
        protocol="http",
        warehouse="TEST_WH",
        platform_detection_timeout_seconds=0,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM large_table")
            assert cur.rowcount == _SNOW_4109042_SERVER_ROWS
            assert len(cur._result_set.batches) == 2
            with pytest.raises(OperationalError) as ex:
                _rows_via_fetchmany(cur, size=100)

    assert target_wm.saw_urls_matching(
        ["snow-4109042"]
    ), "remote chunk was never downloaded; this would not mimic the ticket"
    assert ex.value.errno == ER_INCOMPLETE_RESULT_CHUNK
    assert (
        f"holds {_SNOW_4109042_REMOTE_CHUNK_ACTUAL} row(s) but the server reported "
        f"{_SNOW_4109042_REMOTE_CHUNK_DECLARED}" in ex.value.msg
    )


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

# "total rows = 954, first chunk rows = 79" and the client received 875 rows.
_TICKET_TOTAL = 954
_TICKET_INLINE_ROWS = 79
_TICKET_REMOTE_ROWS = _TICKET_TOTAL - _TICKET_INLINE_ROWS  # 875


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
        _TICKET_REMOTE_ROWS, _json_rows(_TICKET_REMOTE_ROWS, _TICKET_INLINE_ROWS)
    )
    cursor = _cursor_over_batches([_local_json_batch([]), remote], _TICKET_TOTAL)

    with patch.object(remote, "_download", return_value=response):
        with pytest.raises(OperationalError) as ex:
            _rows_via_fetchmany(cursor, size=100)

    assert ex.value.errno == ER_INCOMPLETE_RESULT_CHUNK
    assert (
        f"the result set produced {_TICKET_REMOTE_ROWS} row(s) but the server "
        f"reported {_TICKET_TOTAL}" in ex.value.msg
    )


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_empty_inline_arrow_chunk_with_healthy_remote_chunk_is_loud():
    """End to end on the Arrow path: 954 declared, 875 delivered, no silence.

    The inline chunk's own rowcount is server metadata here, so the batch-level
    check fires first -- either way the caller must not walk away with 875 rows.
    """
    remote, response = _remote_json_batch(
        _TICKET_REMOTE_ROWS, _json_rows(_TICKET_REMOTE_ROWS, _TICKET_INLINE_ROWS)
    )
    cursor = _cursor_over_batches(
        [_empty_inline_arrow_batch(_TICKET_INLINE_ROWS), remote], _TICKET_TOTAL
    )

    with patch.object(remote, "_download", return_value=response):
        with pytest.raises(OperationalError) as ex:
            _rows_via_fetchmany(cursor, size=100)

    assert ex.value.errno == ER_INCOMPLETE_RESULT_CHUNK


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_complete_result_set_does_not_raise():
    remote, response = _remote_json_batch(
        _TICKET_REMOTE_ROWS, _json_rows(_TICKET_REMOTE_ROWS, _TICKET_INLINE_ROWS)
    )
    cursor = _cursor_over_batches(
        [_local_json_batch(_json_rows(_TICKET_INLINE_ROWS)), remote], _TICKET_TOTAL
    )

    with patch.object(remote, "_download", return_value=response):
        assert len(_rows_via_fetchmany(cursor, size=100)) == _TICKET_TOTAL


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
        _TICKET_REMOTE_ROWS, _json_rows(_TICKET_REMOTE_ROWS, _TICKET_INLINE_ROWS)
    )
    cursor = _cursor_over_batches(
        [_local_json_batch(_json_rows(_TICKET_INLINE_ROWS)), remote], _TICKET_TOTAL
    )

    with patch.object(remote, "_download", return_value=response):
        assert len(cursor.fetchmany(10)) == 10
        # Dropping the half-consumed iterator is what closing a cursor does.
        cursor.reset()


@pytest.mark.skipolddriver
@pytestmark_result_set
def test_breaking_out_of_cursor_iteration_does_not_raise():
    remote, response = _remote_json_batch(
        _TICKET_REMOTE_ROWS, _json_rows(_TICKET_REMOTE_ROWS, _TICKET_INLINE_ROWS)
    )
    cursor = _cursor_over_batches(
        [_local_json_batch(_json_rows(_TICKET_INLINE_ROWS)), remote], _TICKET_TOTAL
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
        [_local_json_batch(_json_rows(_TICKET_INLINE_ROWS))], _TICKET_TOTAL
    )

    (batch,) = cursor.get_result_batches()

    assert len(list(batch)) == _TICKET_INLINE_ROWS
