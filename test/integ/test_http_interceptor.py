import os
import pathlib
from typing import Deque

import pytest

from snowflake.connector import SnowflakeConnection

from ..generate_test_files import generate_k_lines_of_n_files
from ..test_utils.http_test_utils import RequestTracker
from .test_large_result_set import ingest_data  # NOQA

try:
    from snowflake.connector.http_interceptor import RequestDTO
    from snowflake.connector.util_text import random_string

except (ImportError, NameError):  # Keep olddrivertest from breaking
    from ..randomize import random_string


@pytest.fixture(scope="session")
def wiremock_auth_dir(wiremock_mapping_dir) -> pathlib.Path:
    return wiremock_mapping_dir / "auth"


@pytest.fixture(scope="session")
def wiremock_queries_dir(wiremock_mapping_dir) -> pathlib.Path:
    return wiremock_mapping_dir / "queries"


@pytest.fixture(scope="session")
def wiremock_password_auth_dir(wiremock_auth_dir) -> pathlib.Path:
    return wiremock_auth_dir / "password"


@pytest.fixture(scope="session")
def current_provider():
    return os.getenv("cloud_provider", "dev")


@pytest.mark.parametrize("execute_on_wiremock", (True, False))
@pytest.mark.skipolddriver
def test_interceptor_detects_expected_requests_in_successful_flow_select_1(
    request,
    execute_on_wiremock,
    wiremock_password_auth_dir,
    wiremock_generic_mappings_dir,
    wiremock_queries_dir,
    static_collecting_customizer,
    conn_cnx,
    conn_cnx_wiremock,
) -> None:
    """
    This kind of test ensures that the request interceptor correctly captures all expected HTTP requests
    during a known use-case scenario of the driver.

    By covering both real and mock (WireMock) executions via the `execute_on_wiremock` param,
    we validate two critical things:
    1. **Real execution**: Interceptor must detect and log every actual request in a live environment.
    2. **WireMock execution**: Verifies that the stubbed mappings in WireMock match the current behavior
       of the driver, so any future API changes (added/removed requests) will cause the test to fail.

    This dual setup:
    - Prevents stale mocks (detects missing or extra requests not aligned with the driver).
    - Guarantees that the interceptor observes requests **in correct order** and no unexpected traffic occurs.
    - Ensures the customizer receives all invocations and no requests go untracked.

    If new driver code introduces additional HTTP calls, this test will fail until WireMock is updated
    to reflect them, prompting to verify those new requests in the flow.
    """

    def assert_expected_requests_occurred(conn: SnowflakeConnection) -> None:
        requests: Deque[RequestDTO] = static_collecting_customizer.invocations
        tracker = RequestTracker(requests)

        with conn as connection_context:
            tracker.assert_login_issued()
            cursor = connection_context.cursor().execute("select 1")
            tracker.assert_sql_query_issued()

            result = cursor.fetchall()
            assert len(result) == 1, "Result should contain exactly one row"
            assert (
                result[0][0] == 1
            ), "Result should contain the value 1 in the first row and the first column"

        tracker.assert_telemetry_send_issued()
        tracker.assert_disconnect_issued()

    if execute_on_wiremock:
        local_wiremock_client = request.getfixturevalue("wiremock_client")
        local_wiremock_client.import_mapping(
            wiremock_password_auth_dir / "successful_flow.json"
        )
        local_wiremock_client.add_mapping(
            wiremock_queries_dir / "select_1_successful.json"
        )
        local_wiremock_client.add_mapping(
            wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
        )
        local_wiremock_client.add_mapping(
            wiremock_generic_mappings_dir / "telemetry.json"
        )

        connection = conn_cnx_wiremock(
            headers_customizers=[static_collecting_customizer]
        )
    else:
        connection = conn_cnx(headers_customizers=[static_collecting_customizer])

    assert_expected_requests_occurred(connection)


@pytest.mark.parametrize("execute_on_wiremock", (True, False))
@pytest.mark.skipolddriver
def test_interceptor_detects_expected_requests_in_successful_flow_with_chunks(
    request,
    execute_on_wiremock,
    wiremock_password_auth_dir,
    wiremock_generic_mappings_dir,
    wiremock_queries_dir,
    static_collecting_customizer,
    conn_cnx,
    conn_cnx_wiremock,
    db_parameters,
    default_db_wiremock_parameters,
) -> None:

    def assert_expected_requests_occurred(
        conn: SnowflakeConnection, expected_large_table_name: str
    ) -> None:
        requests: Deque[RequestDTO] = static_collecting_customizer.invocations
        tracker = RequestTracker(requests)

        with conn as connection_context:
            tracker.assert_login_issued()
            sql = f"select * from {expected_large_table_name} order by 1"
            cursor = connection_context.cursor().execute(sql)
            tracker.assert_sql_query_issued()
            cursor.fetchall()
            tracker.assert_get_chunk_issued()

        tracker.assert_telemetry_send_issued()
        tracker.assert_disconnect_issued()

    if execute_on_wiremock:
        local_wiremock_client = request.getfixturevalue("wiremock_client")
        local_wiremock_client.import_mapping(
            wiremock_password_auth_dir / "successful_flow.json"
        )
        local_wiremock_client.add_mapping(
            wiremock_queries_dir / "select_large_request_successful.json",
            placeholders=local_wiremock_client.http_placeholders,
        )
        local_wiremock_client.add_mapping(
            wiremock_queries_dir / "chunk_1.json",
            placeholders=local_wiremock_client.http_placeholders,
        )
        local_wiremock_client.add_mapping(
            wiremock_queries_dir / "chunk_2.json",
            placeholders=local_wiremock_client.http_placeholders,
        )
        local_wiremock_client.add_mapping(
            wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
        )
        local_wiremock_client.add_mapping(
            wiremock_generic_mappings_dir / "telemetry.json"
        )

        connection = conn_cnx_wiremock(
            headers_customizers=[static_collecting_customizer]
        )
        large_table_name = default_db_wiremock_parameters["name"]
    else:
        request.getfixturevalue("ingest_data")
        connection = conn_cnx(headers_customizers=[static_collecting_customizer])
        large_table_name = db_parameters["name"]

    assert_expected_requests_occurred(connection, large_table_name)


@pytest.mark.skipolddriver
def test_interceptor_detects_expected_requests_in_successful_flow_put_get(
    tmp_path: pathlib.Path,
    static_collecting_customizer,
    conn_cnx,
    current_provider,
):
    def _assert_expected_requests_occurred(conn: SnowflakeConnection) -> None:
        requests: Deque[RequestDTO] = static_collecting_customizer.invocations
        tracker = RequestTracker(requests)

        test_file = tmp_path / "single_part.txt"
        test_file.write_text("test,data\n")
        download_dir = tmp_path / "download"
        download_dir.mkdir()
        stage_name = random_string(5, "test_put_get_")

        with conn as cxn:
            with cxn.cursor() as cursor:
                tracker.assert_login_issued()

                cursor.execute(f"create temporary stage {stage_name}")
                tracker.assert_sql_query_issued()

                put_sql = f"PUT file://{test_file} @{stage_name} AUTO_COMPRESS = FALSE"
                cursor.execute(put_sql)
                tracker.assert_sql_query_issued()
                if current_provider in ("aws", "dev"):
                    tracker.assert_aws_get_accelerate_issued(optional=True)

                tracker.assert_file_head_issued(test_file.name)
                tracker.assert_put_file_issued(cloud_platform=current_provider)

                get_sql = f"GET @{stage_name}/{test_file.name} file://{download_dir}"
                cursor.execute(get_sql)
                tracker.assert_sql_query_issued()
                if current_provider in ("aws", "dev"):
                    tracker.assert_aws_get_accelerate_issued(optional=True)
                tracker.assert_file_head_issued(test_file.name)
                tracker.assert_get_file_issued(test_file.name)

        tracker.assert_telemetry_send_issued()
        tracker.assert_disconnect_issued()

    connection = conn_cnx(headers_customizers=[static_collecting_customizer])
    _assert_expected_requests_occurred(connection)


@pytest.mark.aws
@pytest.mark.azure
@pytest.mark.skipolddriver
def test_interceptor_detects_expected_requests_in_successful_multipart_put_get(
    tmp_path: pathlib.Path,
    static_collecting_customizer,
    dynamic_collecting_customizer,
    conn_cnx,
    current_provider,
):
    """Verifies request flow for multipart PUT and GET of a large file, with MD5 check and optional WireMock."""

    def _assert_expected_requests_occurred_multipart(
        connection: SnowflakeConnection,
    ) -> None:
        requests: Deque[RequestDTO] = static_collecting_customizer.invocations
        tracker = RequestTracker(requests)

        big_folder = tmp_path / "big"
        big_folder.mkdir()
        generate_k_lines_of_n_files(3_000_000, 1, tmp_dir=str(big_folder))
        big_test_file = big_folder / "file0"

        stage_name = random_string(5, "test_multipart_put_get_")
        stage_path = "bigdata"
        download_dir = tmp_path / "download"
        download_dir.mkdir()
        big_test_file_stage_path = f"{stage_path}/{big_test_file.name}"

        with connection as cnx:
            with cnx.cursor() as cur:
                tracker.assert_login_issued()

                cur.execute(f"create temporary stage {stage_name}")
                tracker.assert_sql_query_issued()

                clean_file_path = str(big_test_file).replace("\\", "/")
                cur.execute(
                    f"PUT 'file://{clean_file_path}' "
                    f"@{stage_name}/{stage_path} AUTO_COMPRESS=FALSE"
                )
                tracker.assert_sql_query_issued()
                if current_provider in ("aws", "dev"):
                    tracker.assert_aws_get_accelerate_issued(optional=True)

                tracker.assert_file_head_issued(big_test_file.name, sequentially=False)

                if current_provider in ("aws", "dev"):
                    tracker.assert_post_start_for_multipart_file_issued(
                        sequentially=False, file_path=big_test_file_stage_path
                    )

                tracker.assert_multiple_put_file_issued(
                    big_test_file.name, current_provider, sequentially=False
                )
                tracker.assert_end_for_multipart_file_issued(
                    cloud_platform=current_provider
                )

                cur.execute(
                    f"GET @{stage_name}/{big_test_file_stage_path} file://{download_dir}"
                )
                tracker.assert_sql_query_issued()
                if current_provider in ("aws", "dev"):
                    tracker.assert_aws_get_accelerate_issued(optional=True)
                tracker.assert_file_head_issued(big_test_file.name)
                tracker.assert_get_file_issued(big_test_file.name)

        tracker.assert_telemetry_send_issued()
        tracker.assert_disconnect_issued()

    conn = conn_cnx(
        headers_customizers=[
            static_collecting_customizer,
            dynamic_collecting_customizer,
        ]
    )
    try:
        _assert_expected_requests_occurred_multipart(conn)
    except AssertionError as ex:
        list_of_inv = (
            str(ex)
            + "\n\n"
            + str(
                "\n".join(
                    map(
                        lambda r: f"{r.method} {r.url}",
                        dynamic_collecting_customizer.invocations,
                    )
                )
            )
        )
        print(list_of_inv)
        raise AssertionError(list_of_inv)
