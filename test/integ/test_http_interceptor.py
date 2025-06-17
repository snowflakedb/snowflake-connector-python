import pathlib
from typing import Deque

import pytest

from snowflake.connector import SnowflakeConnection

from ..test_utils.http_test_utils import RequestTracker
from .test_large_result_set import ingest_data  # NOQA

try:
    from snowflake.connector.http_interceptor import RequestDTO
except ImportError:  # Keep olddrivertest from breaking
    pass


@pytest.fixture(scope="session")
def wiremock_auth_dir(wiremock_mapping_dir) -> pathlib.Path:
    return wiremock_mapping_dir / "auth"


@pytest.fixture(scope="session")
def wiremock_queries_dir(wiremock_mapping_dir) -> pathlib.Path:
    return wiremock_mapping_dir / "queries"


@pytest.fixture(scope="session")
def wiremock_password_auth_dir(wiremock_auth_dir) -> pathlib.Path:
    return wiremock_auth_dir / "password"


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
    # TODO: this does not collect retried requests - uses static collector

    # TODO: finish this comment
    # By covering in this way (wiremock + real server) the request we make sure that we will detect if in the future new requests are added and wiremock does not reflect them
    # Prevents duplication and makes sure all requests are covered
    # Detects if interceptor correctly works collecting all the requests that should occur.
    # Detects if all expected requests occur AND NO OTHER.
    # If added new steps that should generate http traffic it will detect those and raise an error.
    # If needed to inspect what requests are occuring use this test or similar and add those asserts

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

    # TODO: add here checks if headers added to each request
    # TODO: e.g. get all requests from wiremock (its endpoint) and chcek if they had headers
    # Perform GET request through Snowflake’s internal session
    # response = rest._session.get(f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/echo-headers")
    # response.raise_for_status()
    # content = response.json()

    # Validate that the custom header was added
    # headers = {k.lower(): v for k, v in content.items()}
    # assert any("test-header-value" in v for v in headers.values()), "Custom header not found in response"


# def test_wiremock_received_all_requests_with_headers
#     EXCLUDED_REGEXPS = [..]

# def test_


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
