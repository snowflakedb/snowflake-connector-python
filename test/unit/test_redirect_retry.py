"""WireMock integration tests for HTTP 307/308 redirect retry behavior.

These tests verify that when a Snowflake query receives a 307/308 redirect
(e.g. from an internal Envoy proxy), the connector retries the original
request and eventually succeeds.

See SNOW-1997074 and cross-driver epic #1325.
"""

import pathlib
import re

import pytest

import snowflake.connector

from ..test_utils.wiremock.wiremock_utils import WiremockClient

pytestmark = pytest.mark.skipolddriver

WIREMOCK_REDIRECT_DIR = (
    pathlib.Path(__file__).parent.parent / "data" / "wiremock" / "mappings" / "redirect"
)


def _connect_to_wiremock(wiremock_client: WiremockClient, **kwargs):
    """Create a connection pointed at the WireMock server."""
    return snowflake.connector.connect(
        account="testAccount",
        user="testUser",
        password="testPassword",
        host=wiremock_client.wiremock_host,
        port=wiremock_client.wiremock_http_port,
        protocol="http",
        **kwargs,
    )


def _count_requests_matching(wiremock_client: WiremockClient, url_pattern: str) -> int:
    """Count WireMock requests whose URL matches the given regex pattern."""
    journal = wiremock_client.get_requests()
    return sum(
        1 for r in journal["requests"] if re.search(url_pattern, r["request"]["url"])
    )


@pytest.mark.parametrize(
    "status_code,mapping_file,expected_query_id",
    [
        (307, "http_307_retry.json", "redirect-test-query-id-307"),
        (308, "http_308_retry.json", "redirect-test-query-id-308"),
    ],
)
def test_http_redirect_retry(
    wiremock_client: WiremockClient, status_code, mapping_file, expected_query_id
):
    """Test that a query succeeds after a 307/308 redirect triggers a retry.

    Scenario:
    1. Login succeeds
    2. First query gets a redirect (307/308) to a target that delays (timeout)
    3. Timeout triggers a retry to the original URL
    4. Retry returns a successful query result

    Verified via WireMock request journal (like JDBC verifyRequestCount):
    - Exactly 2 POSTs to /queries/v1/query-request (original + retry)
    - At least 1 POST to /temp-redirect-target (redirect was followed)
    - Response queryId matches the retry scenario state (like .NET)
    """
    wiremock_client.import_mapping(WIREMOCK_REDIRECT_DIR / mapping_file)

    cnx = _connect_to_wiremock(wiremock_client, socket_timeout=3)
    try:
        cursor = cnx.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        assert result == (1,), f"Expected (1,) but got {result}"

        # Verify response came from the retry scenario state (like .NET AssertResponseId)
        assert (
            cursor.sfqid == expected_query_id
        ), f"Expected queryId '{expected_query_id}' from retry state, got '{cursor.sfqid}'"
    finally:
        cnx.close()

    # Verify WireMock request journal (like JDBC verifyRequestCount)
    query_request_count = _count_requests_matching(
        wiremock_client, r"/queries/v1/query-request"
    )
    redirect_target_count = _count_requests_matching(
        wiremock_client, r"/temp-redirect-target"
    )

    assert query_request_count == 2, (
        f"Expected exactly 2 requests to query endpoint (original + retry), "
        f"got {query_request_count}"
    )
    assert redirect_target_count >= 1, (
        f"Expected at least 1 request to redirect target "
        f"(proving redirect was followed), got {redirect_target_count}"
    )
