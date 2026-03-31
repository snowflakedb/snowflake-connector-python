"""WireMock integration tests for HTTP 307/308 redirect retry behavior.

These tests verify that when a Snowflake query receives a 307/308 redirect
(e.g. from an internal Envoy proxy), the connector retries the original
request and eventually succeeds.

See SNOW-1997074 and cross-driver epic #1325.
"""

import pathlib

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


@pytest.mark.parametrize(
    "status_code,mapping_file",
    [
        (307, "http_307_retry.json"),
        (308, "http_308_retry.json"),
    ],
)
def test_http_redirect_retry(
    wiremock_client: WiremockClient, status_code, mapping_file
):
    """Test that a query succeeds after a 307/308 redirect triggers a retry.

    Scenario:
    1. Login succeeds
    2. First query gets a redirect (307/308) to a target that delays (timeout)
    3. Timeout triggers a retry to the original URL
    4. Retry returns a successful query result
    """
    wiremock_client.import_mapping(WIREMOCK_REDIRECT_DIR / mapping_file)

    cnx = _connect_to_wiremock(wiremock_client, socket_timeout=3)
    try:
        cursor = cnx.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        assert result == (1,), f"Expected (1,) but got {result}"
    finally:
        cnx.close()
