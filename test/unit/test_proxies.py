#!/usr/bin/env python
from __future__ import annotations

import logging
import os
import unittest.mock

import pytest

import snowflake.connector
import snowflake.connector.vendored.requests as requests
from snowflake.connector.errors import OperationalError


def test_get_proxy_url():
    from snowflake.connector.proxy import get_proxy_url

    assert get_proxy_url("host", "port", "user", "password") == (
        "http://user:password@host:port"
    )
    assert get_proxy_url("host", "port") == "http://host:port"

    assert get_proxy_url("http://host", "port") == "http://host:port"
    assert get_proxy_url("https://host", "port", "user", "password") == (
        "http://user:password@host:port"
    )


@pytest.mark.skipolddriver
def test_socks_5_proxy_missing_proxy_header_attribute(caplog):
    from snowflake.connector.vendored.urllib3.poolmanager import ProxyManager

    os.environ["HTTPS_PROXY"] = "socks5://localhost:8080"

    class MockSOCKSProxyManager:
        def __init__(self):
            pass

        def connection_from_url(self, url):
            pass

    def mock_proxy_manager_for_url_no_header(*args, **kwargs):
        return MockSOCKSProxyManager()

    def mock_proxy_manager_for_url_wiht_header(*args, **kwargs):
        return ProxyManager("testurl")

    # connection
    caplog.set_level(logging.DEBUG, "snowflake.connector")

    # bad path
    with unittest.mock.patch(
        "snowflake.connector.session_manager.ProxySupportAdapter.proxy_manager_for",
        mock_proxy_manager_for_url_no_header,
    ):
        with pytest.raises(OperationalError):
            snowflake.connector.connect(
                account="testaccount",
                user="testuser",
                password="testpassword",
                database="TESTDB",
                warehouse="TESTWH",
            )
    assert "Unable to set 'Host' to proxy manager of type" in caplog.text

    caplog.clear()

    # happy path
    with unittest.mock.patch(
        "snowflake.connector.session_manager.ProxySupportAdapter.proxy_manager_for",
        mock_proxy_manager_for_url_wiht_header,
    ):
        with pytest.raises(OperationalError):
            snowflake.connector.connect(
                account="testaccount",
                user="testuser",
                password="testpassword",
                database="TESTDB",
                warehouse="TESTWH",
            )
    assert "Unable to set 'Host' to proxy manager of type" not in caplog.text

    del os.environ["HTTPS_PROXY"]


@pytest.mark.skipolddriver
def test_basic_query_through_proxy(
    wiremock_generic_mappings_dir, wiremock_target_proxy_pair, wiremock_mapping_dir
):
    target_wm, proxy_wm = wiremock_target_proxy_pair

    password_mapping = wiremock_mapping_dir / "auth/password/successful_flow.json"
    select_mapping = wiremock_mapping_dir / "queries/select_1_successful.json"
    disconnect_mapping = (
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    telemetry_mapping = wiremock_generic_mappings_dir / "telemetry.json"

    target_wm.import_mapping(password_mapping)
    target_wm.add_mapping(select_mapping)
    target_wm.add_mapping(disconnect_mapping)
    target_wm.add_mapping(telemetry_mapping)

    # Make connection via proxy
    cnx = snowflake.connector.connect(
        user="testUser",
        password="testPassword",
        account="testAccount",
        host=target_wm.wiremock_host,
        port=target_wm.wiremock_http_port,
        protocol="http",
        warehouse="TEST_WH",
        proxy_host=proxy_wm.wiremock_host,
        proxy_port=str(proxy_wm.wiremock_http_port),
    )
    cur = cnx.cursor()
    cur.execute("SELECT 1")
    result = cur.fetchone()
    assert result[0] == 1
    cur.close()
    cnx.close()

    # Ensure proxy saw query
    proxy_reqs = requests.get(f"{proxy_wm.http_host_with_port}/__admin/requests").json()
    assert any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in proxy_reqs["requests"]
    )

    # Ensure backend saw query
    target_reqs = requests.get(
        f"{target_wm.http_host_with_port}/__admin/requests"
    ).json()
    assert any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in target_reqs["requests"]
    )
