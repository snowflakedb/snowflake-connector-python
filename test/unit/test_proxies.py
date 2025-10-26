#!/usr/bin/env python
from __future__ import annotations

import logging
import unittest.mock

import pytest

import snowflake.connector
import snowflake.connector.vendored.requests as requests
from snowflake.connector.errors import OperationalError


@pytest.mark.skipolddriver
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
def test_socks_5_proxy_missing_proxy_header_attribute(caplog, monkeypatch):
    from snowflake.connector.vendored.urllib3.poolmanager import ProxyManager

    monkeypatch.setenv("HTTPS_PROXY", "socks5://localhost:8080")

    class MockSOCKSProxyManager:
        def __init__(self):
            pass

        def connection_from_url(self, url):
            pass

        def connection_from_host(self, host, *args, **kwargs):
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


@pytest.mark.skipolddriver
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
def test_basic_query_through_proxy(
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
    proxy_env_vars,
    proxy_method,
):
    target_wm, proxy_wm = wiremock_target_proxy_pair

    password_mapping = wiremock_mapping_dir / "auth/password/successful_flow.json"
    select_mapping = wiremock_mapping_dir / "queries/select_1_successful.json"
    disconnect_mapping = (
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    telemetry_mapping = wiremock_generic_mappings_dir / "telemetry.json"

    # Use expected headers to ensure requests go through proxy
    expected_headers = {"Via": {"contains": "wiremock"}}

    target_wm.import_mapping_with_default_placeholders(
        password_mapping, expected_headers
    )
    target_wm.add_mapping_with_default_placeholders(select_mapping, expected_headers)
    target_wm.add_mapping(disconnect_mapping)
    target_wm.add_mapping(telemetry_mapping)

    # Configure proxy based on test parameter
    set_proxy_env_vars, clear_proxy_env_vars = proxy_env_vars
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

    if proxy_method == "explicit_args":
        connect_kwargs.update(
            {
                "proxy_host": proxy_wm.wiremock_host,
                "proxy_port": str(proxy_wm.wiremock_http_port),
            }
        )
        clear_proxy_env_vars()  # Ensure no env vars interfere
    else:  # env_vars
        proxy_url = f"http://{proxy_wm.wiremock_host}:{proxy_wm.wiremock_http_port}"
        set_proxy_env_vars(proxy_url)

    # Make connection via proxy
    cnx = snowflake.connector.connect(**connect_kwargs)
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


@pytest.mark.skipolddriver
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
def test_large_query_through_proxy(
    wiremock_generic_mappings_dir,
    wiremock_target_proxy_pair,
    wiremock_mapping_dir,
    proxy_env_vars,
    proxy_method,
):
    target_wm, proxy_wm = wiremock_target_proxy_pair

    password_mapping = wiremock_mapping_dir / "auth/password/successful_flow.json"
    multi_chunk_request_mapping = (
        wiremock_mapping_dir / "queries/select_large_request_successful.json"
    )
    disconnect_mapping = (
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    telemetry_mapping = wiremock_generic_mappings_dir / "telemetry.json"
    chunk_1_mapping = wiremock_mapping_dir / "queries/chunk_1.json"
    chunk_2_mapping = wiremock_mapping_dir / "queries/chunk_2.json"

    # Configure mappings with proxy header verification
    expected_headers = {"Via": {"contains": "wiremock"}}

    target_wm.import_mapping(password_mapping, expected_headers=expected_headers)
    target_wm.add_mapping_with_default_placeholders(
        multi_chunk_request_mapping, expected_headers
    )
    target_wm.add_mapping(disconnect_mapping, expected_headers=expected_headers)
    target_wm.add_mapping(telemetry_mapping, expected_headers=expected_headers)
    target_wm.add_mapping_with_default_placeholders(chunk_1_mapping, expected_headers)
    target_wm.add_mapping_with_default_placeholders(chunk_2_mapping, expected_headers)

    # Configure proxy based on test parameter
    set_proxy_env_vars, clear_proxy_env_vars = proxy_env_vars
    connect_kwargs = {
        "user": "testUser",
        "password": "testPassword",
        "account": "testAccount",
        "host": target_wm.wiremock_host,
        "port": target_wm.wiremock_http_port,
        "protocol": "http",
        "warehouse": "TEST_WH",
    }

    if proxy_method == "explicit_args":
        connect_kwargs.update(
            {
                "proxy_host": proxy_wm.wiremock_host,
                "proxy_port": str(proxy_wm.wiremock_http_port),
                "proxy_user": "proxyUser",
                "proxy_password": "proxyPass",
            }
        )
        clear_proxy_env_vars()  # Ensure no env vars interfere
    else:  # env_vars
        proxy_url = f"http://proxyUser:proxyPass@{proxy_wm.wiremock_host}:{proxy_wm.wiremock_http_port}"
        set_proxy_env_vars(proxy_url)

    row_count = 50_000
    with snowflake.connector.connect(**connect_kwargs) as conn:
        cursors = conn.execute_string(
            f"select seq4() as n from table(generator(rowcount => {row_count}));"
        )
        assert len(cursors[0]._result_set.batches) > 1  # We need to have remote results
    assert list(cursors[0])

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
