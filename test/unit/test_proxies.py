#!/usr/bin/env python
from __future__ import annotations

import logging
import unittest.mock
from collections import deque

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


"""
Note: The single-target no_proxy test was removed in favor of
test_no_proxy_multiple_hosts_and_ports, which validates both backend and storage
paths and multiple no_proxy entries using shared session manager logic.
"""


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "no_proxy_factory,expect_backend_proxy,expect_storage_proxy",
    [
        (lambda target, storage: [f"localhost:{target}"], False, True),
        (lambda target, storage: [f"localhost:{storage}"], True, False),
        (
            lambda target, storage: [f"localhost:{target}", f"localhost:{storage}"],
            False,
            False,
        ),
        (
            lambda target, storage: ["localhost"],
            False,
            False,
        ),  # host-only bypasses both
        # Tuple and set variants
        (lambda target, storage: (f"localhost:{target}",), False, True),
        (lambda target, storage: {f"localhost:{storage}"}, True, False),
        (
            lambda target, storage: frozenset(
                {f"localhost:{target}", f"localhost:{storage}"}
            ),
            False,
            False,
        ),
        # Deque (generic iterable) variant
        (
            lambda target, storage: deque(
                [f"localhost:{target}", f"localhost:{storage}"]
            ),
            False,
            False,
        ),
        # One long CSV string with many irrelevant entries around both target and storage
        (
            lambda target, storage: (
                "foo.invalid:1,bar.invalid:2,"
                f"localhost:{target},"
                "baz.invalid:3,qux.invalid:4,"
                f"localhost:{storage},"
                "zoo.invalid:5"
            ),
            False,
            False,
        ),
    ],
)
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
def test_no_proxy_multiple_hosts_and_ports(
    wiremock_backend_storage_proxy,
    wiremock_generic_mappings_dir,
    wiremock_mapping_dir,
    proxy_env_vars,
    proxy_method,
    no_proxy_factory,
    expect_backend_proxy,
    expect_storage_proxy,
):
    target_wm, storage_wm, proxy_wm = wiremock_backend_storage_proxy

    # Configure DB and storage mappings (no Via header assertion; we check journals)
    password_mapping = wiremock_mapping_dir / "auth/password/successful_flow.json"
    multi_chunk_request_mapping = (
        wiremock_mapping_dir / "queries/select_large_request_successful.json"
    )
    chunk_1_mapping = wiremock_mapping_dir / "queries/chunk_1.json"
    chunk_2_mapping = wiremock_mapping_dir / "queries/chunk_2.json"
    disconnect_mapping = (
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    telemetry_mapping = wiremock_generic_mappings_dir / "telemetry.json"

    # Import login, disconnect, telemetry on backend
    target_wm.import_mapping_with_default_placeholders(password_mapping)
    target_wm.add_mapping(disconnect_mapping)
    target_wm.add_mapping(telemetry_mapping)

    # Add multi-chunk query response on backend, but point chunk URLs to storage host
    target_wm.add_mapping(
        multi_chunk_request_mapping,
        placeholders={
            "{{WIREMOCK_HTTP_HOST_WITH_PORT}}": storage_wm.http_host_with_port
        },
    )

    # Add chunk GET mappings to storage
    storage_wm.add_mapping_with_default_placeholders(chunk_1_mapping)
    storage_wm.add_mapping_with_default_placeholders(chunk_2_mapping)

    # Configure proxy env/args
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
            }
        )
        clear_proxy_env_vars()
    else:
        proxy_url = f"http://{proxy_wm.wiremock_host}:{proxy_wm.wiremock_http_port}"
        set_proxy_env_vars(proxy_url)

    # Build no_proxy (factory may return CSV string or any iterable)
    connect_kwargs["no_proxy"] = no_proxy_factory(
        target_wm.wiremock_http_port, storage_wm.wiremock_http_port
    )

    # Connect and perform DB query (will return chunk URLs to storage host)
    cnx = snowflake.connector.connect(**connect_kwargs)
    cur = cnx.cursor()
    cur.execute("SELECT 1")
    # Consume results to force chunk downloads
    _ = list(cur)

    # Simulate a storage(S3) GET using the same session manager (to honor connection's proxy settings)
    cnx._session_manager.get(f"{storage_wm.http_host_with_port}/__admin/health")

    cur.close()
    cnx.close()

    # Check proxy vs target/storage
    proxy_reqs = requests.get(f"{proxy_wm.http_host_with_port}/__admin/requests").json()
    target_reqs = requests.get(
        f"{target_wm.http_host_with_port}/__admin/requests"
    ).json()
    storage_reqs = requests.get(
        f"{storage_wm.http_host_with_port}/__admin/requests"
    ).json()

    # DB query expectation
    proxy_saw_db = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in proxy_reqs["requests"]
    )
    target_saw_db = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in target_reqs["requests"]
    )
    assert target_saw_db
    assert proxy_saw_db == expect_backend_proxy

    # Storage chunk GET expectation
    proxy_saw_storage = any(
        "/amazonaws/test/s3testaccount/stage/results/" in r["request"]["url"]
        for r in proxy_reqs["requests"]
    )
    storage_saw_storage = any(
        "/amazonaws/test/s3testaccount/stage/results/" in r["request"]["url"]
        for r in storage_reqs["requests"]
    )
    assert storage_saw_storage
    assert proxy_saw_storage == expect_storage_proxy

    # No extra CSV branch: connection code normalizes strings/iterables equivalently
