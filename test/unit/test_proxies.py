#!/usr/bin/env python
from __future__ import annotations

import logging
import os
import unittest.mock
from collections import deque
from typing import NamedTuple

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
    target_wm.add_mapping(
        multi_chunk_request_mapping,
        placeholders={
            "{{STORAGE_WIREMOCK_HTTP_HOST_WITH_PORT}}": target_wm.http_host_with_port
        },
        expected_headers=expected_headers,
    )
    target_wm.add_mapping(disconnect_mapping, expected_headers=expected_headers)
    target_wm.add_mapping(telemetry_mapping, expected_headers=expected_headers)
    target_wm.add_mapping_with_default_placeholders(chunk_1_mapping, expected_headers)
    target_wm.add_mapping_with_default_placeholders(chunk_2_mapping, expected_headers)

    # Configure proxy based on test parameter using helpers
    connect_kwargs = _base_connect_kwargs(target_wm)
    _configure_proxy(
        connect_kwargs,
        proxy_wm,
        proxy_env_vars,
        proxy_method,
        proxy_auth=("proxyUser", "proxyPass"),
    )

    row_count = 50_000
    _execute_large_query(connect_kwargs, row_count)

    # Ensure proxy saw query
    flags = _collect_db_request_flags_only(proxy_wm, target_wm)
    assert flags.proxy_saw_db

    # Ensure backend saw query
    assert flags.target_saw_db


def _setup_backend_storage_mappings(
    target_wm,
    storage_wm,
    proxy_wm,
    wiremock_mapping_dir,
    wiremock_generic_mappings_dir,
):
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

    target_wm.import_mapping_with_default_placeholders(password_mapping)
    target_wm.add_mapping(disconnect_mapping)
    target_wm.add_mapping(telemetry_mapping)
    target_wm.add_mapping(
        multi_chunk_request_mapping,
        placeholders={
            "{{STORAGE_WIREMOCK_HTTP_HOST_WITH_PORT}}": storage_wm.http_host_with_port
        },
    )

    storage_wm.add_mapping_with_default_placeholders(chunk_1_mapping)
    storage_wm.add_mapping_with_default_placeholders(chunk_2_mapping)

    proxy_wm.add_mapping(
        {
            "request": {"method": "ANY", "urlPathPattern": "/amazonaws/.*"},
            "response": {"proxyBaseUrl": storage_wm.http_host_with_port},
        }
    )


def _base_connect_kwargs(target_wm):
    return {
        "user": "testUser",
        "password": "testPassword",
        "account": "testAccount",
        "host": target_wm.wiremock_host,
        "port": target_wm.wiremock_http_port,
        "protocol": "http",
        "warehouse": "TEST_WH",
        "platform_detection_timeout_seconds": 0,
    }


def _configure_proxy(
    connect_kwargs,
    proxy_wm,
    proxy_env_vars,
    proxy_method,
    proxy_auth: tuple[str, str] | None = None,
):
    set_proxy_env_vars, clear_proxy_env_vars = proxy_env_vars
    if proxy_method == "explicit_args":
        connect_kwargs.update(
            {
                "proxy_host": proxy_wm.wiremock_host,
                "proxy_port": str(proxy_wm.wiremock_http_port),
            }
        )
        if proxy_auth is not None:
            user, password = proxy_auth
            connect_kwargs.update({"proxy_user": user, "proxy_password": password})
        clear_proxy_env_vars()
    else:
        if proxy_auth is not None:
            user, password = proxy_auth
            proxy_url = f"http://{user}:{password}@{proxy_wm.wiremock_host}:{proxy_wm.wiremock_http_port}"
        else:
            proxy_url = f"http://{proxy_wm.wiremock_host}:{proxy_wm.wiremock_http_port}"
        set_proxy_env_vars(proxy_url)


def _apply_no_proxy(no_proxy_source, no_proxy_value, connect_kwargs):
    if no_proxy_source == "param":
        connect_kwargs["no_proxy"] = no_proxy_value
    else:
        os.environ["NO_PROXY"] = (
            no_proxy_value
            if isinstance(no_proxy_value, str)
            else ",".join(no_proxy_value)
        )


def _execute_large_query(connect_kwargs, row_count: int):
    with snowflake.connector.connect(**connect_kwargs) as conn:
        cursors = conn.execute_string(
            f"select seq4() as n from table(generator(rowcount => {row_count}));"
        )
        assert len(cursors[0]._result_set.batches) > 1
    assert list(cursors[0])


class RequestFlags(NamedTuple):
    proxy_saw_db: bool
    target_saw_db: bool
    proxy_saw_storage: bool
    storage_saw_storage: bool


def _collect_request_flags(proxy_wm, target_wm, storage_wm) -> RequestFlags:
    proxy_reqs = requests.get(f"{proxy_wm.http_host_with_port}/__admin/requests").json()
    target_reqs = requests.get(
        f"{target_wm.http_host_with_port}/__admin/requests"
    ).json()
    storage_reqs = requests.get(
        f"{storage_wm.http_host_with_port}/__admin/requests"
    ).json()

    proxy_saw_db = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in proxy_reqs["requests"]
    )
    target_saw_db = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in target_reqs["requests"]
    )
    proxy_saw_storage = any(
        "/amazonaws/test/s3testaccount/stage/results/" in r["request"]["url"]
        for r in proxy_reqs["requests"]
    )
    storage_saw_storage = any(
        "/amazonaws/test/s3testaccount/stage/results/" in r["request"]["url"]
        for r in storage_reqs["requests"]
    )
    return RequestFlags(
        proxy_saw_db=proxy_saw_db,
        target_saw_db=target_saw_db,
        proxy_saw_storage=proxy_saw_storage,
        storage_saw_storage=storage_saw_storage,
    )


class DbRequestFlags(NamedTuple):
    proxy_saw_db: bool
    target_saw_db: bool


def _collect_db_request_flags_only(proxy_wm, target_wm) -> DbRequestFlags:
    proxy_reqs = requests.get(f"{proxy_wm.http_host_with_port}/__admin/requests").json()
    target_reqs = requests.get(
        f"{target_wm.http_host_with_port}/__admin/requests"
    ).json()
    proxy_saw_db = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in proxy_reqs["requests"]
    )
    target_saw_db = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in target_reqs["requests"]
    )
    return DbRequestFlags(proxy_saw_db=proxy_saw_db, target_saw_db=target_saw_db)


@pytest.mark.skipolddriver
@pytest.mark.parametrize("no_proxy_source", ["param", "env"])
def test_no_proxy_bypass_storage(
    wiremock_backend_storage_proxy,
    wiremock_generic_mappings_dir,
    wiremock_mapping_dir,
    proxy_env_vars,
    no_proxy_source,
    host_port_pooling,
):
    target_wm, storage_wm, proxy_wm = wiremock_backend_storage_proxy

    _setup_backend_storage_mappings(
        target_wm,
        storage_wm,
        proxy_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
    )

    connect_kwargs = _base_connect_kwargs(target_wm)
    connect_kwargs.update(
        {
            "proxy_host": proxy_wm.wiremock_host,
            "proxy_port": str(proxy_wm.wiremock_http_port),
        }
    )
    _, clear_proxy_env_vars = proxy_env_vars
    clear_proxy_env_vars()

    no_proxy_value = f"{storage_wm.wiremock_host}:{storage_wm.wiremock_http_port}"
    _apply_no_proxy(no_proxy_source, no_proxy_value, connect_kwargs)

    _execute_large_query(connect_kwargs, row_count=50_000)

    flags = _collect_request_flags(proxy_wm, target_wm, storage_wm)
    assert flags.target_saw_db
    assert flags.proxy_saw_db is True
    assert flags.storage_saw_storage
    assert flags.proxy_saw_storage is False


@pytest.mark.skipolddriver
@pytest.mark.parametrize("no_proxy_source", ["param", "env"])
def test_no_proxy_basic_param_proxy_bypass_backend(
    wiremock_backend_storage_proxy,
    wiremock_generic_mappings_dir,
    wiremock_mapping_dir,
    proxy_env_vars,
    no_proxy_source,
    host_port_pooling,
):
    target_wm, storage_wm, proxy_wm = wiremock_backend_storage_proxy

    _setup_backend_storage_mappings(
        target_wm,
        storage_wm,
        proxy_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
    )

    connect_kwargs = _base_connect_kwargs(target_wm)
    connect_kwargs.update(
        {
            "proxy_host": proxy_wm.wiremock_host,
            "proxy_port": str(proxy_wm.wiremock_http_port),
        }
    )
    _, clear_proxy_env_vars = proxy_env_vars
    clear_proxy_env_vars()

    no_proxy_value = f"{target_wm.wiremock_host}:{target_wm.wiremock_http_port}"
    _apply_no_proxy(no_proxy_source, no_proxy_value, connect_kwargs)

    _execute_large_query(connect_kwargs, row_count=50_000)

    flags = _collect_request_flags(proxy_wm, target_wm, storage_wm)
    assert flags.target_saw_db
    assert flags.proxy_saw_db is False
    assert flags.storage_saw_storage
    assert flags.proxy_saw_storage is True


@pytest.mark.skipolddriver
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
@pytest.mark.parametrize("no_proxy_source", ["param", "env"])
def test_no_proxy_source_vs_proxy_method_matrix(
    wiremock_backend_storage_proxy,
    wiremock_generic_mappings_dir,
    wiremock_mapping_dir,
    proxy_env_vars,
    proxy_method,
    no_proxy_source,
    host_port_pooling,
):
    if proxy_method == "env_vars" and no_proxy_source == "param":
        pytest.xfail(
            "Mixed setup of proxy using env_vars and connection params at the same time is unpredictable and not supported."
        )

    target_wm, storage_wm, proxy_wm = wiremock_backend_storage_proxy
    _setup_backend_storage_mappings(
        target_wm,
        storage_wm,
        proxy_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
    )

    connect_kwargs = _base_connect_kwargs(target_wm)
    _configure_proxy(connect_kwargs, proxy_wm, proxy_env_vars, proxy_method)

    no_proxy_value = f"{storage_wm.wiremock_host}:{storage_wm.wiremock_http_port}"
    _apply_no_proxy(no_proxy_source, no_proxy_value, connect_kwargs)

    _execute_large_query(connect_kwargs, row_count=50_000)

    flags = _collect_request_flags(proxy_wm, target_wm, storage_wm)
    assert flags.target_saw_db
    assert flags.proxy_saw_db is True
    assert flags.storage_saw_storage
    assert flags.proxy_saw_storage is False


@pytest.mark.skipolddriver
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
@pytest.mark.parametrize("no_proxy_source", ["param", "env"])
def test_no_proxy_backend_matrix(
    wiremock_backend_storage_proxy,
    wiremock_generic_mappings_dir,
    wiremock_mapping_dir,
    proxy_env_vars,
    proxy_method,
    no_proxy_source,
    host_port_pooling,
):
    if proxy_method == "env_vars" and no_proxy_source == "param":
        pytest.xfail(
            "Mixed setup of proxy using env_vars and connection params at the same time is unpredictable and not supported."
        )

    target_wm, storage_wm, proxy_wm = wiremock_backend_storage_proxy
    _setup_backend_storage_mappings(
        target_wm,
        storage_wm,
        proxy_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
    )

    connect_kwargs = _base_connect_kwargs(target_wm)
    _configure_proxy(connect_kwargs, proxy_wm, proxy_env_vars, proxy_method)

    no_proxy_value = f"{target_wm.wiremock_host}:{target_wm.wiremock_http_port}"
    _apply_no_proxy(no_proxy_source, no_proxy_value, connect_kwargs)

    _execute_large_query(connect_kwargs, row_count=50_000)

    flags = _collect_request_flags(proxy_wm, target_wm, storage_wm)
    assert flags.target_saw_db
    assert flags.proxy_saw_db is False
    assert flags.storage_saw_storage
    assert flags.proxy_saw_storage is True


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "no_proxy_factory",
    [
        (lambda storage_host, storage_port: f"{storage_host}:{storage_port}"),  # string
        (
            lambda storage_host, storage_port: f"foo.invalid:1,{storage_host}:{storage_port},bar.invalid:2"
        ),  # CSV string
        (lambda storage_host, storage_port: [f"{storage_host}:{storage_port}"]),  # list
        (
            lambda storage_host, storage_port: (f"{storage_host}:{storage_port}",)
        ),  # tuple
        (
            lambda storage_host, storage_port: deque([f"{storage_host}:{storage_port}"])
        ),  # deque
        (lambda storage_host, storage_port: {f"{storage_host}:{storage_port}"}),  # set
    ],
)
def test_no_proxy_multiple_values_param_only(
    wiremock_backend_storage_proxy,
    wiremock_generic_mappings_dir,
    wiremock_mapping_dir,
    proxy_env_vars,
    no_proxy_factory,
):
    target_wm, storage_wm, proxy_wm = wiremock_backend_storage_proxy
    _setup_backend_storage_mappings(
        target_wm,
        storage_wm,
        proxy_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
    )

    connect_kwargs = _base_connect_kwargs(target_wm)
    connect_kwargs.update(
        {
            "proxy_host": proxy_wm.wiremock_host,
            "proxy_port": str(proxy_wm.wiremock_http_port),
        }
    )
    _, clear_proxy_env_vars = proxy_env_vars
    clear_proxy_env_vars()

    # Factories accept (storage_host, storage_port) in this exact order
    no_proxy_value = no_proxy_factory(
        storage_wm.wiremock_host,
        storage_wm.wiremock_http_port,
    )
    connect_kwargs["no_proxy"] = no_proxy_value

    _execute_large_query(connect_kwargs, row_count=50_000)

    proxy_saw_db, target_saw_db, proxy_saw_storage, storage_saw_storage = (
        _collect_request_flags(proxy_wm, target_wm, storage_wm)
    )
    assert target_saw_db
    assert proxy_saw_db is True
    assert storage_saw_storage
    assert proxy_saw_storage is False


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "no_proxy_factory",
    [
        # Both backend and storage bypassed via list
        (
            lambda backend_host, backend_port, storage_host, storage_port: [
                f"{backend_host}:{backend_port}",
                f"{storage_host}:{storage_port}",
            ]
        ),
        # Both backend and storage bypassed via CSV with extra noise
        (
            lambda backend_host, backend_port, storage_host, storage_port: (
                f"foo.invalid:1,bar.invalid:2,{backend_host}:{backend_port},baz.invalid:3,{storage_host}:{storage_port}"
            )
        ),
    ],
)
def test_no_proxy_bypass_backend_and_storage_param_only(
    wiremock_backend_storage_proxy,
    wiremock_generic_mappings_dir,
    wiremock_mapping_dir,
    proxy_env_vars,
    no_proxy_factory,
    host_port_pooling,
):
    target_wm, storage_wm, proxy_wm = wiremock_backend_storage_proxy
    _setup_backend_storage_mappings(
        target_wm,
        storage_wm,
        proxy_wm,
        wiremock_mapping_dir,
        wiremock_generic_mappings_dir,
    )

    connect_kwargs = _base_connect_kwargs(target_wm)
    connect_kwargs.update(
        {
            "proxy_host": proxy_wm.wiremock_host,
            "proxy_port": str(proxy_wm.wiremock_http_port),
        }
    )
    _, clear_proxy_env_vars = proxy_env_vars
    clear_proxy_env_vars()

    no_proxy_value = no_proxy_factory(
        target_wm.wiremock_host,
        target_wm.wiremock_http_port,
        storage_wm.wiremock_host,
        storage_wm.wiremock_http_port,
    )
    connect_kwargs["no_proxy"] = no_proxy_value

    _execute_large_query(connect_kwargs, row_count=50_000)

    flags = _collect_request_flags(proxy_wm, target_wm, storage_wm)
    assert flags.target_saw_db
    assert flags.proxy_saw_db is False
    assert flags.storage_saw_storage
    assert flags.proxy_saw_storage is False
