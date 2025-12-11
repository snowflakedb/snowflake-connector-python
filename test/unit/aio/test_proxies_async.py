from __future__ import annotations

import urllib.request
from collections import deque
from test.unit.test_proxies import (
    DbRequestFlags,
    ProxyPrecedenceFlags,
    RequestFlags,
    _apply_no_proxy,
    _base_connect_kwargs,
    _configure_proxy,
    _set_mappings_for_common_backend,
    _set_mappings_for_query_and_chunks,
    _setup_backend_storage_mappings,
)

import aiohttp
import pytest
from aiohttp import BasicAuth
from aiohttp.helpers import proxies_from_env
from yarl import URL

from snowflake.connector.aio import connect as async_connect

pytestmark = pytest.mark.asyncio


@pytest.mark.timeout(20)
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
async def test_basic_query_through_proxy_async(
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

    expected_headers = {"Via": {"contains": "wiremock"}}

    target_wm.import_mapping_with_default_placeholders(
        password_mapping, expected_headers
    )
    target_wm.add_mapping_with_default_placeholders(select_mapping, expected_headers)
    target_wm.add_mapping(disconnect_mapping)
    target_wm.add_mapping(telemetry_mapping)

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

    conn = await async_connect(**connect_kwargs)
    try:
        cur = conn.cursor()
        await cur.execute("SELECT 1")
        row = await cur.fetchone()
        assert row[0] == 1
    finally:
        await conn.close()

    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{proxy_wm.http_host_with_port}/__admin/requests"
        ) as resp:
            proxy_reqs = await resp.json()
        assert any(
            "/queries/v1/query-request" in r["request"]["url"]
            for r in proxy_reqs["requests"]
        )

        async with session.get(
            f"{target_wm.http_host_with_port}/__admin/requests"
        ) as resp:
            target_reqs = await resp.json()
        assert any(
            "/queries/v1/query-request" in r["request"]["url"]
            for r in target_reqs["requests"]
        )


@pytest.mark.skipolddriver
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
async def test_large_query_through_proxy_async(
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
    await _execute_large_query(connect_kwargs, row_count)

    # Ensure proxy saw query
    flags = await _collect_db_request_flags_only(proxy_wm, target_wm)
    assert flags.proxy_saw_db

    # Ensure backend saw query
    assert flags.target_saw_db


async def _execute_large_query(connect_kwargs, row_count: int):
    conn = await async_connect(**connect_kwargs)
    try:
        cur = conn.cursor()
        await cur.execute(
            f"select seq4() as n from table(generator(rowcount => {row_count}));"
        )
        assert len(cur._execution_state.result_set.batches) > 1
        _ = [r async for r in cur]
    finally:
        await conn.close()


async def _collect_request_flags(proxy_wm, target_wm, storage_wm) -> RequestFlags:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{proxy_wm.http_host_with_port}/__admin/requests"
        ) as resp:
            proxy_reqs = await resp.json()
        async with session.get(
            f"{target_wm.http_host_with_port}/__admin/requests"
        ) as resp:
            target_reqs = await resp.json()
        async with session.get(
            f"{storage_wm.http_host_with_port}/__admin/requests"
        ) as resp:
            storage_reqs = await resp.json()

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


async def _collect_db_request_flags_only(proxy_wm, target_wm) -> DbRequestFlags:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{proxy_wm.http_host_with_port}/__admin/requests"
        ) as resp:
            proxy_reqs = await resp.json()
        async with session.get(
            f"{target_wm.http_host_with_port}/__admin/requests"
        ) as resp:
            target_reqs = await resp.json()
    proxy_saw_db = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in proxy_reqs["requests"]
    )
    target_saw_db = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in target_reqs["requests"]
    )
    return DbRequestFlags(proxy_saw_db=proxy_saw_db, target_saw_db=target_saw_db)


async def _collect_proxy_precedence_flags(
    proxy1_wm, proxy2_wm, target_wm
) -> ProxyPrecedenceFlags:
    """Async version of proxy precedence flags collection using aiohttp."""
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{proxy1_wm.http_host_with_port}/__admin/requests"
        ) as resp:
            proxy1_reqs = await resp.json()
        async with session.get(
            f"{proxy2_wm.http_host_with_port}/__admin/requests"
        ) as resp:
            proxy2_reqs = await resp.json()
        async with session.get(
            f"{target_wm.http_host_with_port}/__admin/requests"
        ) as resp:
            target_reqs = await resp.json()

    proxy1_saw_request = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in proxy1_reqs["requests"]
    )
    proxy2_saw_request = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in proxy2_reqs["requests"]
    )
    backend_saw_request = any(
        "/queries/v1/query-request" in r["request"]["url"]
        for r in target_reqs["requests"]
    )

    return ProxyPrecedenceFlags(
        proxy1_saw_request=proxy1_saw_request,
        proxy2_saw_request=proxy2_saw_request,
        backend_saw_request=backend_saw_request,
    )


@pytest.mark.skipolddriver
@pytest.mark.parametrize("no_proxy_source", ["param", "env"])
async def test_no_proxy_bypass_storage(
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

    await _execute_large_query(connect_kwargs, row_count=50_000)

    flags = await _collect_request_flags(proxy_wm, target_wm, storage_wm)
    assert flags.target_saw_db
    assert flags.proxy_saw_db is True
    assert flags.storage_saw_storage
    assert flags.proxy_saw_storage is False


@pytest.mark.skipolddriver
@pytest.mark.parametrize("no_proxy_source", ["param", "env"])
async def test_no_proxy_basic_param_proxy_bypass_backend(
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

    await _execute_large_query(connect_kwargs, row_count=50_000)

    flags = await _collect_request_flags(proxy_wm, target_wm, storage_wm)
    assert flags.target_saw_db
    assert flags.proxy_saw_db is False
    assert flags.storage_saw_storage
    assert flags.proxy_saw_storage is True


@pytest.fixture
def fix_aiohttp_proxy_bypass(monkeypatch):
    """Fix aiohttp's proxy bypass to check host:port instead of just host.

    This fixture implements a two-step fix:
    1. Override get_env_proxy_for_url to use host_port_subcomponent for proxy_bypass
    2. Override urllib.request._splitport to return (host:port, port) for proper matching
    """

    # Step 1: Override get_env_proxy_for_url to pass host:port to proxy_bypass
    def get_env_proxy_for_url_with_port(url: URL) -> tuple[URL, BasicAuth | None]:
        """Get a permitted proxy for the given URL from the env, checking host:port."""
        from urllib.request import proxy_bypass

        # Check proxy bypass using host:port combination
        if url.host is not None:
            # Use host_port_subcomponent which includes port
            host_port = f"{url.host}:{url.port}" if url.port else url.host
            if proxy_bypass(host_port):
                raise LookupError(f"Proxying is disallowed for `{host_port!r}`")

        proxies_in_env = proxies_from_env()
        try:
            proxy_info = proxies_in_env[url.scheme]
        except KeyError:
            raise LookupError(f"No proxies found for `{url!s}` in the env")
        else:
            return proxy_info.proxy, proxy_info.proxy_auth

    # Step 2: Override _splitport to return host:port as first element
    original_splitport = urllib.request._splitport

    def _splitport_with_port(host):
        """Override to return (host:port, port) instead of (host, port)."""
        result = original_splitport(host)
        if result is None:
            return (host, None)
        host_only, port = result
        # If port was found, return the original host (with port) as first element
        if port is not None:
            return (host, port)  # Return original host:port string
        return (host_only, port)

    monkeypatch.setattr(
        aiohttp.client, "get_env_proxy_for_url", get_env_proxy_for_url_with_port
    )
    monkeypatch.setattr(urllib.request, "_splitport", _splitport_with_port)

    yield


@pytest.mark.skipolddriver
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
@pytest.mark.parametrize("no_proxy_source", ["param", "env"])
async def test_no_proxy_source_vs_proxy_method_matrix(
    wiremock_backend_storage_proxy,
    wiremock_generic_mappings_dir,
    wiremock_mapping_dir,
    proxy_env_vars,
    proxy_method,
    no_proxy_source,
    host_port_pooling,
    fix_aiohttp_proxy_bypass,
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

    await _execute_large_query(connect_kwargs, row_count=50_000)

    flags = await _collect_request_flags(proxy_wm, target_wm, storage_wm)
    assert flags.target_saw_db
    assert flags.proxy_saw_db is True
    assert flags.storage_saw_storage
    assert flags.proxy_saw_storage is False


@pytest.mark.skipolddriver
@pytest.mark.parametrize("proxy_method", ["explicit_args", "env_vars"])
@pytest.mark.parametrize("no_proxy_source", ["param", "env"])
async def test_no_proxy_backend_matrix(
    wiremock_backend_storage_proxy,
    wiremock_generic_mappings_dir,
    wiremock_mapping_dir,
    proxy_env_vars,
    proxy_method,
    no_proxy_source,
    host_port_pooling,
    fix_aiohttp_proxy_bypass,
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

    await _execute_large_query(connect_kwargs, row_count=50_000)

    flags = await _collect_request_flags(proxy_wm, target_wm, storage_wm)
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
async def test_no_proxy_multiple_values_param_only(
    wiremock_backend_storage_proxy,
    wiremock_generic_mappings_dir,
    wiremock_mapping_dir,
    proxy_env_vars,
    no_proxy_factory,
    host_port_pooling,  # Unlike in synch code - Session stores no_proxy setup so it would be reused for proxy and backend since they are both on localhost
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

    await _execute_large_query(connect_kwargs, row_count=50_000)

    proxy_saw_db, target_saw_db, proxy_saw_storage, storage_saw_storage = (
        await _collect_request_flags(proxy_wm, target_wm, storage_wm)
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
async def test_no_proxy_bypass_backend_and_storage_param_only(
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

    await _execute_large_query(connect_kwargs, row_count=50_000)

    flags = await _collect_request_flags(proxy_wm, target_wm, storage_wm)
    assert flags.target_saw_db
    assert flags.proxy_saw_db is False
    assert flags.storage_saw_storage
    assert flags.proxy_saw_storage is False


@pytest.mark.skipolddriver
async def test_proxy_env_vars_take_precedence_over_connection_params(
    wiremock_two_proxies_backend,
    wiremock_mapping_dir,
    wiremock_generic_mappings_dir,
    proxy_env_vars,
    monkeypatch,
    host_port_pooling,
    fix_aiohttp_proxy_bypass,
):
    """Verify that proxy_host/proxy_port connection parameters take precedence over env vars.

    Setup:
    - Set HTTP_PROXY env var to point to proxy_from_env_vars
    - Set proxy_host param to point to proxy_from_conn_params

    Expected outcome:
    - proxy_from_conn_params should see the request (params take precedence)
    - proxy_from_env_vars should NOT see the request
    - backend should see the request
    """
    target_wm, proxy_from_conn_params, proxy_from_env_vars = (
        wiremock_two_proxies_backend
    )

    # Setup backend mappings for large query with multiple chunks
    _set_mappings_for_common_backend(target_wm, wiremock_generic_mappings_dir)
    _set_mappings_for_query_and_chunks(
        target_wm,
        wiremock_mapping_dir,
    )

    # Set HTTP_PROXY env var AFTER Wiremock is running using monkeypatch
    # This prevents Wiremock from inheriting it and forwarding through proxy2
    set_proxy_env_vars, clear_proxy_env_vars = proxy_env_vars
    clear_proxy_env_vars()  # Clear any existing ones first

    env_proxy_url = f"http://{proxy_from_env_vars.wiremock_host}:{proxy_from_env_vars.wiremock_http_port}"

    # Set connection params to point to proxy1 (should take precedence)
    connect_kwargs = _base_connect_kwargs(target_wm)
    connect_kwargs.update(
        {
            "proxy_host": proxy_from_conn_params.wiremock_host,
            "proxy_port": str(proxy_from_conn_params.wiremock_http_port),
        }
    )

    with monkeypatch.context() as m_context:
        m_context.setenv("HTTP_PROXY", env_proxy_url)
        m_context.setenv("HTTPS_PROXY", env_proxy_url)

        # Execute query - now async
        await _execute_large_query(connect_kwargs, row_count=50_000)

    # Verify proxy selection using named tuple flags - now async
    flags = await _collect_proxy_precedence_flags(
        proxy_from_conn_params, proxy_from_env_vars, target_wm
    )
    assert not (
        flags.proxy1_saw_request
    ), "proxy_from_conn_params (connection param proxy) should NOT have seen the query request"
    assert flags.proxy2_saw_request, (
        "proxy_from_env_vars (env var proxy) should have seen the request "
        "since connection params take precedence"
    )
    assert flags.backend_saw_request, "backend should have seen the query request"
