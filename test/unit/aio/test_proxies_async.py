from __future__ import annotations

from collections import deque
from test.unit.test_proxies import (
    DbRequestFlags,
    RequestFlags,
    _apply_no_proxy,
    _base_connect_kwargs,
    _configure_proxy,
    _setup_backend_storage_mappings,
)

import aiohttp
import pytest

from snowflake.connector.aio import connect as async_connect

pytestmark = pytest.mark.asyncio


@pytest.mark.timeout(15)
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
        assert len(cur._result_set.batches) > 1
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
