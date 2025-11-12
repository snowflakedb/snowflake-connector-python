from __future__ import annotations

import aiohttp
import pytest

from snowflake.connector.aio import connect
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

    conn = await connect(**connect_kwargs)
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

    expected_headers = {"Via": {"contains": "wiremock"}}

    target_wm.import_mapping(password_mapping, expected_headers=expected_headers)
    target_wm.add_mapping_with_default_placeholders(
        multi_chunk_request_mapping, expected_headers
    )
    target_wm.add_mapping(disconnect_mapping, expected_headers=expected_headers)
    target_wm.add_mapping(telemetry_mapping, expected_headers=expected_headers)
    target_wm.add_mapping_with_default_placeholders(chunk_1_mapping, expected_headers)
    target_wm.add_mapping_with_default_placeholders(chunk_2_mapping, expected_headers)

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
        clear_proxy_env_vars()
    else:
        proxy_url = f"http://proxyUser:proxyPass@{proxy_wm.wiremock_host}:{proxy_wm.wiremock_http_port}"
        set_proxy_env_vars(proxy_url)

    row_count = 50_000
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
