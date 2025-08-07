#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pathlib
from typing import Any, Generator

import pytest

try:
    from snowflake.connector.aio import SnowflakeConnection
    from snowflake.connector.network import PROGRAMMATIC_ACCESS_TOKEN
except ImportError:
    pass

import snowflake.connector.errors

from ...wiremock.wiremock_utils import WiremockClient


@pytest.fixture(scope="session")
def wiremock_client() -> Generator[WiremockClient | Any, Any, None]:
    with WiremockClient() as client:
        yield client


@pytest.mark.skipolddriver
@pytest.mark.asyncio
async def test_valid_pat_async(wiremock_client: WiremockClient) -> None:
    wiremock_data_dir = (
        pathlib.Path(__file__).parent.parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "pat"
    )

    wiremock_generic_data_dir = (
        pathlib.Path(__file__).parent.parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "generic"
    )

    wiremock_client.import_mapping(wiremock_data_dir / "successful_flow.json")
    wiremock_client.add_mapping(
        wiremock_generic_data_dir / "snowflake_disconnect_successful.json"
    )

    connection = SnowflakeConnection(
        user="testUser",
        authenticator=PROGRAMMATIC_ACCESS_TOKEN,
        token="some PAT",
        account="testAccount",
        protocol="http",
        host=wiremock_client.wiremock_host,
        port=wiremock_client.wiremock_http_port,
    )
    await connection.connect()
    await connection.close()


@pytest.mark.skipolddriver
@pytest.mark.asyncio
async def test_invalid_pat_async(wiremock_client: WiremockClient) -> None:
    wiremock_data_dir = (
        pathlib.Path(__file__).parent.parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "pat"
    )
    wiremock_client.import_mapping(wiremock_data_dir / "invalid_token.json")

    with pytest.raises(snowflake.connector.errors.DatabaseError) as execinfo:
        connection = SnowflakeConnection(
            user="testUser",
            authenticator=PROGRAMMATIC_ACCESS_TOKEN,
            token="some PAT",
            account="testAccount",
            protocol="http",
            host=wiremock_client.wiremock_host,
            port=wiremock_client.wiremock_http_port,
        )
        await connection.connect()

    assert str(execinfo.value).endswith("Programmatic access token is invalid.")


@pytest.mark.skipolddriver
@pytest.mark.asyncio
async def test_pat_as_password_async(wiremock_client: WiremockClient) -> None:
    wiremock_data_dir = (
        pathlib.Path(__file__).parent.parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "pat"
    )

    wiremock_generic_data_dir = (
        pathlib.Path(__file__).parent.parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "generic"
    )

    wiremock_client.import_mapping(wiremock_data_dir / "successful_flow.json")
    wiremock_client.add_mapping(
        wiremock_generic_data_dir / "snowflake_disconnect_successful.json"
    )

    connection = SnowflakeConnection(
        user="testUser",
        authenticator=PROGRAMMATIC_ACCESS_TOKEN,
        token=None,
        password="some PAT",
        account="testAccount",
        protocol="http",
        host=wiremock_client.wiremock_host,
        port=wiremock_client.wiremock_http_port,
    )
    await connection.connect()
    await connection.close()
