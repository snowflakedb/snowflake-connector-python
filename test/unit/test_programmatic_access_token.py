#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pathlib
from typing import Any, Generator, Union

import pytest

try:
    import snowflake.connector
    from src.snowflake.connector.network import PROGRAMMATIC_ACCESS_TOKEN
except ImportError:
    pass

from ..wiremock.wiremock_utils import WiremockClient


@pytest.fixture(scope="session")
def wiremock_client() -> Generator[Union[WiremockClient, Any], Any, None]:
    with WiremockClient() as client:
        yield client


@pytest.mark.skipolddriver
def test_valid_pat(wiremock_client: WiremockClient) -> None:
    wiremock_data_dir = (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "pat"
    )

    wiremock_generic_data_dir = (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "generic"
    )

    wiremock_client.import_mapping(wiremock_data_dir / "successful_flow.json")
    wiremock_client.add_mapping(
        wiremock_generic_data_dir / "snowflake_disconnect_successful.json"
    )

    cnx = snowflake.connector.connect(
        user="testUser",
        authenticator=PROGRAMMATIC_ACCESS_TOKEN,
        token="some PAT",
        account="testAccount",
        protocol="http",
        host=wiremock_client.wiremock_host,
        port=wiremock_client.wiremock_http_port,
    )

    assert cnx, "invalid cnx"
    cnx.close()


@pytest.mark.skipolddriver
def test_invalid_pat(wiremock_client: WiremockClient) -> None:
    wiremock_data_dir = (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "pat"
    )
    wiremock_client.import_mapping(wiremock_data_dir / "invalid_token.json")

    with pytest.raises(snowflake.connector.errors.DatabaseError) as execinfo:
        snowflake.connector.connect(
            user="testUser",
            authenticator=PROGRAMMATIC_ACCESS_TOKEN,
            token="some PAT",
            account="testAccount",
            protocol="http",
            host=wiremock_client.wiremock_host,
            port=wiremock_client.wiremock_http_port,
        )

    assert str(execinfo.value).endswith("Programmatic access token is invalid.")
