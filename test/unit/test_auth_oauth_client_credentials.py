#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pathlib
from typing import Any, Generator, Union
from unittest import mock

import pytest

import snowflake.connector
from snowflake.connector.auth import AuthByOauthCredentials

from ..wiremock.wiremock_utils import WiremockClient


@pytest.fixture(scope="session")
def wiremock_client() -> Generator[Union[WiremockClient, Any], Any, None]:
    with WiremockClient() as client:
        yield client


@pytest.fixture(scope="session")
def wiremock_oauth_authorization_code_dir() -> pathlib.Path:
    return (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "oauth"
        / "client_credentials"
    )


@pytest.fixture(scope="session")
def wiremock_generic_mappings_dir() -> pathlib.Path:
    return (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "generic"
    )


@pytest.mark.skipolddriver
def test_auth_oauth_auth_code_oauth_type():
    """Simple OAuth Client credentials type test."""
    auth = AuthByOauthCredentials(
        "app",
        "clientId",
        "clientSecret",
        "auth_url",
        "tokenRequestUrl",
        "scope",
    )
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["OAUTH_TYPE"] == "client_credentials"


@pytest.mark.skipolddriver
def test_successful_flow(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    wiremock_generic_mappings_dir,
    monkeypatch,
) -> None:
    wiremock_client.import_mapping(
        wiremock_oauth_authorization_code_dir / "successful_flow.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )

    with mock.patch("secrets.token_urlsafe", return_value="abc123"):
        cnx = snowflake.connector.connect(
            user="testUser",
            authenticator="OAUTH_CLIENT_CREDENTIALS",
            oauth_client_id="123",
            oauth_client_secret="123",
            account="testAccount",
            protocol="http",
            role="ANALYST",
            oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
            oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
            host=wiremock_client.wiremock_host,
            port=wiremock_client.wiremock_http_port,
        )

        assert cnx, "invalid cnx"
        cnx.close()


@pytest.mark.skipolddriver
def test_token_request_error(
    wiremock_client: WiremockClient,
    wiremock_oauth_authorization_code_dir,
    wiremock_generic_mappings_dir,
    monkeypatch,
) -> None:
    wiremock_client.import_mapping(
        wiremock_oauth_authorization_code_dir / "token_request_error.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )

    with pytest.raises(snowflake.connector.DatabaseError) as execinfo:
        with mock.patch("secrets.token_urlsafe", return_value="abc123"):
            snowflake.connector.connect(
                user="testUser",
                authenticator="OAUTH_CLIENT_CREDENTIALS",
                oauth_client_id="123",
                oauth_client_secret="123",
                account="testAccount",
                protocol="http",
                role="ANALYST",
                oauth_token_request_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/token-request",
                oauth_authorization_url=f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/oauth/authorize",
                host=wiremock_client.wiremock_host,
                port=wiremock_client.wiremock_http_port,
            )

        assert str(execinfo.value).endswith(
            "Invalid HTTP request from web browser. Idp authentication could have failed."
        )
