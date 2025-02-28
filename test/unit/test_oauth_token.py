#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pathlib
from threading import Thread
from typing import Any, Generator, Union
from unittest import mock
from unittest.mock import Mock

import pytest

try:
    from snowflake.connector.vendored import requests
    from src.snowflake.connector.test_util import RUNNING_ON_JENKINS
except ImportError:
    import os

    import requests

    RUNNING_ON_JENKINS = os.getenv("JENKINS_HOME") is not None

import snowflake.connector

from ..wiremock.wiremock_utils import WiremockClient

AUTH_SOCKET_PORT = 65000


@pytest.fixture(scope="session")
def wiremock_client() -> Generator[Union[WiremockClient, Any], Any, None]:
    with WiremockClient(forbidden_ports=[AUTH_SOCKET_PORT]) as client:
        yield client


def _call_auth_server(url: str):
    response = requests.get(f"http://{url}", allow_redirects=True)
    assert response.status_code == 200, "Invalid status code received from auth server"


def _webbrowser_redirect(*args):
    assert len(args) == 1, "Invalid number of arguments passed to webbrowser open"

    thread = Thread(target=_call_auth_server, args=(args[0],))
    thread.start()

    return thread.is_alive()


@pytest.mark.skipolddriver
@pytest.mark.skipif(RUNNING_ON_JENKINS, reason="jenkins doesn't support wiremock tests")
def test_successful_flow(wiremock_client: WiremockClient, monkeypatch) -> None:
    monkeypatch.setenv("SF_AUTH_SOCKET_PORT", str(AUTH_SOCKET_PORT))

    wiremock_oauth_authorization_code_dir = (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "oauth"
        / "authorization_code"
    )

    wiremock_generic_mappings_dir = (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "generic"
    )

    wiremock_client.import_mapping(
        wiremock_oauth_authorization_code_dir / "successful_flow.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_login_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )

    webbrowser_mock = Mock()
    webbrowser_mock.open = _webbrowser_redirect

    with mock.patch("webbrowser.open", new=webbrowser_mock.open):
        with mock.patch("secrets.token_urlsafe", return_value="abc123"):
            cnx = snowflake.connector.connect(
                user="testUser",
                authenticator="OAUTH_AUTHORIZATION_CODE",
                oauth_client_id="123",
                account="testAccount",
                protocol="http",
                role="ANALYST",
                host=wiremock_client.wiremock_host,
                port=wiremock_client.wiremock_http_port,
            )

            assert cnx, "invalid cnx"
            cnx.close()
