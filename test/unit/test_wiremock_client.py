#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from typing import Any, Generator, Union

import pytest

from snowflake.connector.vendored import requests

from ..wiremock.wiremock_utils import WiremockClient


@pytest.mark.skipolddriver
@pytest.fixture(scope="session")
def wiremock_client() -> Generator[Union[WiremockClient, Any], Any, None]:
    with WiremockClient() as client:
        yield client


@pytest.mark.skipolddriver
def test_wiremock(wiremock_client):
    connection_reset_by_peer_mapping = {
        "mappings": [
            {
                "scenarioName": "Basic example",
                "requiredScenarioState": "Started",
                "request": {"method": "GET", "url": "/endpoint"},
                "response": {"status": 200},
            }
        ],
        "importOptions": {"duplicatePolicy": "IGNORE", "deleteAllNotInImport": True},
    }
    wiremock_client.import_mapping(connection_reset_by_peer_mapping)

    response = None
    try:
        response = requests.get(
            f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/endpoint"
        )
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")

    assert response is not None, "response is None"
    assert (
        response.status_code == 200
    ), f"response status is not 200, received status {response.status_code}"
