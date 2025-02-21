#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from typing import Any, Generator

import pytest

# old driver support
try:
    from snowflake.connector.vendored import requests
    from src.snowflake.connector.test_util import RUNNING_ON_JENKINS
except ImportError:
    import os

    import requests

    RUNNING_ON_JENKINS = os.getenv("JENKINS_HOME") is not None


from ..wiremock.wiremock_utils import WiremockClient


@pytest.fixture(scope="session")
def wiremock_client() -> Generator[WiremockClient, Any, None]:
    with WiremockClient() as client:
        yield client


@pytest.mark.skipif(RUNNING_ON_JENKINS, reason="jenkins doesn't support wiremock tests")
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

    response = requests.get(
        f"http://{wiremock_client.wiremock_host}:{wiremock_client.wiremock_http_port}/endpoint"
    )

    assert response is not None, "response is None"
    assert (
        response.status_code == requests.codes.ok
    ), f"response status is not 200, received status {response.status_code}"
