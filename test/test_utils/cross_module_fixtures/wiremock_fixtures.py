import pathlib
import uuid
from contextlib import contextmanager
from functools import partial
from typing import Any, Callable, ContextManager, Generator, Union

import pytest

import snowflake.connector

from ..wiremock.wiremock_utils import WiremockClient


@pytest.fixture(scope="session")
def wiremock_mapping_dir() -> pathlib.Path:
    return (
        pathlib.Path(__file__).parent.parent.parent / "data" / "wiremock" / "mappings"
    )


@pytest.fixture(scope="session")
def wiremock_generic_mappings_dir(wiremock_mapping_dir) -> pathlib.Path:
    return wiremock_mapping_dir / "generic"


@pytest.fixture(scope="session")
def wiremock_client() -> Generator[Union[WiremockClient, Any], Any, None]:
    with WiremockClient() as client:
        yield client


@pytest.fixture
def default_db_wiremock_parameters(wiremock_client: WiremockClient) -> dict[str, Any]:
    db_params = {
        "account": "testAccount",
        "user": "testUser",
        "password": "testPassword",
        "host": wiremock_client.wiremock_host,
        "port": wiremock_client.wiremock_http_port,
        "protocol": "http",
        "name": "python_tests_" + str(uuid.uuid4()).replace("-", "_"),
    }
    return db_params


@contextmanager
def db_wiremock(
    default_db_wiremock_parameters: dict[str, Any],
    **kwargs,
) -> Generator[snowflake.connector.SnowflakeConnection, None, None]:
    ret = default_db_wiremock_parameters
    ret.update(kwargs)
    cnx = snowflake.connector.connect(**ret)
    try:
        yield cnx
    finally:
        cnx.close()


@pytest.fixture
def conn_cnx_wiremock(
    default_db_wiremock_parameters,
) -> Callable[..., ContextManager[snowflake.connector.SnowflakeConnection]]:
    return partial(
        db_wiremock, default_db_wiremock_parameters=default_db_wiremock_parameters
    )
