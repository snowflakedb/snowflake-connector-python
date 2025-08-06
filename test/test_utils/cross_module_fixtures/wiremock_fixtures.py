import pathlib
import uuid
from contextlib import contextmanager
from functools import partial
from typing import Any, Callable, ContextManager, Generator, Union

import pytest

import snowflake.connector

from ..wiremock.wiremock_utils import WiremockClient, get_clients_for_proxy_and_target


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


@pytest.fixture
def wiremock_target_proxy_pair(wiremock_generic_mappings_dir):
    """Starts a *target* Wiremock and a *proxy* Wiremock pre-configured to forward to it.

    The fixture yields a tuple ``(target_wm, proxy_wm)`` of  ``WiremockClient``
    instances.  It is a thin wrapper around
    ``test.test_utils.wiremock.wiremock_utils.proxy_target_pair``.
    """
    wiremock_proxy_mapping_path = (
        wiremock_generic_mappings_dir / "proxy_forward_all.json"
    )
    with get_clients_for_proxy_and_target(
        proxy_mapping_template=wiremock_proxy_mapping_path
    ) as pair:
        yield pair
