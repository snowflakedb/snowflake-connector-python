#!/usr/bin/env python
from __future__ import annotations

import os
import sys
import time
import uuid
from contextlib import contextmanager
from logging import getLogger
from typing import Any, Callable, ContextManager, Generator

import pytest

# Add cryptography imports for private key handling
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

import snowflake.connector
from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.connection import DefaultConverterClass

from .. import running_on_public_ci
from ..parameters import CONNECTION_PARAMETERS

try:
    from ..parameters import CLIENT_FAILOVER_PARAMETERS  # type: ignore
except ImportError:
    CLIENT_FAILOVER_PARAMETERS: dict[str, Any] = {}  # type: ignore

MYPY = False
if MYPY:  # from typing import TYPE_CHECKING once 3.5 is deprecated
    from snowflake.connector import SnowflakeConnection

RUNNING_ON_GH = os.getenv("GITHUB_ACTIONS") == "true"
RUNNING_ON_JENKINS = os.getenv("JENKINS_HOME") not in (None, "false")
RUNNING_OLD_DRIVER = os.getenv("TOX_ENV_NAME") == "olddriver"
TEST_USING_VENDORED_ARROW = os.getenv("TEST_USING_VENDORED_ARROW") == "true"


def _get_private_key_bytes_for_olddriver(private_key_file: str) -> bytes:
    """Load private key file and convert to DER format bytes for olddriver compatibility.

    The olddriver expects private keys in DER format as bytes.
    This function handles both PEM and DER input formats.
    """
    with open(private_key_file, "rb") as key_file:
        key_data = key_file.read()

    # Try to load as PEM first, then DER
    try:
        # Try PEM format first
        private_key = serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend(),
        )
    except ValueError:
        try:
            # Try DER format
            private_key = serialization.load_der_private_key(
                key_data,
                password=None,
                backend=default_backend(),
            )
        except ValueError as e:
            raise ValueError(f"Could not load private key from {private_key_file}: {e}")

    # Convert to DER format bytes as expected by olddriver
    return private_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )


if not isinstance(CONNECTION_PARAMETERS["host"], str):
    raise Exception("default host is not a string in parameters.py")
RUNNING_AGAINST_LOCAL_SNOWFLAKE = CONNECTION_PARAMETERS["host"].endswith("local")

try:
    from ..parameters import CONNECTION_PARAMETERS_ADMIN  # type: ignore
except ImportError:
    CONNECTION_PARAMETERS_ADMIN: dict[str, Any] = {}  # type: ignore

logger = getLogger(__name__)


def _get_worker_specific_schema():
    """Generate worker-specific schema name for parallel test execution."""
    base_uuid = str(uuid.uuid4()).replace("-", "_")

    # Check if running in pytest-xdist parallel mode
    worker_id = os.getenv("PYTEST_XDIST_WORKER")
    if worker_id:
        # Use worker ID to ensure unique schema per worker
        worker_suffix = worker_id.replace("-", "_")
        if RUNNING_ON_GH:
            return f"GH_JOB_{worker_suffix}_{base_uuid}"
        else:
            return f"python_connector_tests_{worker_suffix}_{base_uuid}"
    else:
        # Single worker mode (original behavior)
        if RUNNING_ON_GH:
            return f"GH_JOB_{base_uuid}"
        else:
            return f"python_connector_tests_{base_uuid}"


TEST_SCHEMA = _get_worker_specific_schema()


if TEST_USING_VENDORED_ARROW:
    snowflake.connector.cursor.NANOARR_USAGE = (
        snowflake.connector.cursor.NanoarrowUsage.DISABLE_NANOARROW
    )


if RUNNING_ON_JENKINS:
    DEFAULT_PARAMETERS: dict[str, Any] = {
        "account": "<account_name>",
        "user": "<user_name>",
        "password": "<password>",
        "database": "<database_name>",
        "schema": "<schema_name>",
        "protocol": "https",
        "host": "<host>",
        "port": "443",
    }
else:
    if RUNNING_OLD_DRIVER:
        DEFAULT_PARAMETERS: dict[str, Any] = {
            "account": "<account_name>",
            "user": "<user_name>",
            "database": "<database_name>",
            "schema": "<schema_name>",
            "protocol": "https",
            "host": "<host>",
            "port": "443",
            "authenticator": "SNOWFLAKE_JWT",
            "private_key_file": "<private_key_file>",
        }
    else:
        DEFAULT_PARAMETERS: dict[str, Any] = {
            "account": "<account_name>",
            "user": "<user_name>",
            "database": "<database_name>",
            "schema": "<schema_name>",
            "protocol": "https",
            "host": "<host>",
            "port": "443",
            "authenticator": "<authenticator>",
            "private_key_file": "<private_key_file>",
        }


def print_help() -> None:
    print(
        """Connection parameter must be specified in parameters.py,
    for example:
CONNECTION_PARAMETERS = {
    'account': 'testaccount',
    'user': 'user1',
    'database': 'testdb',
    'schema': 'public',
    'authenticator': 'KEY_PAIR_AUTHENTICATOR',
    'private_key_file': '/path/to/private_key.p8',
}
"""
    )


@pytest.fixture(scope="session")
def is_public_test() -> bool:
    return is_public_testaccount()


def is_public_testaccount() -> bool:
    db_parameters = get_db_parameters()
    if not isinstance(db_parameters.get("account"), str):
        raise Exception("default account is not a string in parameters.py")
    return running_on_public_ci() or db_parameters["account"].startswith("sfctest0")


@pytest.fixture(scope="session")
def is_local_dev_setup(db_parameters) -> bool:
    return db_parameters.get("is_local_dev_setup", False)


@pytest.fixture(scope="session")
def db_parameters() -> dict[str, str]:
    return get_db_parameters()


def get_db_parameters(connection_name: str = "default") -> dict[str, Any]:
    """Sets the db connection parameters.

    We do this by reading out values from parameters.py and then inserting some
    hard-coded values into them. Dummy values are also inserted in case these
    dictionaries were printed by mistake.
    """
    os.environ["TZ"] = "UTC"
    if not IS_WINDOWS:
        time.tzset()

    connections = {
        "default": CONNECTION_PARAMETERS,
        "client_failover": CLIENT_FAILOVER_PARAMETERS,
        "admin": CONNECTION_PARAMETERS_ADMIN,
    }

    chosen_connection = connections[connection_name]
    if "account" not in chosen_connection:
        pytest.skip(f"{connection_name} connection is unavailable in parameters.py")

    # testaccount connection info
    ret = {**DEFAULT_PARAMETERS, **chosen_connection}

    # snowflake admin account. Not available in GH actions
    for k, v in CONNECTION_PARAMETERS_ADMIN.items():
        ret["sf_" + k] = v

    if "host" in ret and ret["host"] == DEFAULT_PARAMETERS["host"]:
        ret["host"] = ret["account"] + ".snowflakecomputing.com"

    if "account" in ret and ret["account"] == DEFAULT_PARAMETERS["account"]:
        print_help()
        sys.exit(2)

    # a unique table name (worker-specific for parallel execution)
    base_uuid = str(uuid.uuid4()).replace("-", "_")
    worker_id = os.getenv("PYTEST_XDIST_WORKER")
    if worker_id:
        # Include worker ID to prevent conflicts between parallel workers
        worker_suffix = worker_id.replace("-", "_")
        ret["name"] = f"python_tests_{worker_suffix}_{base_uuid}"
    else:
        ret["name"] = f"python_tests_{base_uuid}"
    ret["name_wh"] = ret["name"] + "wh"

    ret["schema"] = TEST_SCHEMA

    # This reduces a chance to exposing password in test output.
    ret["a00"] = "dummy parameter"
    ret["a01"] = "dummy parameter"
    ret["a02"] = "dummy parameter"
    ret["a03"] = "dummy parameter"
    ret["a04"] = "dummy parameter"
    ret["a05"] = "dummy parameter"
    ret["a06"] = "dummy parameter"
    ret["a07"] = "dummy parameter"
    ret["a08"] = "dummy parameter"
    ret["a09"] = "dummy parameter"
    ret["a10"] = "dummy parameter"
    ret["a11"] = "dummy parameter"
    ret["a12"] = "dummy parameter"
    ret["a13"] = "dummy parameter"
    ret["a14"] = "dummy parameter"
    ret["a15"] = "dummy parameter"
    ret["a16"] = "dummy parameter"
    return ret


@pytest.fixture(scope="session", autouse=True)
def init_test_schema(db_parameters) -> Generator[None]:
    """Initializes and destroys the schema specific to this pytest session.

    This is automatically called per test session.
    """
    if RUNNING_ON_JENKINS:
        connection_params = {
            "user": db_parameters["user"],
            "password": db_parameters["password"],
            "host": db_parameters["host"],
            "port": db_parameters["port"],
            "database": db_parameters["database"],
            "account": db_parameters["account"],
            "protocol": db_parameters["protocol"],
        }
    else:
        connection_params = {
            "user": db_parameters["user"],
            "host": db_parameters["host"],
            "port": db_parameters["port"],
            "database": db_parameters["database"],
            "account": db_parameters["account"],
            "protocol": db_parameters["protocol"],
        }

        # Handle private key authentication differently for old vs new driver
        if RUNNING_OLD_DRIVER:
            # Old driver expects private_key as bytes and SNOWFLAKE_JWT authenticator
            private_key_file = db_parameters.get("private_key_file")
            if private_key_file:
                private_key_bytes = _get_private_key_bytes_for_olddriver(
                    private_key_file
                )
                connection_params.update(
                    {
                        "authenticator": "SNOWFLAKE_JWT",
                        "private_key": private_key_bytes,
                    }
                )
        else:
            # New driver expects private_key_file and KEY_PAIR_AUTHENTICATOR
            connection_params.update(
                {
                    "authenticator": db_parameters["authenticator"],
                    "private_key_file": db_parameters["private_key_file"],
                }
            )

    # Role may be needed when running on preprod, but is not present on Jenkins jobs
    optional_role = db_parameters.get("role")
    if optional_role is not None:
        connection_params.update(role=optional_role)

    with snowflake.connector.connect(**connection_params) as con:
        con.cursor().execute(f"CREATE SCHEMA IF NOT EXISTS {TEST_SCHEMA}")
        yield
        con.cursor().execute(f"DROP SCHEMA IF EXISTS {TEST_SCHEMA}")


def create_connection(connection_name: str, **kwargs) -> SnowflakeConnection:
    """Creates a connection using the parameters defined in parameters.py.

    You can select from the different connections by supplying the appropriate
    connection_name parameter and then anything else supplied will overwrite the values
    from parameters.py.
    """
    ret = get_db_parameters(connection_name)
    ret.update(kwargs)

    # Handle private key authentication differently for old vs new driver (only if not on Jenkins)
    if not RUNNING_ON_JENKINS and "private_key_file" in ret:
        if RUNNING_OLD_DRIVER:
            # Old driver (3.1.0) expects private_key as bytes and SNOWFLAKE_JWT authenticator
            private_key_file = ret.get("private_key_file")
            if (
                private_key_file and "private_key" not in ret
            ):  # Don't override if private_key already set
                private_key_bytes = _get_private_key_bytes_for_olddriver(
                    private_key_file
                )
                ret["authenticator"] = "SNOWFLAKE_JWT"
                ret["private_key"] = private_key_bytes
                ret.pop(
                    "private_key_file", None
                )  # Remove private_key_file for old driver

    connection = snowflake.connector.connect(**ret)
    return connection


@contextmanager
def db(
    connection_name: str = "default",
    **kwargs,
) -> Generator[SnowflakeConnection]:
    if not kwargs.get("timezone"):
        kwargs["timezone"] = "UTC"
    if not kwargs.get("converter_class"):
        kwargs["converter_class"] = DefaultConverterClass()
    cnx = create_connection(connection_name, **kwargs)
    try:
        yield cnx
    finally:
        cnx.close()


@contextmanager
def negative_db(
    connection_name: str = "default",
    **kwargs,
) -> Generator[SnowflakeConnection]:
    if not kwargs.get("timezone"):
        kwargs["timezone"] = "UTC"
    if not kwargs.get("converter_class"):
        kwargs["converter_class"] = DefaultConverterClass()
    cnx = create_connection(connection_name, **kwargs)
    if not is_public_testaccount():
        cnx.cursor().execute("alter session set SUPPRESS_INCIDENT_DUMPS=true")
    try:
        yield cnx
    finally:
        cnx.close()


@pytest.fixture()
def conn_testaccount(request) -> SnowflakeConnection:
    connection = create_connection("default")

    def fin():
        connection.close()  # close when done

    request.addfinalizer(fin)
    return connection


@pytest.fixture()
def conn_cnx() -> Callable[..., ContextManager[SnowflakeConnection]]:
    return db


@pytest.fixture(scope="module")
def module_conn_cnx() -> Callable[..., ContextManager[SnowflakeConnection]]:
    return db


@pytest.fixture()
def negative_conn_cnx() -> Callable[..., ContextManager[SnowflakeConnection]]:
    """Use this if an incident is expected and we don't want GS to create a dump file about the incident."""
    return negative_db
