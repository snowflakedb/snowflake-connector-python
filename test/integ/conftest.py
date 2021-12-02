#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

import os
import sys
import time
import uuid
from contextlib import contextmanager
from logging import getLogger
from typing import Any, Callable, ContextManager, Dict, Generator

import pytest

import snowflake.connector
from snowflake.connector.compat import IS_WINDOWS
from snowflake.connector.connection import DefaultConverterClass

from .. import running_on_public_ci
from ..parameters import CONNECTION_PARAMETERS

try:
    from ..parameters import CLIENT_FAILOVER_PARAMETERS  # type: ignore
except ImportError:
    CLIENT_FAILOVER_PARAMETERS: Dict[str, Any] = {}  # type: ignore

MYPY = False
if MYPY:  # from typing import TYPE_CHECKING once 3.5 is deprecated
    from snowflake.connector import SnowflakeConnection

RUNNING_ON_GH = os.getenv("GITHUB_ACTIONS") == "true"

if not isinstance(CONNECTION_PARAMETERS["host"], str):
    raise Exception("default host is not a string in parameters.py")
RUNNING_AGAINST_LOCAL_SNOWFLAKE = CONNECTION_PARAMETERS["host"].endswith("local")

try:
    from ..parameters import CONNECTION_PARAMETERS_ADMIN  # type: ignore
except ImportError:
    CONNECTION_PARAMETERS_ADMIN: Dict[str, Any] = {}  # type: ignore

logger = getLogger(__name__)

if RUNNING_ON_GH:
    TEST_SCHEMA = "GH_JOB_{}".format(str(uuid.uuid4()).replace("-", "_"))
else:
    TEST_SCHEMA = "python_connector_tests_" + str(uuid.uuid4()).replace("-", "_")

DEFAULT_PARAMETERS: Dict["str", Any] = {
    "account": "<account_name>",
    "user": "<user_name>",
    "password": "<password>",
    "database": "<database_name>",
    "schema": "<schema_name>",
    "protocol": "https",
    "host": "<host>",
    "port": "443",
}


def print_help() -> None:
    print(
        """Connection parameter must be specified in parameters.py,
    for example:
CONNECTION_PARAMETERS = {
    'account': 'testaccount',
    'user': 'user1',
    'password': 'test',
    'database': 'testdb',
    'schema': 'public',
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
def db_parameters() -> Dict[str, str]:
    return get_db_parameters()


def get_db_parameters(connection_name: str = "default") -> Dict[str, Any]:
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

    # a unique table name
    ret["name"] = "python_tests_" + str(uuid.uuid4()).replace("-", "_")
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
def init_test_schema(db_parameters) -> Generator[None, None, None]:
    """Initializes and destroys the schema specific to this pytest session.

    This is automatically called per test session.
    """
    ret = db_parameters
    with snowflake.connector.connect(
        user=ret["user"],
        password=ret["password"],
        host=ret["host"],
        port=ret["port"],
        database=ret["database"],
        account=ret["account"],
        protocol=ret["protocol"],
    ) as con:
        con.cursor().execute("CREATE SCHEMA IF NOT EXISTS {}".format(TEST_SCHEMA))
        yield
        con.cursor().execute("DROP SCHEMA IF EXISTS {}".format(TEST_SCHEMA))


def create_connection(connection_name: str, **kwargs) -> "SnowflakeConnection":
    """Creates a connection using the parameters defined in parameters.py.

    You can select from the different connections by supplying the appropiate
    connection_name parameter and then anything else supplied will overwrite the values
    from parameters.py.
    """
    ret = get_db_parameters(connection_name)
    ret.update(kwargs)
    connection = snowflake.connector.connect(**ret)
    return connection


@contextmanager
def db(
    connection_name: str = "default",
    **kwargs,
) -> Generator["SnowflakeConnection", None, None]:
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
def negative_db(**kwargs) -> Generator["SnowflakeConnection", None, None]:
    if not kwargs.get("timezone"):
        kwargs["timezone"] = "UTC"
    if not kwargs.get("converter_class"):
        kwargs["converter_class"] = DefaultConverterClass()
    cnx = create_connection(**kwargs)
    if not is_public_testaccount():
        cnx.cursor().execute("alter session set SUPPRESS_INCIDENT_DUMPS=true")
    try:
        yield cnx
    finally:
        cnx.close()


@pytest.fixture()
def conn_testaccount(request) -> "SnowflakeConnection":
    connection = create_connection("default")

    def fin():
        connection.close()  # close when done

    request.addfinalizer(fin)
    return connection


@pytest.fixture()
def conn_cnx() -> Callable[..., ContextManager["SnowflakeConnection"]]:
    return db


@pytest.fixture()
def negative_conn_cnx() -> Callable[..., ContextManager["SnowflakeConnection"]]:
    """Use this if an incident is expected and we don't want GS to create a dump file about the incident."""
    return negative_db
