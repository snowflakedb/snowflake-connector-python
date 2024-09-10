#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from contextlib import asynccontextmanager
from test.integ.conftest import get_db_parameters, is_public_testaccount
from typing import AsyncContextManager, Callable, Generator

import pytest

from snowflake.connector.aio import SnowflakeConnection
from snowflake.connector.connection import DefaultConverterClass


async def create_connection(connection_name: str, **kwargs) -> SnowflakeConnection:
    """Creates a connection using the parameters defined in parameters.py.

    You can select from the different connections by supplying the appropiate
    connection_name parameter and then anything else supplied will overwrite the values
    from parameters.py.
    """
    ret = get_db_parameters(connection_name)
    ret.update(kwargs)
    connection = SnowflakeConnection(**ret)
    await connection.connect()
    return connection


@asynccontextmanager
async def db(
    connection_name: str = "default",
    **kwargs,
) -> Generator[SnowflakeConnection, None, None]:
    if not kwargs.get("timezone"):
        kwargs["timezone"] = "UTC"
    if not kwargs.get("converter_class"):
        kwargs["converter_class"] = DefaultConverterClass()
    cnx = await create_connection(connection_name, **kwargs)
    try:
        yield cnx
    finally:
        await cnx.close()


@asynccontextmanager
async def negative_db(
    connection_name: str = "default",
    **kwargs,
) -> Generator[SnowflakeConnection, None, None]:
    if not kwargs.get("timezone"):
        kwargs["timezone"] = "UTC"
    if not kwargs.get("converter_class"):
        kwargs["converter_class"] = DefaultConverterClass()
    cnx = await create_connection(connection_name, **kwargs)
    if not is_public_testaccount():
        await cnx.cursor().execute("alter session set SUPPRESS_INCIDENT_DUMPS=true")
    try:
        yield cnx
    finally:
        await cnx.close()


@pytest.fixture
def async_conn_cnx():
    return db


@pytest.fixture
def conn_cnx():
    return db


@pytest.fixture()
async def conn_testaccount() -> SnowflakeConnection:
    connection = await create_connection("default")
    yield connection
    await connection.close()


@pytest.fixture()
def negative_conn_cnx() -> Callable[..., AsyncContextManager[SnowflakeConnection]]:
    """Use this if an incident is expected and we don't want GS to create a dump file about the incident."""
    return negative_db
