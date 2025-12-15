#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import os
from contextlib import asynccontextmanager
from test.integ.conftest import (
    USE_PASSWORD_AUTH,
    _get_private_key_bytes_for_olddriver,
    get_db_parameters,
    is_public_testaccount,
)
from typing import Any, AsyncContextManager, AsyncGenerator, Callable

import pytest

from snowflake.connector.aio import SnowflakeConnection
from snowflake.connector.aio import connect as async_connect
from snowflake.connector.aio._telemetry import TelemetryClient
from snowflake.connector.connection import DefaultConverterClass
from snowflake.connector.telemetry import TelemetryData


class TelemetryCaptureHandlerAsync(TelemetryClient):
    def __init__(
        self,
        real_telemetry: TelemetryClient,
        propagate: bool = True,
    ):
        super().__init__(real_telemetry._rest)
        self.records: list[TelemetryData] = []
        self._real_telemetry = real_telemetry
        self._propagate = propagate

    async def add_log_to_batch(self, telemetry_data):
        self.records.append(telemetry_data)
        if self._propagate:
            await super().add_log_to_batch(telemetry_data)

    async def send_batch(self):
        self.records = []
        if self._propagate:
            await super().send_batch()


class TelemetryCaptureFixtureAsync:
    """Provides a way to capture Snowflake telemetry messages."""

    @asynccontextmanager
    async def patch_connection(
        self,
        con: SnowflakeConnection,
        propagate: bool = True,
    ) -> AsyncGenerator[TelemetryCaptureHandlerAsync, None]:
        original_telemetry = con._telemetry
        new_telemetry = TelemetryCaptureHandlerAsync(
            original_telemetry,
            propagate,
        )
        con._telemetry = new_telemetry
        try:
            yield new_telemetry
        finally:
            con._telemetry = original_telemetry


RUNNING_OLD_DRIVER = os.getenv("TOX_ENV_NAME") == "olddriver"


@pytest.fixture(scope="session")
def capture_sf_telemetry_async() -> TelemetryCaptureFixtureAsync:
    return TelemetryCaptureFixtureAsync()


def fill_conn_kwargs_for_tests(connection_name: str, **kwargs) -> dict[str, Any]:
    ret = get_db_parameters(connection_name)
    ret.update(kwargs)

    # Handle private key authentication differently for old vs new driver (only if not using password auth)
    if not USE_PASSWORD_AUTH and "private_key_file" in ret:
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

    return ret


async def create_connection(connection_name: str, **kwargs) -> SnowflakeConnection:
    """Creates a connection using the parameters defined in parameters.py.

    You can select from the different connections by supplying the appropiate
    connection_name parameter and then anything else supplied will overwrite the values
    from parameters.py.
    """
    ret = fill_conn_kwargs_for_tests(connection_name, **kwargs)
    return await async_connect(**ret)


@asynccontextmanager
async def db(
    connection_name: str = "default",
    **kwargs,
) -> AsyncGenerator[SnowflakeConnection, None]:
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
) -> AsyncGenerator[SnowflakeConnection, None]:
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
def conn_cnx():
    return db


@pytest.fixture()
async def conn_testaccount() -> AsyncGenerator[SnowflakeConnection, None]:
    connection = await create_connection("default")
    yield connection
    await connection.close()


@pytest.fixture()
def negative_conn_cnx() -> Callable[..., AsyncContextManager[SnowflakeConnection]]:
    """Use this if an incident is expected and we don't want GS to create a dump file about the incident."""
    return negative_db


@pytest.fixture()
async def aio_connection(db_parameters) -> AsyncGenerator[SnowflakeConnection, None]:
    # Build connection params supporting both password and key-pair auth depending on environment
    connection_params = {
        "user": db_parameters["user"],
        "host": db_parameters["host"],
        "port": db_parameters["port"],
        "account": db_parameters["account"],
        "database": db_parameters["database"],
        "schema": db_parameters["schema"],
        "protocol": db_parameters["protocol"],
        "timezone": "UTC",
    }

    # Optional fields
    warehouse = db_parameters.get("warehouse")
    if warehouse is not None:
        connection_params["warehouse"] = warehouse

    role = db_parameters.get("role")
    if role is not None:
        connection_params["role"] = role

    if "password" in db_parameters and db_parameters["password"]:
        connection_params["password"] = db_parameters["password"]
    elif "private_key_file" in db_parameters:
        # Use key-pair authentication
        connection_params["authenticator"] = "SNOWFLAKE_JWT"
        if RUNNING_OLD_DRIVER:
            private_key_bytes = _get_private_key_bytes_for_olddriver(
                db_parameters["private_key_file"]
            )
            connection_params["private_key"] = private_key_bytes
        else:
            connection_params["private_key_file"] = db_parameters["private_key_file"]

    cnx = SnowflakeConnection(**connection_params)
    try:
        yield cnx
    finally:
        await cnx.close()
