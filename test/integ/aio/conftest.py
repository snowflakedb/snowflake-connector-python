#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from contextlib import asynccontextmanager
from test.integ.conftest import get_db_parameters, is_public_testaccount
from typing import AsyncContextManager, Callable, Generator

import pytest

from snowflake.connector.aio import SnowflakeConnection
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
    ) -> Generator[TelemetryCaptureHandlerAsync, None, None]:
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


@pytest.fixture(scope="session")
def capture_sf_telemetry_async() -> TelemetryCaptureFixtureAsync:
    return TelemetryCaptureFixtureAsync()


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


@pytest.fixture()
async def aio_connection(db_parameters):
    cnx = SnowflakeConnection(
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        account=db_parameters["account"],
        database=db_parameters["database"],
        schema=db_parameters["schema"],
        warehouse=db_parameters["warehouse"],
        protocol=db_parameters["protocol"],
        timezone="UTC",
    )
    yield cnx
    await cnx.close()
