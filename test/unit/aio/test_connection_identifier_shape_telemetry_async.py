#!/usr/bin/env python
"""Async unit tests for ``aio.SnowflakeConnection._log_connection_identifier_shape``.

The async override mirrors the sync emission method but awaits the
``_log_telemetry`` call (which is itself a coroutine on the async class).
We feed it a ``Mock`` connection with an ``AsyncMock`` ``_log_telemetry``
so the test exercises the real method body without standing up a full
async connection.

Sibling sync coverage lives in
``test/unit/test_connection_identifier_shape_telemetry.py``; keep the two
files in lockstep when adjusting the emission behavior.

TODO(SNOW-3548350): remove together with the telemetry emission
(target: 2026-11-30).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, Mock

import pytest

from snowflake.connector._connection_identifier_shape import ConnectionIdentifierShape
from snowflake.connector.aio._connection import (
    SnowflakeConnection as AsyncSnowflakeConnection,
)
from snowflake.connector.description import CLIENT_NAME, SNOWFLAKE_CONNECTOR_VERSION
from snowflake.connector.telemetry import TelemetryData, TelemetryField

_DISABLE_ENV = "SF_TELEMETRY_DISABLE_CONNECTION_SHAPE"


def _mock_conn(shape: ConnectionIdentifierShape | None) -> Mock:
    """Build a Mock standing in for the async SnowflakeConnection so we can
    invoke the real method body and inspect calls to ``_log_telemetry``."""
    conn = Mock()
    conn.application = "test_application"
    conn._connection_identifier_shape = shape
    conn._log_telemetry = AsyncMock()
    return conn


async def _invoke(conn: Mock) -> None:
    """Call the real (unbound) async emit method against the mock connection.
    Looking up the method on the class (not the Mock instance) bypasses
    Mock's auto-attribute machinery, so we exercise the production code
    path rather than a Mock-generated stub."""
    await AsyncSnowflakeConnection._log_connection_identifier_shape(conn)


def _captured_telemetry(conn: Mock) -> TelemetryData:
    assert conn._log_telemetry.call_count == 1, (
        f"expected exactly one telemetry record, got "
        f"{conn._log_telemetry.call_count}"
    )
    (telemetry_data,) = conn._log_telemetry.call_args[0]
    return telemetry_data


@pytest.mark.asyncio
async def test_emits_expected_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_DISABLE_ENV, raising=False)
    conn = _mock_conn(
        ConnectionIdentifierShape(
            account_provided=True,
            account_with_region=True,
            account_org_provided=True,
            region_provided=False,
            host_provided=False,
        )
    )

    await _invoke(conn)

    td = _captured_telemetry(conn)
    msg = td.message
    assert msg[TelemetryField.KEY_TYPE.value] == (
        TelemetryField.CONNECTION_IDENTIFIER_SHAPE.value
    )
    assert msg[TelemetryField.KEY_DRIVER_TYPE.value] == CLIENT_NAME
    assert msg[TelemetryField.KEY_DRIVER_VERSION.value] == SNOWFLAKE_CONNECTOR_VERSION
    assert msg[TelemetryField.KEY_SOURCE.value] == "test_application"
    assert msg[TelemetryField.KEY_ACCOUNT_PROVIDED.value] == "true"
    assert msg[TelemetryField.KEY_ACCOUNT_WITH_REGION.value] == "true"
    assert msg[TelemetryField.KEY_ACCOUNT_ORG_PROVIDED.value] == "true"
    assert msg[TelemetryField.KEY_REGION_PROVIDED.value] == "false"
    assert msg[TelemetryField.KEY_HOST_PROVIDED.value] == "false"


@pytest.mark.asyncio
async def test_skips_when_shape_not_captured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(_DISABLE_ENV, raising=False)
    conn = _mock_conn(shape=None)

    await _invoke(conn)

    conn._log_telemetry.assert_not_called()


@pytest.mark.asyncio
async def test_skips_when_shape_attribute_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If ``__config`` never ran (e.g. via an unusual subclass path), the
    attribute may be missing entirely. The emitter must skip cleanly via
    ``getattr(..., None)``."""
    monkeypatch.delenv(_DISABLE_ENV, raising=False)
    conn = Mock(spec=["application", "_log_telemetry"])
    conn.application = "test_application"
    conn._log_telemetry = AsyncMock()

    await _invoke(conn)

    conn._log_telemetry.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["true", "True", "TRUE", "tRuE"])
async def test_honors_env_kill_switch(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Case-insensitive ``"true"`` disables emission, matching the
    cross-driver convention.

    Strict equality after ``.lower()`` — no surrounding-whitespace
    tolerance — so this mirrors gosnowflake's
    ``strings.EqualFold(..., "true")`` exactly.
    """
    monkeypatch.setenv(_DISABLE_ENV, value)
    conn = _mock_conn(ConnectionIdentifierShape(account_provided=True))

    await _invoke(conn)

    conn._log_telemetry.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "",
        "1",
        "yes",
        "Yes",
        "0",
        "false",
        "no",
        "anything-else",
        " true ",  # whitespace tolerance is intentionally NOT honored — see Go parity comment in connection.py.
        "true ",
        " true",
    ],
)
async def test_off_by_default_for_non_true_env_values(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Only case-insensitive ``"true"`` disables emission; every other
    string (including former truthy aliases like ``"1"``/``"yes"`` and
    whitespace-wrapped ``" true "``) leaves emission enabled."""
    monkeypatch.setenv(_DISABLE_ENV, value)
    conn = _mock_conn(ConnectionIdentifierShape(account_provided=True))

    await _invoke(conn)

    assert conn._log_telemetry.call_count == 1
