from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

from snowflake.connector.aio import SnowflakeConnection
from snowflake.connector.errors import Error
from snowflake.connector.telemetry import TelemetryData, TelemetryField


def _extract_message_from_log_call(mock_conn: Mock) -> dict:
    mock_conn._log_telemetry.assert_called_once()
    td = mock_conn._log_telemetry.call_args[0][0]
    assert isinstance(td, TelemetryData)
    return td.message


async def test_error_telemetry_async_connection():
    conn = Mock(SnowflakeConnection)
    conn.telemetry_enabled = True
    conn._telemetry = Mock()
    conn._telemetry.is_closed = False
    conn.application = "pytest_app_async"
    conn._log_telemetry = AsyncMock()

    with patch("asyncio.get_running_loop") as loop_mock:
        Error(msg="kaboom", errno=654321, sqlstate="00000", connection=conn)
        loop_mock.return_value.run_until_complete.assert_called_once()

    msg = _extract_message_from_log_call(conn)
    assert msg[TelemetryField.KEY_TYPE.value] == TelemetryField.SQL_EXCEPTION.value
    assert msg[TelemetryField.KEY_SOURCE.value] == conn.application
    assert msg[TelemetryField.KEY_EXCEPTION.value] == "Error"
    assert TelemetryField.KEY_DRIVER_TYPE.value in msg
    assert TelemetryField.KEY_DRIVER_VERSION.value in msg
