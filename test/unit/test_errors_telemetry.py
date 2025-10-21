from __future__ import annotations

from unittest.mock import Mock

from snowflake.connector.errors import Error
from snowflake.connector.telemetry import TelemetryData, TelemetryField


def _extract_message_from_log_call(mock_conn: Mock) -> dict:
    mock_conn._log_telemetry.assert_called_once()
    td = mock_conn._log_telemetry.call_args[0][0]
    assert isinstance(td, TelemetryData)
    return td.message


def test_error_telemetry_sync_connection():
    conn = Mock()
    conn.telemetry_enabled = True
    conn._telemetry = Mock()
    conn._telemetry.is_closed = False
    conn.application = "pytest_app"
    conn._log_telemetry = Mock()

    err = Error(msg="boom", errno=123456, sqlstate="00000", connection=conn)
    assert str(err)

    msg = _extract_message_from_log_call(conn)
    assert msg[TelemetryField.KEY_TYPE.value] == TelemetryField.SQL_EXCEPTION.value
    assert msg[TelemetryField.KEY_SOURCE.value] == conn.application
    assert msg[TelemetryField.KEY_EXCEPTION.value] == "Error"
    assert msg[TelemetryField.KEY_USES_AIO.value] == "false"
    assert TelemetryField.KEY_DRIVER_TYPE.value in msg
    assert TelemetryField.KEY_DRIVER_VERSION.value in msg
