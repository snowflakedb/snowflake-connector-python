#!/usr/bin/env python
from __future__ import annotations

import logging
import warnings
from threading import Lock
from unittest import mock

import pytest

from snowflake.connector.connection import DEFAULT_CONFIGURATION, SnowflakeConnection
from snowflake.connector.cursor import SnowflakeCursor
from snowflake.connector.errors import ProgrammingError

SQL_MARKER = "SELECT unique_sql_marker FROM t WHERE id = ?"
SECRET_SQL = "SELECT 'password=SuperSecret123' FROM t WHERE id = ?"
BIND_MARKER = "visible-bind-token"
LONG_SQL = "SELECT " + ("x" * 80)


def _info(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]


def _debug(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


def _configure(**kwargs) -> SnowflakeConnection:
    """Run connection configuration without opening a session."""
    conn = SnowflakeConnection.__new__(SnowflakeConnection)
    for name, (value, _) in DEFAULT_CONFIGURATION.items():
        setattr(conn, f"_{name}", value)
    conn._ocsp_explicit = frozenset()
    conn._SnowflakeConnection__config(
        user="user",
        account="account",
        password="password",
        **kwargs,
    )
    return conn


def _cursor(
    *,
    log_query_text: bool = False,
    log_query_parameters: bool = False,
    max_len: int = 10240,
    paramstyle: str = "qmark",
) -> SnowflakeCursor:
    conn = SnowflakeConnection.__new__(SnowflakeConnection)
    conn._log_max_query_length = max_len
    conn._log_query_text = log_query_text
    conn._log_query_parameters = log_query_parameters
    conn._paramstyle = paramstyle
    conn._interpolate_empty_sequences = False
    conn._network_timeout = None
    conn._reuse_results = False
    conn._lock_sequence_counter = Lock()
    conn.sequence_counter = 0
    conn._rest = mock.MagicMock()
    conn.messages = []

    def cmd_query(*_args, **_kwargs):
        return {"success": False, "message": "stub", "data": {}, "code": 1}

    conn.cmd_query = cmd_query

    def process_qmarks(params, _cursor=None):
        if not params:
            return None
        return {
            str(i + 1): {"type": "TEXT", "value": value}
            for i, value in enumerate(params)
        }

    conn._process_params_qmarks = process_qmarks

    def process_pyformat(params, _cursor=None):
        if params is None:
            return {}
        if isinstance(params, dict):
            return {key: f"'{value}'" for key, value in params.items()}
        return tuple(f"'{value}'" for value in params)

    conn._process_params_pyformat = process_pyformat
    return SnowflakeCursor(conn)


def _execute(cursor: SnowflakeCursor, sql: str, params=None):
    with pytest.raises(ProgrammingError):
        cursor.execute(sql, params)


def test_query_log_flags_default_false():
    assert DEFAULT_CONFIGURATION["log_query_text"] == (False, bool)
    assert DEFAULT_CONFIGURATION["log_query_parameters"] == (False, bool)
    conn = _configure()
    assert conn.log_query_text is False
    assert conn.log_query_parameters is False


def test_flags_false_info_omits_sql_and_binds(caplog):
    cursor = _cursor()
    with caplog.at_level(logging.DEBUG, logger="snowflake.connector"):
        _execute(cursor, SQL_MARKER, [BIND_MARKER])
    info = "\n".join(_info(caplog))
    debug = "\n".join(_debug(caplog))
    assert "unique_sql_marker" not in info
    assert BIND_MARKER not in info
    assert "unique_sql_marker" in debug
    assert "running query" in debug


def test_log_query_text_info_contains_masked_truncated_sql(caplog):
    cursor = _cursor(log_query_text=True, max_len=20)
    with caplog.at_level(logging.DEBUG, logger="snowflake.connector"):
        _execute(cursor, SECRET_SQL, [BIND_MARKER])
        _execute(cursor, LONG_SQL, [BIND_MARKER])
    info = "\n".join(_info(caplog))
    assert "SuperSecret123" not in info
    assert "password=****" in info
    assert BIND_MARKER not in info
    assert "x" * 80 not in info
    assert "..." in info


def test_log_query_parameters_alone_logs_no_sql_or_binds(caplog):
    cursor = _cursor(log_query_parameters=True)
    with caplog.at_level(logging.DEBUG, logger="snowflake.connector"):
        _execute(cursor, SQL_MARKER, [BIND_MARKER])
    info = "\n".join(_info(caplog))
    debug = "\n".join(_debug(caplog))
    assert "unique_sql_marker" not in info
    assert BIND_MARKER not in info
    assert "unique_sql_marker" in debug


def test_both_flags_log_binds_and_mask_sql(caplog):
    cursor = _cursor(log_query_text=True, log_query_parameters=True)
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        _execute(cursor, SECRET_SQL, [BIND_MARKER])
    info = "\n".join(_info(caplog))
    assert "SuperSecret123" not in info
    assert "password=****" in info
    assert BIND_MARKER in info
    assert "query parameters:" in info


def test_pyformat_query_text_omits_interpolated_binds(caplog):
    cursor = _cursor(log_query_text=True, paramstyle="pyformat")
    with caplog.at_level(logging.DEBUG, logger="snowflake.connector"):
        _execute(cursor, "SELECT %s", [BIND_MARKER])
    info = "\n".join(_info(caplog))
    debug = "\n".join(_debug(caplog))
    assert BIND_MARKER not in info
    assert "SELECT %s" in info
    assert BIND_MARKER in debug


def test_executemany_insert_query_text_omits_inlined_binds(caplog):
    cursor = _cursor(log_query_text=True, paramstyle="pyformat")
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        with pytest.raises(ProgrammingError):
            cursor.executemany("INSERT INTO t (c) VALUES (%s)", [[BIND_MARKER]])
    info = "\n".join(_info(caplog))
    assert BIND_MARKER not in info
    assert "%s" in info


def test_executemany_insert_both_flags_include_bind(caplog):
    cursor = _cursor(
        log_query_text=True,
        log_query_parameters=True,
        paramstyle="pyformat",
    )
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        with pytest.raises(ProgrammingError):
            cursor.executemany("INSERT INTO t (c) VALUES (%s)", [[BIND_MARKER]])
    assert BIND_MARKER in "\n".join(_info(caplog))


def test_executemany_num_statements_query_text_omits_inlined_binds(caplog):
    cursor = _cursor(log_query_text=True, paramstyle="pyformat")
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        with pytest.raises(ProgrammingError):
            cursor.executemany(
                "SELECT %s",
                [[BIND_MARKER], ["other-bind-token"]],
                num_statements=1,
            )
    info = "\n".join(_info(caplog))
    assert BIND_MARKER not in info
    assert "other-bind-token" not in info
    assert "%s" in info


def test_executemany_num_statements_both_flags_include_bind(caplog):
    cursor = _cursor(
        log_query_text=True,
        log_query_parameters=True,
        paramstyle="pyformat",
    )
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        with pytest.raises(ProgrammingError):
            cursor.executemany(
                "SELECT %s",
                [[BIND_MARKER]],
                num_statements=1,
            )
    assert BIND_MARKER in "\n".join(_info(caplog))


def test_pyformat_both_flags_log_params_and_mask_sql(caplog):
    cursor = _cursor(
        log_query_text=True,
        log_query_parameters=True,
        paramstyle="pyformat",
    )
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        _execute(cursor, "SELECT 'password=SuperSecret123', %s", [BIND_MARKER])
    info = "\n".join(_info(caplog))
    assert "SuperSecret123" not in info
    assert "password=****" in info
    assert BIND_MARKER in info


def test_warning_at_config_time_per_enabled_flag(caplog):
    with caplog.at_level(logging.WARNING, logger="snowflake.connector.connection"):
        _configure()
    assert not any(
        "log_query_text is enabled" in message for message in _warnings(caplog)
    )
    assert not any(
        "log_query_parameters is enabled" in message for message in _warnings(caplog)
    )

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="snowflake.connector.connection"):
        text_only = _configure(log_query_text=True)
    warnings_text = _warnings(caplog)
    assert sum("log_query_text is enabled" in message for message in warnings_text) == 1
    assert not any(
        "log_query_parameters is enabled" in message for message in warnings_text
    )
    assert text_only.log_query_text is True

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="snowflake.connector.connection"):
        _configure(log_query_parameters=True)
    warnings_params = _warnings(caplog)
    assert not any(
        "log_query_text is enabled" in message for message in warnings_params
    )
    assert (
        sum("log_query_parameters is enabled" in message for message in warnings_params)
        == 1
    )

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="snowflake.connector.connection"):
        both = _configure(log_query_text=True, log_query_parameters=True)
    warnings_both = _warnings(caplog)
    assert sum("log_query_text is enabled" in message for message in warnings_both) == 1
    assert (
        sum("log_query_parameters is enabled" in message for message in warnings_both)
        == 1
    )
    before = len(warnings_both)
    both._log_query_at_info(SQL_MARKER, [BIND_MARKER])
    both._log_query_at_info(SQL_MARKER, [BIND_MARKER])
    assert len(_warnings(caplog)) == before


def test_invalid_bool_warns_like_other_bool_options():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        conn = _configure(validate_default_parameters=True, log_query_text="yes")
    messages = [str(item.message) for item in caught if item.category is UserWarning]
    assert (
        "'log_query_text' connection parameter should be of type 'bool', but is a 'str'"
        in messages
    )
    assert conn._log_query_text == "yes"


def test_parameters_string_is_masked_and_truncated():
    conn = SnowflakeConnection.__new__(SnowflakeConnection)
    conn._log_max_query_length = 24
    conn._log_query_text = True
    conn._log_query_parameters = True
    records = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    log = logging.getLogger("snowflake.connector.test_query_log_opt_in")
    log.setLevel(logging.INFO)
    handler = _Capture()
    log.addHandler(handler)
    try:
        conn._log_query_at_info(
            "SELECT 1",
            "password=SuperSecret123 " + ("p" * 80),
            log=log,
        )
    finally:
        log.removeHandler(handler)
    rendered = "\n".join(records)
    assert "SuperSecret123" not in rendered
    assert "password=****" in rendered
    assert "p" * 80 not in rendered
    assert "..." in rendered
