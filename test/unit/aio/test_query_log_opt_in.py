#!/usr/bin/env python
from __future__ import annotations

import asyncio
import logging
from unittest import mock

import pytest

from snowflake.connector.aio import SnowflakeConnection, SnowflakeCursor
from snowflake.connector.aio._connection import DEFAULT_CONFIGURATION
from snowflake.connector.errors import ProgrammingError

SQL_MARKER = "SELECT unique_async_sql_marker FROM t WHERE id = ?"
SECRET_SQL = "SELECT 'password=SuperSecret123' FROM t WHERE id = ?"
BIND_MARKER = "visible-async-bind"


def _info(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


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
    conn._lock_sequence_counter = asyncio.Lock()
    conn.sequence_counter = 0
    conn._rest = mock.MagicMock()
    conn.messages = []

    async def cmd_query(*_args, **_kwargs):
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


async def _execute(cursor: SnowflakeCursor, sql: str, params=None):
    with pytest.raises(ProgrammingError):
        await cursor.execute(sql, params)


def test_async_configuration_defaults_false():
    assert DEFAULT_CONFIGURATION["log_query_text"] == (False, bool)
    assert DEFAULT_CONFIGURATION["log_query_parameters"] == (False, bool)


def test_async_connection_warns_at_config_time(caplog):
    conn = SnowflakeConnection.__new__(SnowflakeConnection)
    for name, (value, _) in DEFAULT_CONFIGURATION.items():
        setattr(conn, f"_{name}", value)
    conn._ocsp_explicit = frozenset()
    with caplog.at_level(logging.WARNING, logger="snowflake.connector.connection"):
        conn._SnowflakeConnection__config(
            user="user",
            account="account",
            password="password",
            log_query_text=True,
            log_query_parameters=True,
        )
    messages = _warnings(caplog)
    assert sum("log_query_text is enabled" in message for message in messages) == 1
    assert (
        sum("log_query_parameters is enabled" in message for message in messages) == 1
    )

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="snowflake.connector.connection"):
        conn._SnowflakeConnection__config(
            user="user",
            account="account",
            password="password",
            log_query_text=False,
            log_query_parameters=False,
        )
    assert not any(
        "log_query_" in message and "is enabled" in message
        for message in _warnings(caplog)
    )


async def test_async_flags_false_info_omits_sql_and_binds(caplog):
    cursor = _cursor()
    with caplog.at_level(logging.DEBUG, logger="snowflake.connector"):
        await _execute(cursor, SQL_MARKER, [BIND_MARKER])
    info = "\n".join(_info(caplog))
    debug = "\n".join(
        r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG
    )
    assert "unique_async_sql_marker" not in info
    assert BIND_MARKER not in info
    assert "unique_async_sql_marker" in debug


async def test_async_log_query_text_masks_sql_and_skips_binds(caplog):
    cursor = _cursor(log_query_text=True, max_len=20)
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        await _execute(cursor, SECRET_SQL, [BIND_MARKER])
    info = "\n".join(_info(caplog))
    assert "SuperSecret123" not in info
    assert "password=****" in info
    assert BIND_MARKER not in info


async def test_async_parameters_alone_logs_nothing(caplog):
    cursor = _cursor(log_query_parameters=True)
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        await _execute(cursor, SQL_MARKER, [BIND_MARKER])
    info = "\n".join(_info(caplog))
    assert "unique_async_sql_marker" not in info
    assert BIND_MARKER not in info


async def test_async_pyformat_query_text_omits_interpolated_binds(caplog):
    cursor = _cursor(log_query_text=True, paramstyle="pyformat")
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        await _execute(cursor, "SELECT %s", [BIND_MARKER])
    info = "\n".join(_info(caplog))
    assert BIND_MARKER not in info
    assert "SELECT %s" in info


async def test_async_pyformat_both_flags_include_bind(caplog):
    cursor = _cursor(
        log_query_text=True,
        log_query_parameters=True,
        paramstyle="pyformat",
    )
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        await _execute(cursor, "SELECT %s", [BIND_MARKER])
    assert BIND_MARKER in "\n".join(_info(caplog))


async def test_async_executemany_insert_query_text_omits_inlined_binds(caplog):
    cursor = _cursor(log_query_text=True, paramstyle="pyformat")
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        with pytest.raises(ProgrammingError):
            await cursor.executemany(
                "INSERT INTO t (c) VALUES (%s)",
                [[BIND_MARKER]],
            )
    info = "\n".join(_info(caplog))
    assert BIND_MARKER not in info
    assert "%s" in info


async def test_async_executemany_num_statements_query_text_omits_inlined_binds(caplog):
    cursor = _cursor(log_query_text=True, paramstyle="pyformat")
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        with pytest.raises(ProgrammingError):
            await cursor.executemany(
                "SELECT %s",
                [[BIND_MARKER], ["other-async-bind"]],
                num_statements=1,
            )
    info = "\n".join(_info(caplog))
    assert BIND_MARKER not in info
    assert "other-async-bind" not in info
    assert "%s" in info


async def test_async_executemany_both_flags_include_bind(caplog):
    cursor = _cursor(
        log_query_text=True,
        log_query_parameters=True,
        paramstyle="pyformat",
    )
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        with pytest.raises(ProgrammingError):
            await cursor.executemany(
                "INSERT INTO t (c) VALUES (%s)",
                [[BIND_MARKER]],
            )
    assert BIND_MARKER in "\n".join(_info(caplog))


async def test_async_both_flags_log_binds_and_mask_sql(caplog):
    cursor = _cursor(log_query_text=True, log_query_parameters=True)
    with caplog.at_level(logging.INFO, logger="snowflake.connector"):
        await _execute(cursor, SECRET_SQL, [BIND_MARKER])
    info = "\n".join(_info(caplog))
    assert "SuperSecret123" not in info
    assert "password=****" in info
    assert BIND_MARKER in info
    assert "query parameters:" in info
