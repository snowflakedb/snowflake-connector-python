#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations

import traceback

import pytest

import snowflake.connector
from snowflake.connector import errors
from snowflake.connector.telemetry import TelemetryField


def test_error_classes(conn_cnx):
    """Error classes in Connector module, object."""
    # class
    assert snowflake.connector.ProgrammingError == errors.ProgrammingError
    assert snowflake.connector.OperationalError == errors.OperationalError

    # object
    with conn_cnx() as ctx:
        assert ctx.ProgrammingError == errors.ProgrammingError


def test_error_code(conn_cnx):
    """Error code is included in the exception."""
    syntax_errno = 1494
    syntax_errno_old = 1003
    syntax_sqlstate = "42601"
    syntax_sqlstate_old = "42000"
    with conn_cnx() as ctx:
        with pytest.raises(errors.ProgrammingError) as e:
            ctx.cursor().execute("SELECT * FROOOM TEST")
        assert (
            e.value.errno == syntax_errno or e.value.errno == syntax_errno_old
        ), "Syntax error code"
        assert (
            e.value.sqlstate == syntax_sqlstate
            or e.value.sqlstate == syntax_sqlstate_old
        ), "Syntax SQL state"
        e.match(
            rf"^({syntax_errno:06d}|{syntax_errno_old:06d}) \(({syntax_sqlstate}|{syntax_sqlstate_old})\): "
        )


@pytest.mark.skipolddriver
def test_error_telemetry(conn_cnx):
    with conn_cnx() as ctx:
        with pytest.raises(errors.ProgrammingError) as e:
            ctx.cursor().execute("SELECT * FROOOM TEST")
        telemetry_stacktrace = e.value.telemetry_traceback
        assert "SELECT * FROOOM TEST" not in telemetry_stacktrace
        for frame in traceback.extract_tb(e.value.__traceback__):
            assert frame.line not in telemetry_stacktrace
        telemetry_data = e.value.generate_telemetry_exception_data()
        assert (
            "Failed to detect Syntax error"
            not in telemetry_data[TelemetryField.KEY_REASON.value]
        )
