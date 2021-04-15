#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

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
    with conn_cnx() as ctx:
        try:
            ctx.cursor().execute("SELECT * FROOOM TEST")
            raise Exception("Failed to detect Syntax error")
        except errors.ProgrammingError as e:
            assert e.errno == 1003, "Syntax error code"


@pytest.mark.skipolddriver
def test_error_telemetry(conn_cnx):
    with conn_cnx() as ctx:
        try:
            ctx.cursor().execute("SELECT * FROOOM TEST")
            raise Exception("Failed to detect Syntax error")
        except errors.ProgrammingError as e:
            telemetry_stacktrace = e.telemetry_traceback
            assert "SELECT * FROOOM TEST" not in telemetry_stacktrace
            for frame in traceback.extract_tb(e.__traceback__):
                assert frame.line not in telemetry_stacktrace
            telemetry_data = e.generate_telemetry_exception_data()
            assert (
                "Failed to detect Syntax error"
                not in telemetry_data[TelemetryField.KEY_REASON]
            )
