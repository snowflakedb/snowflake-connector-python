#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import snowflake.connector
from snowflake.connector import errors


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
            raise Exception('Failed to detect Syntax error')
        except errors.ProgrammingError as e:
            assert e.errno == 1003, "Syntax error code"
