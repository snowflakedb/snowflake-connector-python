#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import snowflake.connector


def test_session_parameters(db_parameters):
    """Sets the session parameters in connection time."""
    connection = snowflake.connector.connect(
        protocol=db_parameters["protocol"],
        account=db_parameters["account"],
        user=db_parameters["user"],
        password=db_parameters["password"],
        host=db_parameters["host"],
        port=db_parameters["port"],
        database=db_parameters["database"],
        schema=db_parameters["schema"],
        session_parameters={"TIMEZONE": "UTC"},
    )
    ret = connection.cursor().execute("show parameters like 'TIMEZONE'").fetchone()
    assert ret[1] == "UTC"
