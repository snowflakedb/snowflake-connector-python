#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import time

import pytest

import snowflake.connector

try:
    from parameters import CONNECTION_PARAMETERS
except ImportError:
    CONNECTION_PARAMETERS = {}

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}


@pytest.fixture
def token_validity_test_values(request):
    with snowflake.connector.connect(**CONNECTION_PARAMETERS_ADMIN) as cnx:
        print("[INFO] Setting token validity to test values")
        cnx.cursor().execute(
            """
ALTER SYSTEM SET
    MASTER_TOKEN_VALIDITY=30,
    SESSION_TOKEN_VALIDITY=10
"""
        )

    def fin():
        with snowflake.connector.connect(**CONNECTION_PARAMETERS_ADMIN) as cnx:
            print("[INFO] Reverting token validity")
            cnx.cursor().execute(
                """
ALTER SYSTEM SET
    MASTER_TOKEN_VALIDITY=default,
    SESSION_TOKEN_VALIDITY=default
"""
            )

    request.addfinalizer(fin)
    return None


@pytest.mark.skipif(
    not (CONNECTION_PARAMETERS_ADMIN),
    reason="ADMIN connection parameters must be provided.",
)
def test_client_session_keep_alive(token_validity_test_values):
    test_connection_parameters = CONNECTION_PARAMETERS.copy()
    print("[INFO] Connected")
    test_connection_parameters["client_session_keep_alive"] = True
    with snowflake.connector.connect(**test_connection_parameters) as con:
        print("[INFO] Running a query. Ensuring a connection is valid.")
        con.cursor().execute("select 1")
        print("[INFO] Sleeping 15s")
        time.sleep(15)
        print(
            "[INFO] Running a query. Both master and session tokens must "
            "have been renewed by token request"
        )
        con.cursor().execute("select 1")
        print("[INFO] Sleeping 40s")
        time.sleep(40)
        print(
            "[INFO] Running a query. Master token must have been renewed "
            "by the heartbeat"
        )
        con.cursor().execute("select 1")
