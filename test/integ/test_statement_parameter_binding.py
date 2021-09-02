#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from datetime import datetime

import pytest
import pytz

try:
    from parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN, reason="Snowflake admin account is not accessible."
)
def test_binding_security(conn_cnx):
    """Tests binding statement parameters."""
    expected_qa_mode_datetime = datetime(1967, 6, 23, 7, 0, 0, 123000, pytz.UTC)

    with conn_cnx() as cnx:
        cnx.cursor().execute("alter session set timezone='UTC'")
        with cnx.cursor() as cur:
            cur.execute("show databases like 'TESTDB'")
            rec = cur.fetchone()
            assert rec[0] != expected_qa_mode_datetime

        with cnx.cursor() as cur:
            cur.execute(
                "show databases like 'TESTDB'",
                _statement_params={
                    "QA_MODE": True,
                },
            )
            rec = cur.fetchone()
            assert rec[0] == expected_qa_mode_datetime

        with cnx.cursor() as cur:
            cur.execute("show databases like 'TESTDB'")
            rec = cur.fetchone()
            assert rec[0] != expected_qa_mode_datetime
