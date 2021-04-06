#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#


try:
    from ..parameters import CONNECTION_PARAMETERS_ADMIN
except ImportError:
    CONNECTION_PARAMETERS_ADMIN = {}


def test_session_parameters(conn_cnx):
    """Sets the session parameters in connection time."""
    with conn_cnx(session_parameters={"TIMEZONE": "UTC"}) as cnx, cnx.cursor() as csr:
        ret = csr.execute("show parameters like 'TIMEZONE'").fetchone()
        assert ret[1] == "UTC"
