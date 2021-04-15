#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

from logging import getLogger

from snowflake.connector import errorcode, errors
from snowflake.connector.network import SnowflakeRestful

logger = getLogger(__name__)


def test_no_auth(db_parameters):
    """SNOW-13588: No auth Rest API test."""
    rest = SnowflakeRestful(host=db_parameters["host"], port=db_parameters["port"])
    try:
        # no auth
        # show warehouse
        rest.request(
            url="/queries",
            body={
                "sequenceId": 10000,
                "sqlText": "show warehouses",
                "parameters": {
                    "ui_mode": True,
                },
            },
            method="post",
            client="rest",
        )
        raise Exception("Must fail with auth error")
    except errors.Error as e:
        assert e.errno == errorcode.ER_CONNECTION_IS_CLOSED
    finally:
        rest.close()
