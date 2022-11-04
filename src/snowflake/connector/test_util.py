#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import os
import time

import pytest

import snowflake.connector.connection
from snowflake.connector.constants import QueryStatus

from .compat import IS_LINUX

RUNNING_ON_JENKINS = os.getenv("JENKINS_HOME") is not None
REGRESSION_TEST_LOG_DIR = os.getenv("CLIENT_LOG_DIR_PATH_DOCKER")
ENABLE_TELEMETRY_LOG = RUNNING_ON_JENKINS and REGRESSION_TEST_LOG_DIR and IS_LINUX
rt_plain_logger = None


if ENABLE_TELEMETRY_LOG:
    rt_plain_logger = logging.getLogger("regression.test.plain.logger")
    rt_plain_logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(
        os.path.join(REGRESSION_TEST_LOG_DIR, "snowflake_ssm_rt_telemetry.log")
    )
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s"
        )
    )
    rt_plain_logger.addHandler(ch)


def _wait_while_query_running(
    con: snowflake.connector.connection,
    sfqid: str,
    sleep_time: int,
    dont_cache: bool = False,
):
    """
    Checks if the provided still returns that it is still running, and if so,
    sleeps for the specified time in a while loop.
    """
    query_status = con._get_query_status if dont_cache else con.get_query_status
    while con.is_still_running(query_status(sfqid)):
        time.sleep(sleep_time)


def _wait_until_query_success(
    con: snowflake.connector.connection,
    sfqid: str,
    num_checks: int,
    sleep_per_check: int,
):
    for _ in range(num_checks):
        status = con.get_query_status(sfqid)
        if status == QueryStatus.SUCCESS:
            break
        time.sleep(sleep_per_check)
    else:
        pytest.fail(
            f"We should have broke out of wait loop for query success."
            f"Query ID: {sfqid}"
            f"Final query status: {status}"
        )
