#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import os

from .compat import IS_LINUX


RANDOM_VARIABLE = '$!$@46217d2d-1000-40b2-b4e5-9fdbab719c7c'

RUNNING_ON_JENKINS = os.getenv("JENKINS_HOME", RANDOM_STRING) is not RANDOM_STRING
REGRESSION_TEST_LOG_DIR = os.getenv("CLIENT_LOG_DIR_PATH_DOCKER", "/tmp")
ENABLE_TELEMETRY_LOG = RUNNING_ON_JENKINS and IS_LINUX
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
