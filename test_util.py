#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#
import logging
import os
import pathlib

RUNNING_ON_GH = os.getenv('GITHUB_ACTIONS') == 'true'
REGRESSION_TEST_LOG_DIR = os.getenv('CLIENT_LOG_DIR_PATH_DOCKER', str(pathlib.Path(__file__).parent.absolute()))
rt_plain_logger = None

if RUNNING_ON_GH:
    rt_plain_logger = logging.getLogger('regression.test.plain.logger')
    rt_plain_logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(os.path.join(REGRESSION_TEST_LOG_DIR, 'snowflake_ssm_rt_telemetry.log'))
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s'))
    rt_plain_logger.addHandler(ch)

    print("[WUFAN DEBUG] telemetry_log init with path: '{}'".format(os.path.join(REGRESSION_TEST_LOG_DIR, 'snowflake_ssm_rt_telemetry.log')))
