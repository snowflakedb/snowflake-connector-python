#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#
import logging
import os
import pathlib

RUNNING_ON_GH = os.getenv('GITHUB_ACTIONS') == 'true'
RUNNING_ON_JENKINS = os.getenv('JENKINS_HOME') is not None
REGRESSION_TEST_LOG_DIR = os.getenv('CLIENT_LOG_DIR_PATH_DOCKER', str(pathlib.Path(__file__).parent.absolute()))
rt_plain_logger = None

print("[WUFAN DEBUG] GITHUB_ACTIONS is {}, type of it is {}".format(os.getenv('GITHUB_ACTIONS'), type(os.getenv('GITHUB_ACTIONS'))))
print("[WUFAN DEBUG] RUNNING_ON_GH is {}".format(RUNNING_ON_GH))
print("[WUFAN DEBUG] RUNNING_ON_JENKINS is {}".format(RUNNING_ON_JENKINS))
print("[WUFAN DEBUG] CLIENT_LOG_DIR_PATH_DOCKER is {}".format(os.getenv('CLIENT_LOG_DIR_PATH_DOCKER')))
print("[WUFAN DEBUG] REGRESSION_TEST_LOG_DIR is {}".format(REGRESSION_TEST_LOG_DIR))

if RUNNING_ON_JENKINS:
    rt_plain_logger = logging.getLogger('regression.test.plain.logger')
    rt_plain_logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(os.path.join(REGRESSION_TEST_LOG_DIR, 'snowflake_ssm_rt_telemetry.log'))
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s'))
    rt_plain_logger.addHandler(ch)

    print("[WUFAN DEBUG] telemetry_log init with path: '{}'".format(os.path.join(REGRESSION_TEST_LOG_DIR, 'snowflake_ssm_rt_telemetry.log')))
