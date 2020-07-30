#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#
import logging
import os
import pathlib

RUNNING_ON_GH = os.getenv('GITHUB_ACTIONS') == 'true'

this_dir = pathlib.Path(__file__).parent.absolute()
REGRESSION_TEST_LOG_DIR = this_dir

if RUNNING_ON_GH:
    rt_plain_logger = logging.getLogger('regression.test.plain.logger')
    rt_plain_logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(os.path.join(REGRESSION_TEST_LOG_FIR, 'snowflake_ssm_rt_telemetry.log'))
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter('%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s'))
    logger.addHandler(ch)
