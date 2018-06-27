#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Snowflake Computing Inc. All right reserved.
import time


def get_time_millis():
    """
    Return the current time in millis
    """
    return int(time.time() * 1000)
