#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Snowflake Computing Inc. All right reserved.
#
import time

try:
    from threading import _Timer as Timer
except ImportError:
    from threading import Timer

DEFAULT_HEARTBEAT_INTERVAL = 60.0 * 60


class HeartBeatTimer(Timer):
    """A thread which executes a function every 1/4th timing of master token
    validity."""

    def __init__(self, master_validity_in_seconds, f):
        interval = master_validity_in_seconds / 4 if \
            master_validity_in_seconds else DEFAULT_HEARTBEAT_INTERVAL
        super(HeartBeatTimer, self).__init__(interval, f)

    def run(self):
        while not self.finished.is_set():
            self.finished.wait(self.interval)
            if not self.finished.is_set():
                self.function()


def get_time_millis():
    """
    Return the current time in millis
    """
    return int(time.time() * 1000)
