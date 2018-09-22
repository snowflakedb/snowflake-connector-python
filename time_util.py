#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Snowflake Computing Inc. All right reserved.
import time
try:
    from threading import _Timer as Timer
except ImportError:
    from threading import Timer


class HourlyTimer(Timer):
    """A thread which executes a function every hour."""

    def __init__(self, function, args=None, kwargs={}):
        super(HourlyTimer, self).__init__(
            self, function, args=args, kwargs=kwargs)
        self.interval = 60.0 * 60  # one hour

    def run(self):
        while not self.finished.is_set():
            self.finished.wait(self.interval)
            if not self.finished.is_set():
                self.function(*self.args, **self.kwargs)


def get_time_millis():
    """
    Return the current time in millis
    """
    return int(time.time() * 1000)
