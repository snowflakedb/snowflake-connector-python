#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018-2019 Snowflake Computing Inc. All right reserved.
#
import random
import time
from logging import getLogger

logger = getLogger(__name__)

try:
    from threading import _Timer as Timer
except ImportError:
    from threading import Timer

DEFAULT_MASTER_VALIDITY_IN_SECONDS = 4 * 60 * 60  # seconds


class HeartBeatTimer(Timer):
    """
    A thread which executes a function every
    client_session_keep_alive_heartbeat_frequency seconds
    """

    def __init__(self, client_session_keep_alive_heartbeat_frequency, f):
        interval = client_session_keep_alive_heartbeat_frequency
        super(HeartBeatTimer, self).__init__(interval, f)

    def run(self):
        while not self.finished.is_set():
            self.finished.wait(self.interval)
            if not self.finished.is_set():
                try:
                    self.function()
                except Exception as e:
                    logger.debug('failed to heartbeat: %s', e)


def get_time_millis():
    """
    Return the current time in millis
    """
    return int(time.time() * 1000)


class DecorrelateJitterBackoff(object):
    # Decorrelate Jitter backoff
    # https://www.awsarchitectureblog.com/2015/03/backoff.html
    def __init__(self, base, cap):
        self._base = base
        self._cap = cap

    def next_sleep(self, _, sleep):
        return min(self._cap, random.randint(self._base, sleep * 3))
