#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import random
import time
from logging import getLogger
from types import TracebackType
from typing import Any, Callable

from .constants import BackoffMode

logger = getLogger(__name__)

try:
    from threading import _Timer as Timer
except ImportError:
    from threading import Timer

DEFAULT_MASTER_VALIDITY_IN_SECONDS = 4 * 60 * 60  # seconds


class HeartBeatTimer(Timer):
    """A thread which executes a function every client_session_keep_alive_heartbeat_frequency seconds."""

    def __init__(
        self, client_session_keep_alive_heartbeat_frequency: int, f: Callable
    ) -> None:
        interval = client_session_keep_alive_heartbeat_frequency
        super().__init__(interval, f)
        # Mark this as a daemon thread, so that it won't prevent Python from exiting.
        self.daemon = True

    def run(self) -> None:
        while not self.finished.is_set():
            self.finished.wait(self.interval)
            if not self.finished.is_set():
                try:
                    self.function()
                except Exception as e:
                    logger.debug("failed to heartbeat: %s", e)


def get_time_millis() -> int:
    """Returns the current time in milliseconds."""
    return int(time.time() * 1000)


class BackoffCtx:
    @staticmethod
    def resolve_backoff(backoff_mode: BackoffMode) -> Backoff:
        """Takes a BackoffMode enum and returns the corresponding Backoff class"""
        return {
            BackoffMode.DECORRELATED_JITTER: DecorrelateJitterBackoff,
            BackoffMode.FULL_JITTER: FullJitterBackoff,
            BackoffMode.LINEAR: LinearBackoff,
            BackoffMode.EXPONENTIAL: ExponentialBackoff,
        }[backoff_mode]

    def __init__(self) -> None:
        # default backoff
        self.set_backoff(BackoffMode.DECORRELATED_JITTER)

    def set_backoff(self, backoff_mode: BackoffMode, **kwargs) -> None:
        clean_kwargs = {k: v for k, v in kwargs.items() if v is not None}
        backoff = self.resolve_backoff(backoff_mode)
        self._backoff = backoff(**clean_kwargs)


class Backoff:
    def __init__(self, base: int = 1, cap: int = 16, factor: int = 2):
        """default argument values were previously used everywhere else in code"""
        self._base = base
        self._cap = cap
        self._factor = factor

    def next_sleep(self, _: Any, sleep: int) -> int:
        pass


class DecorrelateJitterBackoff(Backoff):
    """Decorrelate jitter backoff, see https://www.awsarchitectureblog.com/2015/03/backoff.html"""

    def next_sleep(self, _: Any, sleep: int) -> int:
        return min(self._cap, random.randint(self._base, sleep * 3))


class FullJitterBackoff(Backoff):
    """Full jitter backoff, see https://www.awsarchitectureblog.com/2015/03/backoff.html"""

    def next_sleep(self, cnt: int, _: Any) -> int:
        return random.randint(0, min(self._cap, self._base * (self._factor**cnt)))


class LinearBackoff(Backoff):
    """Standard linear backoff"""

    def next_sleep(self, cnt: int, _: Any) -> int:
        return min(self._cap, self._base + self._factor * cnt)


class ExponentialBackoff(Backoff):
    """Standard exponential backoff"""

    def next_sleep(self, cnt: int, _: Any) -> int:
        return min(self._cap, self._base * (self._factor**cnt))


class TimerContextManager:
    """Context manager class to easily measure execution of a code block.

    Once the context manager finishes, the class should be cast into an int to retrieve
    result.

    Example:

        with TimerContextManager() as measured_time:
            pass
        download_metric = measured_time.get_timing_millis()
    """

    def __init__(self) -> None:
        self._start: int | None = None
        self._end: int | None = None

    def __enter__(self) -> TimerContextManager:
        self._start = get_time_millis()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self._end = get_time_millis()

    def get_timing_millis(self) -> int:
        """Get measured timing in milliseconds."""
        if self._start is None or self._end is None:
            raise Exception(
                "Trying to get timing before TimerContextManager has finished"
            )
        return self._end - self._start
