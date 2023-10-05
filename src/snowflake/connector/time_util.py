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

DEFAULT_BACKOFF_MODE = BackoffMode.DEFAULT_JITTER
INITIAL_TIMEOUT_SLEEP_TIME = 1


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


class TimeoutBackoffCtx:
    """Base context for handling timeouts and backoffs on retries"""

    def __init__(
        self,
        max_retry_attempts: int | None = None,
        timeout: int | None = None,
        backoff_mode: BackoffMode = DEFAULT_BACKOFF_MODE,
        **kwargs,
    ) -> None:
        backoff_class: Backoff = resolve_backoff(backoff_mode)
        self._backoff = backoff_class(
            base=kwargs.pop("backoff_base", None),
            cap=kwargs.pop("backoff_cap", None),
            factor=kwargs.pop("backoff_factor", None),
        )

        self._current_retry_count = 0
        self._current_sleep_time = INITIAL_TIMEOUT_SLEEP_TIME

        self._max_retry_attempts = max_retry_attempts
        # in seconds
        self._timeout = timeout

        # in milliseconds
        self._start_time_millis = None

    @property
    def timeout(self) -> int | None:
        return self._timeout

    @property
    def remaining_time_millis(self) -> float | None:
        if self._timeout is None or self._start_time_millis is None:
            return None

        elapsed_time_millis = get_time_millis() - self._start_time_millis
        timeout_millis = self._timeout * 1000
        return timeout_millis - elapsed_time_millis

    @property
    def current_retry_count(self) -> int:
        return int(self._current_retry_count)

    @property
    def current_sleep_time(self) -> int:
        return int(self._current_sleep_time)

    def set_start_time(self) -> None:
        self._start_time_millis = get_time_millis()

    def should_retry(self) -> bool:
        """Decides whether to retry connection."""
        if self._timeout is not None and self._start_time_millis is None:
            logger.warning(
                "Timeout set in TimeoutBackoffCtx, but start time not recorded"
            )

        timed_out = False
        if self._timeout is not None and self._start_time_millis is not None:
            timed_out = self.remaining_time_millis < 0

        retry_attempts_exceeded = False
        if self._max_retry_attempts is not None:
            retry_attempts_exceeded = (
                self._current_retry_count >= self._max_retry_attempts
            )

        return not timed_out and not retry_attempts_exceeded

    def increment(self) -> None:
        """Updates retry count and sleep time for another retry"""
        self._current_retry_count += 1
        self._current_sleep_time = self._backoff.next_sleep(
            self._current_retry_count, self._current_sleep_time
        )
        logger.debug(f"Update retry count to {self._current_retry_count}")
        logger.debug(f"Update sleep time to {self._current_sleep_time} seconds")

    def reset(self) -> None:
        self._current_retry_count = 0
        self._current_sleep_time = INITIAL_TIMEOUT_SLEEP_TIME


def resolve_backoff(backoff_mode: BackoffMode) -> Backoff:
    """Takes a BackoffMode enum and returns the corresponding Backoff class"""
    return {
        BackoffMode.DEFAULT_JITTER: DefaultJitterBackoff,
        BackoffMode.DECORRELATED_JITTER: DecorrelateJitterBackoff,
        BackoffMode.FULL_JITTER: FullJitterBackoff,
        BackoffMode.LINEAR: LinearBackoff,
        BackoffMode.EXPONENTIAL: ExponentialBackoff,
    }[backoff_mode]


class Backoff:
    DEFAULT_BACKOFF_BASE = 1
    DEFAULT_BACKOFF_CAP = 16
    DEFAULT_BACKOFF_FACTOR = 2

    def __init__(
        self,
        base: int | None = None,
        cap: int | None = None,
        factor: int | None = None,
    ):
        self._base = base if base is not None else self.DEFAULT_BACKOFF_BASE
        self._cap = cap if cap is not None else self.DEFAULT_BACKOFF_CAP
        self._factor = factor if cap is not None else self.DEFAULT_BACKOFF_FACTOR

    def next_sleep(self, cnt: Any, sleep: int) -> int:
        pass


class DefaultJitterBackoff(Backoff):
    """Default retry strategy as specified in Client Retry Strategy"""

    def next_sleep(self, cnt: Any, sleep: int) -> int:
        mult_factor = random.choice([-1, 1])
        jitter_amount = 0.5 * sleep * mult_factor

        linear_wait = sleep + jitter_amount
        exp_wait = (self._factor**cnt) + jitter_amount

        return int(random.choice([linear_wait, exp_wait]))


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
