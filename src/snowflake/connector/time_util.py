#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import random
import time
from abc import ABC, abstractmethod
from logging import getLogger
from types import TracebackType
from typing import Any, Callable

logger = getLogger(__name__)

try:
    from threading import _Timer as Timer
except ImportError:
    from threading import Timer

DEFAULT_MASTER_VALIDITY_IN_SECONDS = 4 * 60 * 60  # seconds

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


class BackoffPolicy(ABC):
    DEFAULT_BACKOFF_BASE = 1
    DEFAULT_BACKOFF_CAP = 16
    DEFAULT_BACKOFF_FACTOR = 2
    DEFAULT_ENABLE_JITTER = True

    def __init__(
        self,
        base: int = DEFAULT_BACKOFF_BASE,
        cap: int = DEFAULT_BACKOFF_CAP,
        factor: int = DEFAULT_BACKOFF_FACTOR,
        enable_jitter: bool = DEFAULT_ENABLE_JITTER,
    ):
        """Initialize a Backoff
        backoff_base: Integer constant term used in backoff computations. Usage depends on implementation.
        backoff_factor: Integer constant term used in backoff computations. Usage depends on implementation.
        backoff_cap: Maximum backoff time in integer seconds.
        backoff_enable_jitter: Boolean specifying whether to enable randomized jitter on computed backoff times.
        """
        self._base = base
        self._cap = cap
        self._factor = factor
        self._enable_jitter = enable_jitter

    @abstractmethod
    def next_sleep(self, cnt: Any, sleep: int) -> int:
        """Implement this method if using a custom Backoff"""
        pass


class DecorrelateJitterBackoff(BackoffPolicy):
    """Decorrelate jitter backoff (retained for backwards compatibility), see https://www.awsarchitectureblog.com/2015/03/backoff.html"""

    def next_sleep(self, _: Any, sleep: int) -> int:
        return min(self._cap, random.randint(self._base, sleep * 3))


class RecursiveMixedBackoff(BackoffPolicy):
    """Default retry strategy as specified in Client Retry Strategy"""

    def next_sleep(self, cnt: Any, sleep: int) -> int:
        mult_factor = random.choice([-1, 1])
        jitter_amount = 0.5 * sleep * mult_factor if self._enable_jitter else 0

        linear_wait = sleep + jitter_amount
        exp_wait = self._base * (self._factor**cnt) + jitter_amount

        return int(random.choice([linear_wait, exp_wait]))


class LinearBackoff(BackoffPolicy):
    """Standard linear backoff"""

    def next_sleep(self, cnt: int, _: Any) -> int:
        t = min(self._cap, self._base + self._factor * cnt)
        return t if self._enable_jitter else random.randint(0, t)


class ExponentialBackoff(BackoffPolicy):
    """Standard exponential backoff"""

    def next_sleep(self, cnt: int, _: Any) -> int:
        t = min(self._cap, self._base * (self._factor**cnt))
        return t if self._enable_jitter else random.randint(0, t)


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


class TimeoutBackoffCtx:
    """Base context for handling timeouts and backoffs on retries"""

    DEFAULT_BACKOFF_POLICY = RecursiveMixedBackoff

    def __init__(
        self,
        max_retry_attempts: int | None = None,
        timeout: int | None = None,
        backoff_policy: BackoffPolicy | None = None,
    ) -> None:
        self._backoff_policy = (
            backoff_policy
            if backoff_policy is not None
            else TimeoutBackoffCtx.DEFAULT_BACKOFF_POLICY()
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
    def current_retry_count(self) -> int:
        return int(self._current_retry_count)

    @property
    def current_sleep_time(self) -> int:
        return int(self._current_sleep_time)

    def set_start_time(self) -> None:
        self._start_time_millis = get_time_millis()

    def remaining_time_millis(self, timeout: int | None) -> int | None:
        if timeout is None or self._start_time_millis is None:
            return None

        timeout_millis = timeout * 1000
        elapsed_time_millis = get_time_millis() - self._start_time_millis
        return timeout_millis - elapsed_time_millis

    def should_retry(self) -> bool:
        """Decides whether to retry connection."""
        if self._timeout is not None and self._start_time_millis is None:
            logger.warning(
                "Timeout set in TimeoutBackoffCtx, but start time not recorded"
            )

        timed_out = False
        if self.remaining_time_millis(self._timeout) is not None:
            timed_out = self.remaining_time_millis(self._timeout) < 0

        retry_attempts_exceeded = False
        if self._max_retry_attempts is not None:
            retry_attempts_exceeded = (
                self._current_retry_count >= self._max_retry_attempts
            )

        return not timed_out and not retry_attempts_exceeded

    def increment(self) -> None:
        """Updates retry count and sleep time for another retry"""
        self._current_retry_count += 1
        self._current_sleep_time = self._backoff_policy.next_sleep(
            self._current_retry_count, self._current_sleep_time
        )
        logger.debug(f"Update retry count to {self._current_retry_count}")
        logger.debug(f"Update sleep time to {self._current_sleep_time} seconds")

    def reset(self) -> None:
        self._current_retry_count = 0
        self._current_sleep_time = INITIAL_TIMEOUT_SLEEP_TIME
