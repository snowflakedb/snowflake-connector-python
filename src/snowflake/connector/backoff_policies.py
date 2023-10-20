#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import random
from typing import Iterator

"""This module provides common implementations of backoff policies

All backoff policies must be implemented as generator functions with the behaviour specified below.

Args:
    factor (int): Constant term used in backoff computations. Usage depends on implementation.
    base (int): Initial backoff time in seconds. Recursive usage depends on implementation.
    cap (int): Maximum backoff time in seconds.
    enable_jitter (int): Whether to enable random jitter on computed durations. For details see
        https://www.awsarchitectureblog.com/2015/03/backoff.html

Yields:
    int: Next backoff duration in seconds
"""

DEFAULT_BACKOFF_FACTOR = 2
DEFAULT_BACKOFF_BASE = 1
DEFAULT_BACKOFF_CAP = 16
DEFAULT_ENABLE_JITTER = True


def mixed_backoff(
    factor: int = DEFAULT_BACKOFF_FACTOR,
    base: int = DEFAULT_BACKOFF_BASE,
    cap: int = DEFAULT_BACKOFF_CAP,
    enable_jitter: bool = DEFAULT_ENABLE_JITTER,
) -> Iterator[int]:
    """Randomly chooses between exponential and constant backoff. Uses equal jitter."""
    cnt = 0
    sleep = base

    yield sleep
    while True:
        cnt += 1

        # equal jitter
        mult_factor = random.choice([-1, 1])
        jitter_amount = 0.5 * sleep * mult_factor if enable_jitter else 0
        sleep = int(
            random.choice([sleep + jitter_amount, factor**cnt + jitter_amount])
        )
        sleep = min(cap, sleep)

        yield sleep


def linear_backoff(
    factor: int = DEFAULT_BACKOFF_FACTOR,
    base: int = DEFAULT_BACKOFF_BASE,
    cap: int = DEFAULT_BACKOFF_CAP,
    enable_jitter: bool = DEFAULT_ENABLE_JITTER,
) -> Iterator[int]:
    """Standard linear backoff. Uses full jitter."""

    sleep = base

    yield sleep
    while True:
        sleep += factor
        sleep = min(cap, sleep)

        # full jitter
        yield random.randint(0, sleep) if enable_jitter else sleep


def exponential_backoff(
    factor: int = DEFAULT_BACKOFF_FACTOR,
    base: int = DEFAULT_BACKOFF_BASE,
    cap: int = DEFAULT_BACKOFF_CAP,
    enable_jitter: bool = DEFAULT_ENABLE_JITTER,
) -> Iterator[int]:
    """Standard exponential backoff. Uses full jitter."""

    sleep = base

    yield sleep
    while True:
        sleep *= factor
        sleep = min(cap, sleep)

        # full jitter
        yield random.randint(0, sleep) if enable_jitter else sleep
