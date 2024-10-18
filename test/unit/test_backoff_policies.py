#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pytest

try:
    from snowflake.connector.backoff_policies import (
        DEFAULT_BACKOFF_CAP,
        exponential_backoff,
        linear_backoff,
    )
except ImportError:
    pass


@pytest.mark.skipolddriver
def test_linear_backoff():
    # test default w/ config
    backoff_generator = linear_backoff()()
    # after 12 calls, we will reach the default max 16 and won't grow
    # 1, 3, 5, 7, 9, 11, 13, 15, 16, 16...
    assert max([next(backoff_generator) for _ in range(200)]) <= DEFAULT_BACKOFF_CAP

    # test default w/o enable_jitter config
    backoff_generator = linear_backoff(enable_jitter=False)()
    # after 12 calls, we will reach the default max 16 and won't grow
    # 1, 3, 5, 7, 9, 11, 13, 15, 16, 16...
    assert [next(backoff_generator) for _ in range(20)] == [
        i for i in range(1, DEFAULT_BACKOFF_CAP, 2)
    ] + [DEFAULT_BACKOFF_CAP] * 12

    # # test custom config
    backoff_generator = linear_backoff(factor=2, base=1, cap=100, enable_jitter=False)()
    # after 50 calls, we will reach the max 100 and won't grow
    # 1, 3, 5, 7, 9, ... 100, 100, 100, 100, 100, max is the cap 100
    assert [next(backoff_generator) for _ in range(60)] == [
        i for i in range(1, 100, 2)
    ] + [100] * 10


@pytest.mark.skipolddriver
def test_exponential_backoff():
    # test default w/ enable_jitter config
    backoff_generator = exponential_backoff()()
    # after 12 calls, we will reach the default max 16 and won't grow
    # 1, 3, 5, 7, 9, 11, 13, 15, 16, 16...
    assert max([next(backoff_generator) for _ in range(200)]) <= DEFAULT_BACKOFF_CAP

    # test default w/o enable_jitter config
    backoff_generator = exponential_backoff(enable_jitter=False)()
    # after 12 calls, we will reach the default max 16 and won't grow
    # 1, 3, 5, 7, 9, 11, 13, 15, 16, 16...
    assert [next(backoff_generator) for _ in range(20)] == [1, 2, 4, 8] + [
        DEFAULT_BACKOFF_CAP
    ] * 16

    # test custom config
    backoff_generator = exponential_backoff(
        factor=2, base=1, cap=100, enable_jitter=False
    )()
    # after 7 calls, we will reach max which is the cap 100 and won't grow
    assert [next(backoff_generator) for _ in range(10)] == [
        1,
        2,
        4,
        8,
        16,
        32,
        64,
        100,
        100,
        100,
    ]
