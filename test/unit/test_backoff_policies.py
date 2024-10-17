#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import pytest

try:
    from snowflake.connector.backoff_policies import exponential_backoff, linear_backoff
except ImportError:
    pass


@pytest.mark.skipolddriver
def test_linear_backoff():
    backoff_generator = linear_backoff(factor=2, base=1, cap=100, enable_jitter=False)()
    # after 50 calls, we will reach the max 100 and won't grow
    # 1, 3, 5, 7, 9, ... 100, 100, 100, 100, 100, max is the cap 100
    assert [next(backoff_generator) for _ in range(60)] == [
        i for i in range(1, 100, 2)
    ] + [100] * 10


@pytest.mark.skipolddriver
def test_exponential_backoff():
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
