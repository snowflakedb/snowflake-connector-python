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
    assert [next(backoff_generator) for _ in range(5)] == [1, 3, 5, 7, 9]


@pytest.mark.skipolddriver
def test_exponential_backoff():
    backoff_generator = exponential_backoff(
        factor=2, base=1, cap=100, enable_jitter=False
    )()
    assert [next(backoff_generator) for _ in range(5)] == [1, 2, 4, 8, 16]
