#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from snowflake.connector._utils import _TrackedQueryCancellationTimer


def test_timer():
    timer = _TrackedQueryCancellationTimer(1, lambda: None)
    timer.start()
    timer.join()
    assert timer.executed

    timer = _TrackedQueryCancellationTimer(1, lambda: None)
    timer.start()
    timer.cancel()
    assert not timer.executed
