import pytest

try:
    from snowflake.connector._utils import _TrackedQueryCancellationTimer
except ImportError:
    pass

pytestmark = pytest.mark.skipolddriver


def test_timer():
    timer = _TrackedQueryCancellationTimer(1, lambda: None)
    timer.start()
    timer.join()
    assert timer.executed

    timer = _TrackedQueryCancellationTimer(1, lambda: None)
    timer.start()
    timer.cancel()
    assert not timer.executed
