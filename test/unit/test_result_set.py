import gc
import sys
import threading
import time
import traceback
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures.thread import _threads_queues
from test.helpers import create_mock_response
from test.unit.test_cursor import FakeConnection
from test.unit.test_result_batch import REQUEST_MODULE_PATH
from threading import RLock
from unittest import mock

from snowflake.connector.backoff_policies import exponential_backoff
from snowflake.connector.cursor import SnowflakeCursor
from snowflake.connector.result_batch import MAX_DOWNLOAD_RETRY, JSONResultBatch
from snowflake.connector.result_set import ResultSet
from snowflake.connector.time_util import get_time_millis
from snowflake.connector.vendored import requests  # NOQA

REQUEST_MODULE_PATH = "snowflake.connector.vendored.requests"

MockRemoteChunkInfo = namedtuple("MockRemoteChunkInfo", "url")
chunk_info = MockRemoteChunkInfo("http://www.chunk-url.com")
batches = [
    JSONResultBatch(100, None, chunk_info, [], [], True),
    JSONResultBatch(100, None, chunk_info, [], [], True),
    JSONResultBatch(100, None, chunk_info, [], [], True),
    JSONResultBatch(100, None, chunk_info, [], [], True),
    JSONResultBatch(100, None, chunk_info, [], [], True),
]
row = '{"a": 1}'

class SessionWithLockAndGc:

    def __init__(self):
        self.threads = []
        self.lock = RLock()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def request(self, *args, **kwargs):
        self.threads.append(threading.current_thread())
        with self.lock:
            time.sleep(0.1)
            gc.collect()
            time.sleep(0.1)
            return create_mock_response(200, text=(row + ",") * 99 + row)


def test_result_set_does_not_hang():
    session = SessionWithLockAndGc()
    fake_conn = FakeConnection()
    fake_conn._backoff_policy = exponential_backoff()
    fake_conn._rest = mock.Mock()
    fake_conn._rest._use_requests_session.return_value = session
    cursor = SnowflakeCursor(fake_conn)
    result_set = ResultSet(cursor=cursor, result_chunks=batches, prefetch_thread_num=4)

    results = iter(result_set)
    first_batch = next(results)
    assert first_batch is not None
    cursor._result = results
    results = None
    cursor = None
    result_set = None

    for thread in session.threads:
        if thread == threading.current_thread():
            continue
        while thread.is_alive():
            thread.join(timeout=0.1)
