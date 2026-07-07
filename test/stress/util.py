import base64
import threading
import time

import psutil

process = psutil.Process()

from snowflake.connector.arrow_context import ArrowConverterContext
from snowflake.connector.nanoarrow_arrow_iterator import (
    PyArrowRowIterator,
    PyArrowTableIterator,
)

SAMPLE_RATE = 10  # record data every SAMPLE_RATE execution
_DEFAULT_TZ = "America/Los_Angeles"


# ===========================================================================
# Local (offline) iterator helpers
# Build and convert nanoarrow iterators from local Arrow bytes
# ===========================================================================


def load_arrow_bytes(path: str) -> bytes:
    """Read Snowflake Arrow bytes from a file that is either base64 text or raw binary."""
    raw = open(path, "rb").read()
    try:
        return base64.b64decode(raw.decode("ascii"))
    except ValueError:
        return raw


def make_iter(data: bytes, use_table: bool = False, tz: str = _DEFAULT_TZ):
    """Construct a nanoarrow row/table iterator over ``data`` (the shared, correct
    signature). Returns the iterator; the caller materializes it.
    """
    ctx = ArrowConverterContext(session_parameters={"TIMEZONE": tz})
    if use_table:
        return PyArrowTableIterator(None, data, ctx, False, False, False, True)
    return PyArrowRowIterator(None, data, ctx, False, False, False, True)


def convert(data: bytes, use_table: bool = False, tz: str = _DEFAULT_TZ):
    """Build an iterator and fully materialize one pass into a comparable object.

    Row unit -> list of tuples; table unit -> list of per-batch dicts. Used by the
    concurrency harness for reference/race comparison.
    """
    it = make_iter(data, use_table, tz)
    return [tbl.to_pydict() for tbl in it] if use_table else list(it)


# ===========================================================================
# End-to-end (live connection) iterator helpers
# Prepare a table and fetch/convert over a live Snowflake connection.
# ===========================================================================


def prepare_data(cursor, row_count=100, test_table_name="TEMP_ARROW_TEST_TABLE"):
    cursor.execute(
        f"""\
CREATE OR REPLACE TEMP TABLE {test_table_name} (
    C1 BIGINT, C2 BINARY, C3 BOOLEAN, C4 CHAR, C5 CHARACTER, C6 DATE, C7 DATETIME, C8 DEC(12,3),
    C9 DECIMAL(12,3), C10 DOUBLE, C11 FLOAT, C12 INT, C13 INTEGER, C14 NUMBER, C15 REAL, C16 BYTEINT,
    C17 SMALLINT, C18 STRING, C19 TEXT, C20 TIME, C21 TIMESTAMP, C22 TIMESTAMP_TZ, C23 TIMESTAMP_LTZ,
    C24 TIMESTAMP_NTZ, C25 TINYINT, C26 VARBINARY, C27 VARCHAR);
"""
    )

    for _ in range(row_count):
        cursor.execute(
            f"""\
INSERT INTO {test_table_name} SELECT
    123456,
    TO_BINARY('HELP', 'UTF-8'),
    TRUE,
    'a',
    'b',
    '2023-07-18',
    '2023-07-18 12:51:00',
    984.28,
    268.35,
    123.456,
    738.132,
    6789,
    23456,
    12583,
    513.431,
    10,
    9,
    'abc456',
    'def123',
    '12:34:56',
    '2021-01-01 00:00:00 +0000',
    '2021-01-01 00:00:00 +0000',
    '2021-01-01 00:00:00 +0000',
    '2021-01-01 00:00:00 +0000',
    1,
    TO_BINARY('HELP', 'UTF-8'),
    'vxlmls!21321#@!#!'
;
"""
        )


def task_fetch_rows(cursor, table_name, row_count_limit=50000):
    return cursor.execute(
        f"select * from {table_name} limit {row_count_limit}"
    ).fetchall()


def task_fetch_arrow_batches(cursor, table_name, row_count_limit=50000):
    return list(
        cursor.execute(
            f"select * from {table_name} limit {row_count_limit}"
        ).fetch_arrow_batches()
    )


# ===========================================================================
# Shared harness helpers
# Used by both the local and end-to-end harnesses.
# ===========================================================================


def run_concurrent(
    work, threads: int = 16, rounds: int = 100, log=print, perf_records=None
) -> int:
    """Run work function on threads per round, released together via a
    Barrier, and assert every thread's result equals single-threaded reference.

    work is a no-arg callable returning a comparable value that returns 0 on success,
    a non-zero code on mismatch / worker error / empty reference..
    """
    reference = work()
    if not reference:
        log("ERROR: reference work() produced no data")
        return 2

    failures: list = []
    lock = threading.Lock()

    def worker(idx: int, barrier: threading.Barrier) -> None:
        try:
            barrier.wait()
            if work() != reference:
                with lock:
                    failures.append(f"thread {idx}: result != reference")
        except Exception as e:
            with lock:
                failures.append(f"thread {idx}: {e!r}")

    start = time.time()
    for r in range(rounds):
        barrier = threading.Barrier(threads)
        ts = [
            threading.Thread(target=worker, args=(i, barrier)) for i in range(threads)
        ]
        round_start = time.time()
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        if perf_records is not None:
            perf_records.append(time.time() - round_start)
        if failures:
            log(f"FAIL round {r}: {failures[:5]}")
            return 1
        if r % 20 == 0:
            log(f"round {r}/{rounds} ok ({threads} threads)")

    elapsed = time.time() - start
    total = rounds * threads
    log(
        f"PASS: {total} conversions ({rounds} rounds x {threads} threads) in "
        f"{elapsed:.3f}s = {total / elapsed:.0f} conv/s"
    )
    return 0


def draw_perf_graphs(perf_records, memory_records=None):
    """Plot per-unit execution time (and memory, if provided)."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("graphs can not be drawn as matplotlib is not installed.")
        return

    plt.plot(list(range(len(perf_records))), perf_records)
    plt.title("per iteration execution time")
    if memory_records:
        plt.show(block=False)
        plt.figure()
        plt.plot(list(range(len(memory_records))), memory_records)
        plt.title("memory usage")
    plt.show(block=True)


def task_execution_decorator(func, perf_file, memory_file):
    count = 0

    def wrapper(*args, **kwargs):
        start = time.time()
        func(*args, **kwargs)
        memory_usage = (
            process.memory_info().rss / 1024 / 1024
        )  # rss is of unit bytes, we get unit in MB
        period = time.time() - start
        nonlocal count
        if count % SAMPLE_RATE == 0:
            perf_file.write(str(period) + "\n")
            print(f"execution time {count}")
            print(f"memory usage: {memory_usage} MB")
            print(f"execution time: {period} s")
            memory_file.write(str(memory_usage) + "\n")
        count += 1

    return wrapper
