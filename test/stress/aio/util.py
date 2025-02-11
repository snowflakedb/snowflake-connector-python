#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import time
from contextlib import contextmanager

import psutil

process = psutil.Process()

SAMPLE_RATE = 10  # record data evey SAMPLE_RATE execution


@contextmanager
def task_decorator(perf_file, memory_file):
    count = 0

    start = time.time()
    yield
    memory_usage = (
        process.memory_info().rss / 1024 / 1024
    )  # rss is of unit bytes, we get unit in MB
    period = time.time() - start
    if count % SAMPLE_RATE == 0:
        perf_file.write(str(period) + "\n")
        print(f"execution time {count}")
        print(f"memory usage: {memory_usage} MB")
        print(f"execution time: {period} s")
        memory_file.write(str(memory_usage) + "\n")
    count += 1
