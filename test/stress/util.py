#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import time

import psutil

process = psutil.Process()

SAMPLE_RATE = 10  # record data evey SAMPLE_RATE execution


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
