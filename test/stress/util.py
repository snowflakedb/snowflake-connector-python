#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import time

import psutil

process = psutil.Process()


def task_execution_decorator(func, perf_file, memory_file):
    def wrapper(*args, **kwargs):
        start = time.time()
        func(*args, **kwargs)
        percent = process.memory_percent()
        period = time.time() - start
        perf_file.write(str(period) + "\n")
        memory_file.write(str(percent) + "\n")

    return wrapper
