#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import time

import psutil

process = psutil.Process()

last_memory_record = None
memory_records = []
time_records = []
memory_decoration_execution_time = 0
print_to_console = False


def collect_memory_records():
    memory_records.append(last_memory_record)
    return memory_records


def collect_time_execution_records():
    return time_records


def task_memory_decorator(func):
    memory_records.clear()
    global memory_decoration_execution_time
    memory_decoration_execution_time = 0

    def wrapper(*args, **kwargs):
        global memory_decoration_execution_time
        global print_to_console
        global last_memory_record
        func(*args, **kwargs)
        percent = process.memory_percent()
        if not memory_records or (memory_records and percent != memory_records[-1][1]):
            memory_records.append((memory_decoration_execution_time, percent))
        memory_decoration_execution_time += 1
        last_memory_record = (memory_decoration_execution_time, percent)
        if print_to_console:
            print(memory_decoration_execution_time, percent)

    return wrapper


def task_time_execution_decorator(func):
    time_records.clear()

    def wrapper(*args, **kwargs):
        start = time.time()
        func(*args, **kwargs)
        period = time.time() - start
        time_records.append(period)

    return wrapper
