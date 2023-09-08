#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

"""
This script is used for PyArrowIterator performance test.
It tracks the processing time of PyArrowIterator converting data to python objects.

There are two scenarios:

- row data conversion: PyArrowIterator convert data into list of tuple of python primitive objects
- table data conversion: PyArrowIterator converts data into pyarrow table
"""

import argparse
import base64
import io
import math
import random
import secrets

import util as stress_util
from util import task_memory_decorator, task_time_execution_decorator

from snowflake.connector.arrow_context import ArrowConverterContext
from snowflake.connector.arrow_iterator import PyArrowIterator
from snowflake.connector.version import VERSION

stress_util.print_to_console = False
can_draw = True
try:
    import matplotlib.pyplot as plt
except ImportError:
    can_draw = False


def remove_bytes(byte_str, num_bytes):
    """
    Remove a specified number of random bytes from a byte string.
    """
    if num_bytes >= len(byte_str):
        return (
            bytearray()
        )  # Return an empty bytearray if attempting to remove more bytes than available.

    indices_to_remove = random.sample(range(len(byte_str)), num_bytes)
    new_byte_str = bytearray(
        byte for idx, byte in enumerate(byte_str) if idx not in indices_to_remove
    )
    return new_byte_str


def create_pyarrow_iterator(input_data):
    # create nanoarrow based iterator
    return PyArrowIterator(
        None,
        input_data,
        ArrowConverterContext(session_parameters={"TIMEZONE": "America/Los_Angeles"}),
        False,
        False,
        False,
    )


def create_old_pyarrow_iterator(input_data):
    # created vendored arrow based iterator
    return PyArrowIterator(
        None,
        io.BytesIO(input_data),
        ArrowConverterContext(session_parameters={"TIMEZONE": "America/Los_Angeles"}),
        False,
        False,
        False,
    )


def task_for_loop_iterator(input_data: bytes, create_iterator_method):
    for _ in create_iterator_method(input_data):
        pass


def task_for_loop_table_iterator(input_data: bytes, create_iterator_method):
    iterator = create_iterator_method(input_data)
    iterator.init_table_unit()
    for _ in iterator:
        pass


def task_for_loop_iterator_expected_error(input_data: bytes, create_iterator_method):
    # case 1: removing the i-th byte in the input_data
    try:
        iterator = create_iterator_method(input_data[:10] + input_data[10 + 1 :])
        for _ in iterator:
            pass
    except:  # noqa
        pass

    # case 2: removing the 2**math.log2(len(decode_bytes) bytes in input_data input
    try:
        iterator = create_iterator_method(
            bytes(remove_bytes(input_data, 2 ** int(math.log2(len(input_data)))))
        )
        for _ in iterator:
            pass
    except:  # noqa
        pass

    # case 3: randomly-generated 2*22 bytes
    try:
        iterator = create_iterator_method(secrets.token_bytes(2**22))
        for _ in iterator:
            pass
    except:  # noqa
        pass


def task_for_loop_table_iterator_expected_error(
    input_data: bytes, create_iterator_method
):
    # case 1: removing the i-th byte in the input_data
    try:
        iterator = create_iterator_method(input_data[:10] + input_data[10 + 1 :])
        iterator.init_table_unit()
        for _ in iterator:
            pass
    except:  # noqa
        pass

    # case 2: removing the 2**math.log2(len(decode_bytes) bytes in input_data input
    try:
        iterator = create_iterator_method(
            bytes(remove_bytes(input_data, 2 ** int(math.log2(len(input_data)))))
        )
        iterator.init_table_unit()
        for _ in iterator:
            pass
    except:  # noqa
        pass

    # case 3: randomly-generated 2*22 bytes
    try:
        iterator = create_iterator_method(secrets.token_bytes(2**22))
        iterator.init_table_unit()
        for _ in iterator:
            pass
    except:  # noqa
        pass


def execute_task(task, bytes_data, create_iterator_method, iteration_cnt):
    for _ in range(iteration_cnt):
        task(bytes_data, create_iterator_method)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--iteration_cnt",
        type=int,
        default=100000,
        help="how many times to run the test function, default is 100000",
    )
    parser.add_argument(
        "--data_file",
        type=str,
        default="test_data",
        help="a local file to read data from, the file contains base64 encoded string returned from snowflake",
    )
    args = parser.parse_args()

    with open(args.data_file) as f:
        b64data = f.read()

    decode_bytes = base64.b64decode(b64data)

    # if connector is pre-release, then it's nanoarrow based iterator
    print(
        "Testing connector version: ",
        ".".join([str(v) for v in VERSION if v is not None]),
    )
    create_arrow_iterator_method = (
        create_old_pyarrow_iterator
        if str(VERSION[2]).isdigit()
        else create_pyarrow_iterator
    )

    perf_check_task_for_loop_iterator = task_time_execution_decorator(
        task_for_loop_table_iterator
    )
    memory_check_task_for_loop_iterator = task_memory_decorator(
        task_for_loop_table_iterator
    )

    execute_task(
        memory_check_task_for_loop_iterator,
        decode_bytes,
        create_arrow_iterator_method,
        args.iteration_cnt,
    )
    memory_records = stress_util.collect_memory_records()
    execute_task(
        perf_check_task_for_loop_iterator,
        decode_bytes,
        create_arrow_iterator_method,
        args.iteration_cnt,
    )
    time_records = stress_util.collect_time_execution_records()

    print("average time is", sum(time_records) / len(time_records))

    if can_draw:
        plt.plot([i for i in range(len(time_records))], time_records)
        plt.title("per iteration execution time")
        plt.show()
        plt.plot(
            [item[0] for item in memory_records], [item[1] for item in memory_records]
        )
        plt.title("memory usage")
        plt.show()
