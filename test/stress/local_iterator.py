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
import math
import random
import secrets

import util as stress_util
from util import task_execution_decorator

from snowflake.connector.arrow_context import ArrowConverterContext
from snowflake.connector.nanoarrow_arrow_iterator import (
    PyArrowRowIterator as NanoarrowRowIterator,
)
from snowflake.connector.nanoarrow_arrow_iterator import (
    PyArrowTableIterator as NanoarrowTableIterator,
)
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


def create_nanoarrow_pyarrow_iterator(input_data, use_table_unit):
    # create nanoarrow based iterator
    return (
        NanoarrowRowIterator(
            None,
            input_data,
            ArrowConverterContext(
                session_parameters={"TIMEZONE": "America/Los_Angeles"}
            ),
            False,
            False,
            False,
        )
        if not use_table_unit
        else NanoarrowTableIterator(
            None,
            input_data,
            ArrowConverterContext(
                session_parameters={"TIMEZONE": "America/Los_Angeles"}
            ),
            False,
            False,
            False,
        )
    )


def task_for_loop_iterator(
    input_data: bytes, create_iterator_method, use_table_unit=False
):
    list(create_iterator_method(input_data, use_table_unit))


def task_for_loop_iterator_expected_error(
    input_data: bytes, create_iterator_method, use_table_unit=False
):
    # case 1: removing the i-th byte in the input_data
    try:
        list(
            create_iterator_method(
                input_data[:10] + input_data[10 + 1 :], use_table_unit
            )
        )
    except:  # noqa
        pass

    # case 2: removing the 2**math.log2(len(decode_bytes) bytes in input_data input
    try:
        list(
            create_iterator_method(
                bytes(remove_bytes(input_data, 2 ** int(math.log2(len(input_data))))),
                use_table_unit,
            )
        )
    except:  # noqa
        pass

    # case 3: randomly-generated 2*22 bytes
    try:
        list(create_iterator_method(secrets.token_bytes(2**22), use_table_unit))
    except:  # noqa
        pass


def execute_task(
    task, bytes_data, create_iterator_method, iteration_cnt, use_table_unit=False
):
    for _ in range(iteration_cnt):
        task(bytes_data, create_iterator_method, use_table_unit)


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
        default="stress_test_data/test_multi_column_row_decimal_data",
        help="a local file to read data from, the file contains base64 encoded string returned from snowflake",
    )
    parser.add_argument(
        "--use_table_unit",
        action="store_true",
        default=False,
    )

    parser.add_argument(
        "--test_error_method",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()

    try:
        # file contains base64 encoded data
        with open(args.data_file) as f:
            b64data = f.read()

        decode_bytes = base64.b64decode(b64data)
    except UnicodeDecodeError:
        # file contains raw bytes data
        with open(args.data_file, "rb") as f:
            decode_bytes = f.read()

    # if connector is pre-release, then it's nanoarrow based iterator
    print(
        "Testing connector version: ",
        ".".join([str(v) for v in VERSION if v is not None]),
    )

    perf_record_file = "stress_perf_record"
    memory_record_file = "stress_memory_record"
    with open(perf_record_file, "w") as perf_file, open(
        memory_record_file, "w"
    ) as memory_file:
        task_for_loop_iterator = task_execution_decorator(
            (
                task_for_loop_iterator_expected_error
                if args.test_error_method
                else task_for_loop_iterator
            ),
            perf_file,
            memory_file,
        )

        execute_task(
            task_for_loop_iterator,
            decode_bytes,
            create_nanoarrow_pyarrow_iterator,
            args.iteration_cnt,
            args.use_table_unit,
        )

    if can_draw:
        with open(perf_record_file) as perf_file, open(
            memory_record_file
        ) as memory_file:
            # sample rate
            perf_lines = perf_file.readlines()
            perf_records = [float(line) for line in perf_lines]

            memory_lines = memory_file.readlines()
            memory_records = [float(line) for line in memory_lines]

            plt.plot([i for i in range(len(perf_records))], perf_records)
            plt.title("per iteration execution time")
            plt.show(block=False)
            plt.figure()
            plt.plot([i for i in range(len(memory_records))], memory_records)
            plt.title("memory usage")
            plt.show(block=True)
