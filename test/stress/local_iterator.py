"""
This script is used for PyArrowIterator performance test.
It tracks the processing time of PyArrowIterator converting data to python objects.

There are two scenarios:

- row data conversion: PyArrowIterator convert data into list of tuple of python primitive objects
- table data conversion: PyArrowIterator converts data into pyarrow table
"""

import argparse
import math
import random
import secrets

from util import draw_perf_graphs, load_arrow_bytes, make_iter, task_execution_decorator

from snowflake.connector.version import VERSION

can_draw = True
try:
    import matplotlib.pyplot as plt  # noqa: F401
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

    decode_bytes = load_arrow_bytes(args.data_file)

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
            make_iter,
            args.iteration_cnt,
            args.use_table_unit,
        )

    with open(perf_record_file) as perf_file, open(memory_record_file) as memory_file:
        perf_records = [float(line) for line in perf_file.readlines()]
        memory_records = [float(line) for line in memory_file.readlines()]
    if can_draw:
        draw_perf_graphs(perf_records, memory_records)
