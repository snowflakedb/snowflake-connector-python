"""
This script is used for end-to-end performance test.
It tracks the processing time from cursor fetching data till all data are converted to python objects.

There are two scenarios:

- row data conversion: fetch data and call `fetchall` on the cursor
- table data conversion: fetch data and call `fetch_arrow_batches` on the cursor
"""

import argparse

from util import draw_perf_graphs, task_execution_decorator, task_fetch_arrow_batches

import snowflake.connector
from parameters import CONNECTION_PARAMETERS

can_draw = True
try:
    import matplotlib.pyplot as plt  # noqa: F401
except ImportError:
    print("graphs can not be drawn as matplotlib is not installed.")
    can_draw = False


def execute_task(task, cursor, table_name, iteration_cnt):
    for _ in range(iteration_cnt):
        task(cursor, table_name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--iteration_cnt",
        type=int,
        default=5000,
        help="how many times to run the test function, default is 5000",
    )
    parser.add_argument(
        "--row_count",
        type=int,
        default=100,
        help="how man rows of data to insert into the temp test able if test_table_name is not provided",
    )
    parser.add_argument(
        "--test_table_name",
        type=str,
        default="ARROW_TEST_TABLE",
        help="an existing test table that has data prepared, by default the it looks for 'ARROW_TEST_TABLE'",
    )
    args = parser.parse_args()

    with snowflake.connector.connect(
        **CONNECTION_PARAMETERS
    ) as conn, conn.cursor() as cursor:
        test_table_name = args.test_table_name

        perf_record_file = "stress_perf_record"
        memory_record_file = "stress_memory_record"
        with open(perf_record_file, "w") as perf_file, open(
            memory_record_file, "w"
        ) as memory_file:
            task = task_execution_decorator(
                task_fetch_arrow_batches, perf_file, memory_file
            )
            execute_task(task, cursor, test_table_name, args.iteration_cnt)

        with open(perf_record_file) as perf_file, open(
            memory_record_file
        ) as memory_file:
            perf_records = [float(line) for line in perf_file.readlines()]
            memory_records = [float(line) for line in memory_file.readlines()]
        if can_draw:
            draw_perf_graphs(perf_records, memory_records)
