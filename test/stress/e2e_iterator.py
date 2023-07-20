#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import argparse

import util as stress_util
from util import task_memory_decorator, task_time_execution_decorator

import snowflake.connector
from parameters import CONNECTION_PARAMETERS

stress_util.print_to_console = False
can_draw = True
try:
    import matplotlib.pyplot as plt
except ImportError:
    can_draw = False


def prepare_data(cursor, row_count=100, test_table_name="TEMP_ARROW_TEST_TABLE"):
    cursor.execute(
        f"""
CREATE TEMP TABLE {test_table_name} (
    C1 BIGINT, C2 BINARY, C3 BOOLEAN, C4 CHAR, C5 CHARACTER, C6 DATE, C7 DATETIME, C8 DEC(12,3),
    C9 DECIMAL(12,3), C10 DOUBLE, C11 FLOAT, C12 INT, C13 INTEGER, C14 NUMBER, C15 REAL, C16 BYTEINT,
    C17 SMALLINT, C18 STRING, C19 TEXT, C20 TIME, C21 TIMESTAMP, C22 TIMESTAMP_TZ, C23 TIMESTAMP_LTZ,
    C24 TIMESTAMP_NTZ, C25 TINYINT, C26 VARBINARY, C27 VARCHAR);
"""
    )

    for _ in range(row_count):
        cursor.execute(
            f"""
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


def task_fetch_rows(cursor, table_name):
    ret = cursor.execute(f"select * from {table_name}").fetchall()
    for _ in ret:
        pass


def task_fetch_arrow_batches(cursor, table_name):
    ret = cursor.execute(f"select * from {table_name}").fetch_arrow_batches()
    for _ in ret:
        pass


def execute_task(task, cursor, table_name, iteration_cnt):
    for _ in range(iteration_cnt):
        task(cursor, table_name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iteration_cnt", type=int, default=5000)
    parser.add_argument("--data_file", type=str, default="test_data")
    parser.add_argument("--row_count", type=int, default=100)
    parser.add_argument("--test_table_name", type=str, default="ARROW_TEST_TABLE")
    args = parser.parse_args()

    test_table_name = "TEMP_ARROW_TEST_TABLE"

    with snowflake.connector.connect(
        **CONNECTION_PARAMETERS
    ) as conn, conn.cursor() as cursor:
        if not args.test_table_name:
            print("preparing data started")
            prepare_data(cursor, args.row_count)
            print("preparing data is done")
        else:
            print("using data in existing table")
            test_table_name = args.test_table_name

        memory_check_task = task_memory_decorator(task_fetch_arrow_batches)
        execute_task(memory_check_task, cursor, test_table_name, args.iteration_cnt)
        memory_records = stress_util.collect_memory_records()

        perf_check_task = task_time_execution_decorator(task_fetch_arrow_batches)
        execute_task(perf_check_task, cursor, test_table_name, args.iteration_cnt)
        time_records = stress_util.collect_time_execution_records()

        print("average time is", sum(time_records) / len(time_records))

        if can_draw:
            plt.plot([i for i in range(len(time_records))], time_records)
            plt.title("per iteration execution time")
            plt.show()
            plt.plot(
                [item[0] for item in memory_records],
                [item[1] for item in memory_records],
            )
            plt.title("memory usage")
            plt.show()
