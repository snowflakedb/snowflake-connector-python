#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

"""
This script is used for end-to-end performance test for asyncio python connector.

1. select and consume rows of different types for 3 hr, (very large amount of data 10m rows)

    - goal: timeout/retry/refresh token
    - fetch_one/fetch_many/fetch_pandas_batches
    - validate the fetched data is accurate

2. put file
    - many small files
    - one large file
    - verify files(etc. file amount, sha256 signature)

3. get file
    - many small files
    - one large file
    - verify files (etc. file amount, sha256 signature)
"""

import argparse

import util as stress_util
from util import task_execution_decorator

from parameters import CONNECTION_PARAMETERS
from snowflake.connector.aio import SnowflakeConnection

stress_util.print_to_console = False
can_draw = True
try:
    import matplotlib.pyplot as plt
except ImportError:
    print("graphs can not be drawn as matplotlib is not installed.")
    can_draw = False


async def prepare_data(cursor, row_count=100, test_table_name="TEMP_ARROW_TEST_TABLE"):
    await cursor.execute(
        f"""\
CREATE OR REPLACE TEMP TABLE {test_table_name} (
    C1 BIGINT, C2 BINARY, C3 BOOLEAN, C4 CHAR, C5 CHARACTER, C6 DATE, C7 DATETIME, C8 DEC(12,3),
    C9 DECIMAL(12,3), C10 DOUBLE, C11 FLOAT, C12 INT, C13 INTEGER, C14 NUMBER, C15 REAL, C16 BYTEINT,
    C17 SMALLINT, C18 STRING, C19 TEXT, C20 TIME, C21 TIMESTAMP, C22 TIMESTAMP_TZ, C23 TIMESTAMP_LTZ,
    C24 TIMESTAMP_NTZ, C25 TINYINT, C26 VARBINARY, C27 VARCHAR);
"""
    )

    for _ in range(row_count):
        await cursor.execute(
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


async def task_fetch_one_row(cursor, table_name, row_count_limit=50000):
    ret = await (
        await cursor.execute(f"select * from {table_name} limit {row_count_limit}")
    ).fetchone()
    print(ret)


async def task_fetch_rows(cursor, table_name, row_count_limit=50000):
    ret = await (
        await cursor.execute(f"select * from {table_name} limit {row_count_limit}")
    ).fetchall()
    for _ in ret:
        pass


async def task_fetch_arrow_batches(cursor, table_name, row_count_limit=50000):
    ret = await (
        await cursor.execute(f"select * from {table_name} limit {row_count_limit}")
    ).fetch_arrow_batches()
    for _ in ret:
        pass


async def get_file(cursor, source_file, dest_file):
    res = await cursor.execute(f"PUT {source_file} {dest_file} OVERWRITE = TRUE")
    print(await res.fetchall())


async def put_file(cursor, source_file, dest_file):
    res = await cursor.execute(f"GET {source_file} {dest_file}")
    print(await res.fetchall())


def execute_task(task, cursor, table_name, iteration_cnt):
    for _ in range(iteration_cnt):
        task(cursor, table_name)


async def async_wrapper(args):
    conn = SnowflakeConnection(
        user=CONNECTION_PARAMETERS["user"],
        password=CONNECTION_PARAMETERS["password"],
        host=CONNECTION_PARAMETERS["host"],
        account=CONNECTION_PARAMETERS["account"],
        database=CONNECTION_PARAMETERS["database"],
        schema=CONNECTION_PARAMETERS["schema"],
        warehouse=CONNECTION_PARAMETERS["warehouse"],
    )
    await conn.connect()
    cursor = conn.cursor()

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

    await conn.close()


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
