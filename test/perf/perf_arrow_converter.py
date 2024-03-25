#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

"""
This script is for an E2E test the perf of arrow converter.
By E2E, it's testing the whole life cycle of converting arrow data into python object from Python layer to the C Arrow
Converter Implementation.

It will generate a table with test data,
test fetching and convert arrow data into python objects with different row count.

The source code of the connector has been changed such that all data chunks will be downloaded first before conversion
to eliminate the effect of networking.
"""
import time
import timeit

import snowflake.connector

TEST_TABLE_NAME = "ARROW_CONVERTER_PERF"
CREATE_TABLE = True
DROP_TABLE = False
TEST_ROW_COUNTS = [10_000, 100_000, 500_000, 1_000_000, 2_000_000, 5_000_000]
CONNECTION_PARAMETERS = {
    "account": "",
    "user": "",
    "password": "",
    "schema": "",
    "database": "",
    "protocol": "https",
    "host": "",
    "warehouse": "",
    "port": 443,
    "role": "",
}


def manual_run_code(row_count):
    """This is for manual running of the conversion perf"""
    with snowflake.connector.connect(**CONNECTION_PARAMETERS) as inner_conn:
        with inner_conn.cursor() as inner_cursor:
            res = inner_cursor.execute(
                f"select * from {TEST_TABLE_NAME} limit {row_count}"
            )
            # call fetch one here to force downloading all the result chunks first
            # result_set.py has been modified such that when it's called, it will wait until all chunks are downloaded,
            # such that the networking impact could be minimized
            print("*** start calling fetchone")
            res.fetchone()
            # fetchall() will iterate over all the PyArrowIterators and
            # call the converters to convert arrow data into python
            # objects, this is the method used to measure the performance
            print("*** start calling fetchall")
            start_time = time.time()
            remaining_rows = res.fetchall()
            duration = time.time() - start_time
            costed_time_per_row = duration / row_count
            assert len(remaining_rows) == row_count - 1
            inner_conn.close()
            print(
                f"Converted {row_count} rows of data in time {duration} seconds,"
                f" conversion time per row is {costed_time_per_row:.10f} seconds."
            )


def preload_data_into_db(row_count):
    # randomly generate row_count data into the test database
    sql = f"""
create or replace table {TEST_TABLE_NAME}(col1 varchar, col2 int, col3 date, col4 boolean) as
select randstr(1000, random()), uniform(1, 1000000, random()), CURRENT_DATE(), True
from table(generator(rowCount => {row_count}));
    """
    cursor.execute(sql)


def timeit_setup_code(row_count):
    return f"""
import snowflake.connector
CONNECTION_PARAMETERS = {CONNECTION_PARAMETERS}
conn = snowflake.connector.connect(**CONNECTION_PARAMETERS)
cursor = conn.cursor()
res = cursor.execute("select * from {TEST_TABLE_NAME} limit {row_count}")
res.fetchone()
    """


def timeit_stmt_code():
    return """
res.fetchall()
"""


try:
    conn = snowflake.connector.connect(**CONNECTION_PARAMETERS)
    cursor = conn.cursor()
    if CREATE_TABLE:
        preload_data_into_db(TEST_ROW_COUNTS[-1])
    for idx, row_count in enumerate(TEST_ROW_COUNTS):
        costed_time = timeit.timeit(
            stmt=timeit_stmt_code(), setup=timeit_setup_code(row_count)
        )
        costed_time_per_row = costed_time / row_count
        print(
            f"{idx + 1}. Converted {row_count} rows of data in time {costed_time} seconds,"
            f" conversion time per row is {costed_time_per_row:.10f} seconds."
        )
finally:
    if DROP_TABLE:
        cursor.execute(f"drop table {TEST_TABLE_NAME}")
    conn.close()


# uncomment the following line to verify the code logic by calling function manual_run_code
# manual_run_code(TEST_ROW_COUNTS[0])

""" sample results:
Test results based on M1 Macbook Pro, Chip is Apple M1 Max, Memory 64 GB, macOS Monterey v12.6, Python 3.10.6
Converted 10000 rows of data in time 0.32649300002958626 seconds, conversion time per row is 0.0000326493 seconds.
Converted 100000 rows of data in time 0.424488749995362 seconds, conversion time per row is 0.0000042449 seconds.
Converted 500000 rows of data in time 0.8756381669663824 seconds, conversion time per row is 0.0000017513 seconds.
Converted 1000000 rows of data in time 1.4148951250244863 seconds, conversion time per row is 0.0000014149 seconds.
Converted 2000000 rows of data in time 2.6491352079901844 seconds, conversion time per row is 0.0000013246 seconds.
Converted 5000000 rows of data in time 6.295799833955243 seconds, conversion time per row is 0.0000012592 seconds.
"""
