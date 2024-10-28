#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from datetime import datetime
from typing import List

from snowflake.connector.cursor import SnowflakeCursor

from ..randomize import random_string


def create_or_replace_table(cur: SnowflakeCursor, table_name: str, columns: List[str]):
    sql = f"CREATE OR REPLACE TEMP TABLE {table_name} ({','.join(columns)})"
    cur.execute(sql)


def insert_multiple_records(
    cur: SnowflakeCursor,
    table_name: str,
    column_names: List[str],
    ts: datetime,
    row_count: int,
    should_bind: bool,
):
    sql = f"INSERT INTO {table_name} ({','.join(column_names)}) values (?)"
    dates = [[ts] for _ in range(row_count)]
    cur.executemany(sql, dates)
    is_bind_sql_scoped = "SHOW stages like 'SNOWPARK_TEMP_STAGE_BIND'"
    is_bind_sql_non_scoped = "SHOW stages like 'SYSTEMBIND'"
    res1 = cur.execute(is_bind_sql_scoped).fetchall()
    res2 = cur.execute(is_bind_sql_non_scoped).fetchall()
    if should_bind:
        assert len(res1) != 0 or len(res2) != 0
    else:
        assert len(res1) == 0 and len(res2) == 0


def test_timestamp_bindings(conn):
    table_name = f"TEST_TIMESTAMP_BINDING_{random_string(10)}"
    print(table_name)
    # with conn.cursor() as cur:
    #     create_or_replace_table(cur, table_name, ["TIMESTAMP"])
