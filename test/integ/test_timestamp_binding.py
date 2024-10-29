#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from datetime import datetime
from typing import List

import pytest

from snowflake.connector.cursor import SnowflakeCursor

from ..randomize import random_string


def create_or_replace_table(cur: SnowflakeCursor, table_name: str, columns: List[str]):
    sql = f"CREATE OR REPLACE TEMP TABLE {table_name} ({','.join(columns)})"
    cur.execute(sql)


def insert_multiple_records(
    cur: SnowflakeCursor,
    table_name: str,
    ts: str,
    row_count: int,
    should_bind: bool,
):
    sql = f"INSERT INTO {table_name} values (?)"
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


@pytest.mark.parametrize(
    "timestamp_type, timestamp_precision",
    [
        ("TIMESTAMPTZ", 6),
    ],
)
def test_timestamp_bindings(
    conn_cnx, timestamp_type, timestamp_precision, db_parameters
):
    timestamp = "2023-03-15 13:17:29.207 +05:00"
    column_name = f"ts {timestamp_type}({timestamp_precision})"
    table_name = f"TEST_TIMESTAMP_BINDING_{random_string(10)}"
    binding_threshold = 65280

    with conn_cnx(paramstyle="qmark") as cnx:
        with cnx.cursor() as cur:
            create_or_replace_table(cur, table_name, [column_name])
            insert_multiple_records(
                cur, table_name, timestamp, binding_threshold + 1, True
            )
            res = cur.execute(f"select ts from {table_name}").fetchall()
            expected = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f %z")
            for r in res:
                assert r[0] == expected
