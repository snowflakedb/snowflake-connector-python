#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import pytest

from snowflake.connector.cursor import SnowflakeCursor


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "sql, expected",
    [
        ("insert into test(c1) values   (%s)", "(%s)"),
        ("insert into test(c1, c2) values (%s, %s)", "(%s, %s)"),
        ("insert into test(c1, c2) VALUES (%d, 123)", "(%d, 123)"),
        (
            "insert into test(c1, c2) values (  %d,  %f, 123, %s   )  ;",
            "(  %d,  %f, 123, %s   )",
        ),
        ("insert into test(c1, c2) values (%s, '))((()(())(')", "(%s, '))((()(())(')"),
        (
            "insert into test(c1, c2) values (%s, '))((()(())(')))))))",
            "(%s, '))((()(())(')",
        ),
        (
            "insert into test (c1) (select parse_json(column1) as raw from values (%(raw)s))",
            "(%(raw)s)",
        ),
    ],
)
def test_match_insert_sql_values(sql: str, expected: str):
    from snowflake.connector.util_text import parse_pyformat_insertion_values

    text = SnowflakeCursor.INSERT_SQL_VALUES_RE.match(sql)
    assert text, "Failed to match VALUES clause"
    assert parse_pyformat_insertion_values(text.group(1)) == expected
