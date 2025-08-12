#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import logging

import snowflake.connector

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(threadName)s] %(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


CONNECTION_PARAMETERS = {}

stored_procedure_mocking_long_query_sql = """
CREATE OR REPLACE PROCEDURE reproduce_long_query_insert()
RETURNS VARCHAR NOT NULL
LANGUAGE SQL
AS
BEGIN
  insert into reproduce_table values(1);
  select system$wait(300);
END;
"""


with snowflake.connector.connect(**CONNECTION_PARAMETERS) as conn:
    with conn.cursor() as cursor:
        cursor.execute("create or replace table reproduce_table(col int);")
        cursor.execute(stored_procedure_mocking_long_query_sql)
        assert len(cursor.execute("select * from reproduce_table").fetchall()) == 0
        ret = cursor.execute("call reproduce_long_query_insert()")
        assert len(cursor.execute("select * from reproduce_table").fetchall()) == 1
