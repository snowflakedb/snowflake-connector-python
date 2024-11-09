#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from snowflake.connector import connect

with connect() as conn:
    with conn.cursor() as cur:
        assert cur.execute("select 1;").fetchall() == [
            (1,),
        ]
