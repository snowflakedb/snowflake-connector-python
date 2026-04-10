from snowflake.connector import connect

from ..parameters import CONNECTION_PARAMETERS

with connect(**CONNECTION_PARAMETERS) as conn:
    with conn.cursor() as cur:
        assert cur.execute("select 1;").fetchall() == [
            (1,),
        ]
