import os


THIS_DIR = os.path.dirname(os.path.realpath(__file__))


def test_api(conn_testaccount):
    filepath = os.path.join(THIS_DIR, "../data", "segfault_query.sql")
    with open(filepath) as f:
        sql = f.read()

    conn = conn_testaccount
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()

    print(rows) # this prints rows without iterating them through Python, notice `<NULL>, <NULL>` - they are real, C-nulls! 
    rows[0][0] # this segfaults the process
