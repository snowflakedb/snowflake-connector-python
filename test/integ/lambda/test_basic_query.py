#!/usr/bin/env python


def test_connection(conn_cnx):
    """Test basic connection."""
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        result = cur.execute("select 1;").fetchall()
        assert result == [(1,)]


def test_large_resultset(conn_cnx):
    """Test large resultset."""
    with conn_cnx() as cnx:
        cur = cnx.cursor()
        result = cur.execute(
            "select seq8(), randstr(1000, random()) from table(generator(rowcount=>10000));"
        ).fetchall()
        assert len(result) == 10000
