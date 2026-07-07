#!/usr/bin/env python
"""
Tests the nanoarrow converter backend driven concurrently by the
connector's internal ``client_prefetch_threads`` pool. Covers the default
python-object converters and the distinct numpy converter path.
"""
from __future__ import annotations

import datetime
from decimal import Decimal

import pytest


def test_single_query_prefetch_pool_conversion(conn_cnx):
    """A single large query whose chunks are converted by the
    client_prefetch_threads pool -- the default fetchall/to_pandas path.
    """
    rowcount = 200_000
    query = f"""
        select seq4() as n,
               dateadd(day, seq4(), to_date('2020-01-01')) as d,
               time_from_parts(mod(seq4(), 24), mod(seq4(), 60), mod(seq4(), 60)) as t,
               (seq4() / 1000.0)::decimal(18, 3) as dec,
               'row_' || seq4()::string as s
        from table(generator(rowcount => {rowcount}))
        order by n
    """
    for _ in range(3):
        with conn_cnx(client_prefetch_threads=4) as cnx:
            rows = cnx.cursor().execute(query).fetchall()
        assert len(rows) == rowcount
        assert rows[0][0] == 0 and rows[-1][0] == rowcount - 1
        first = rows[0]
        assert isinstance(first[1], datetime.date)
        assert isinstance(first[2], datetime.time)
        assert isinstance(first[3], Decimal)
        assert isinstance(first[4], str)


def test_numpy_prefetch_pool_conversion(conn_cnx):
    """The numpy converter path (``numpy=True``) driven concurrently by the
    prefetch pool. FIXED/REAL/TIMESTAMP_NTZ are converted to numpy scalars.
    """
    np = pytest.importorskip("numpy")
    rowcount = 200_000
    query = f"""
        select seq4() as n,
               (seq4() / 7.0)::double as f,
               dateadd(second, seq4(), '2020-01-01'::timestamp_ntz) as ts
        from table(generator(rowcount => {rowcount}))
        order by n
    """
    with conn_cnx(numpy=True, client_prefetch_threads=4) as cnx:
        rows = cnx.cursor().execute(query).fetchall()
    assert len(rows) == rowcount
    assert rows[0][0] == 0 and rows[-1][0] == rowcount - 1
    first = rows[0]
    assert isinstance(first[0], np.int64)
    assert isinstance(first[1], np.float64)
    assert isinstance(first[2], np.datetime64)
