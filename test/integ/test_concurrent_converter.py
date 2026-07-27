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

# Size of the connector's internal chunk download/convert pool.
CLIENT_PREFETCH_THREADS = 4


def test_single_query_prefetch_pool_conversion(conn_cnx):
    """A single large query whose chunks are converted by the
    client_prefetch_threads pool -- the default fetchall/to_pandas path.

    Type checks alone would survive a converter-cache race that hands back a
    correctly-typed but wrong object, so compare against a single-threaded
    (race-free) reference: the concurrent conversion must reproduce the exact
    values, not merely their types.
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
    # Race-free reference: a single prefetch thread converts chunks serially.
    with conn_cnx(client_prefetch_threads=1) as cnx:
        reference = cnx.cursor().execute(query).fetchall()
    assert len(reference) == rowcount
    assert reference[0][0] == 0 and reference[-1][0] == rowcount - 1
    first = reference[0]
    assert isinstance(first[1], datetime.date)
    assert isinstance(first[2], datetime.time)
    assert isinstance(first[3], Decimal)
    assert isinstance(first[4], str)

    # Check concurrent conversion reproduces the reference values exactly.
    for _ in range(3):
        with conn_cnx(client_prefetch_threads=CLIENT_PREFETCH_THREADS) as cnx:
            rows = cnx.cursor().execute(query).fetchall()
        assert rows == reference


def test_numpy_prefetch_pool_conversion(conn_cnx):
    """The numpy converter path (``numpy=True``) driven concurrently by the
    prefetch pool. FIXED/REAL/TIMESTAMP_NTZ are converted to numpy scalars.

    As above, compare the concurrent result against a single-threaded
    reference so a data-corrupting race is caught, not just a type mismatch.
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
    # Race-free reference: a single prefetch thread converts chunks serially.
    with conn_cnx(numpy=True, client_prefetch_threads=1) as cnx:
        reference = cnx.cursor().execute(query).fetchall()
    assert len(reference) == rowcount
    assert reference[0][0] == 0 and reference[-1][0] == rowcount - 1
    first = reference[0]
    assert isinstance(first[0], np.int64)
    assert isinstance(first[1], np.float64)
    assert isinstance(first[2], np.datetime64)

    # Check concurrent conversion reproduces the reference values exactly.
    with conn_cnx(numpy=True, client_prefetch_threads=CLIENT_PREFETCH_THREADS) as cnx:
        rows = cnx.cursor().execute(query).fetchall()
    assert len(rows) == rowcount
    assert all(
        a == b for row, ref in zip(rows, reference) for a, b in zip(row, ref)
    ), "concurrent numpy conversion diverged from the single-threaded reference"
