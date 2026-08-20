#!/usr/bin/env python
"""
Tests concurrent fetch of the same typed result set. Exercising both
independent connections and a shared connection path.
"""
from __future__ import annotations

import threading

N_THREADS = 12


def _typed_query(rowcount: int) -> str:
    # DATE, TIME, DECIMAL and TEXT so every lazy-init converter is exercised.
    return f"""
        select seq4() as n,
               dateadd(day, seq4(), to_date('2020-01-01')) as d,
               time_from_parts(mod(seq4(), 24), mod(seq4(), 60), mod(seq4(), 60)) as t,
               (seq4() / 1000.0)::decimal(18, 3) as dec,
               'row_' || seq4()::string as s
        from table(generator(rowcount => {rowcount}))
        order by n
    """


def _barrier_map(fn, n=N_THREADS):
    """Run ``fn(i, barrier)`` on ``n`` threads released together; collect results.

    The barrier maximizes the chance the threads collide (e.g. on a cold converter
    cache) versus starting staggered like ``ThreadPoolExecutor.map``. Returns
    (results, errors) with per-thread exceptions captured.
    """
    results: list = [None] * n
    errors: list = [None] * n
    barrier = threading.Barrier(n)

    def wrapped(i):
        try:
            results[i] = fn(i, barrier)
        except Exception as e:
            errors[i] = repr(e)

    threads = [threading.Thread(target=wrapped, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results, [e for e in errors if e is not None]


def test_concurrent_fetch_independent_connections(conn_cnx):
    """N threads, each its own connection, fetch the same typed result set."""
    query = _typed_query(3000)
    with conn_cnx() as cnx:
        reference = cnx.cursor().execute(query).fetchall()
    assert reference

    def worker(i, barrier):
        barrier.wait()
        with conn_cnx() as cnx:
            return cnx.cursor().execute(query).fetchall()

    results, errors = _barrier_map(worker)
    assert not errors, f"errors in concurrent independent connections: {errors}"
    for i, r in enumerate(results):
        assert r == reference, f"thread {i} differs from reference"


def test_concurrent_fetch_shared_connection(conn_cnx):
    """Many cursors on ONE shared connection execute/fetch concurrently."""
    query = _typed_query(1500)
    with conn_cnx() as cnx:
        reference = cnx.cursor().execute(query).fetchall()

        def worker(i, barrier):
            barrier.wait()
            cur = cnx.cursor()
            cur.execute(query)
            return cur.fetchall()

        results, errors = _barrier_map(worker)
    assert not errors, f"errors on shared-connection cursors: {errors}"
    for i, r in enumerate(results):
        assert r == reference, f"cursor {i} differs from reference"
