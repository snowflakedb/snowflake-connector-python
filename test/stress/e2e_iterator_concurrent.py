#!/usr/bin/env python
"""Concurrent end-to-end stress harness for the fetch/convert path (free-threading).

Example run:
    python e2e_iterator_concurrent.py --threads 12 --rounds 20 --row_count 200
    python e2e_iterator_concurrent.py --unit table
    TSAN_OPTIONS=halt_on_error=1 python e2e_iterator_concurrent.py --threads 8 --rounds 10
"""
from __future__ import annotations

import argparse
import sys

from util import (
    draw_perf_graphs,
    prepare_data,
    run_concurrent,
    task_fetch_arrow_batches,
    task_fetch_rows,
)

import snowflake.connector
from parameters import CONNECTION_PARAMETERS

can_draw = True
try:
    import matplotlib.pyplot as plt  # noqa: F401
except ImportError:
    can_draw = False


def make_work(conn, unit: str, table_name: str, limit: int):
    """Return a no-arg callable that fetches on its own cursor of the shared
    connection and returns a comparable result, reusing the e2e_iterator tasks."""

    def work():
        cursor = conn.cursor()
        if unit == "table":
            # pyarrow RecordBatches aren't directly comparable -> normalize
            return [
                b.to_pydict()
                for b in task_fetch_arrow_batches(cursor, table_name, limit)
            ]
        return task_fetch_rows(cursor, table_name, limit)

    return work


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--threads", type=int, default=12)
    p.add_argument("--rounds", type=int, default=20)
    p.add_argument("--row_count", type=int, default=200)
    p.add_argument("--unit", choices=("row", "table"), default="row")
    p.add_argument("--test_table_name", type=str, default="ARROW_TEST_TABLE_CONCURRENT")
    p.add_argument("--draw", action="store_true", default=False)
    args = p.parse_args()

    gil = getattr(sys, "_is_gil_enabled", lambda: True)()
    print(
        f"interpreter: {sys.version.split()[0]} "
        f"({'GIL' if gil else 'FREE-THREADED'}); unit={args.unit}"
    )
    if gil:
        print(
            "NOTE: GIL is enabled -- races are masked; run on python3.14t for signal.",
            file=sys.stderr,
        )

    perf_records = [] if args.draw else None
    with snowflake.connector.connect(**CONNECTION_PARAMETERS) as conn:
        with conn.cursor() as cursor:
            prepare_data(cursor, args.row_count, args.test_table_name)
        work = make_work(conn, args.unit, args.test_table_name, args.row_count)
        rc = run_concurrent(work, args.threads, args.rounds, perf_records=perf_records)
    if args.draw and can_draw and perf_records:
        draw_perf_graphs(perf_records)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
