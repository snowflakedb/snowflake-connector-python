#!/usr/bin/env python
"""Concurrent stress harness for the nanoarrow PyArrow iterators (free-threading).

Example run:
    python local_iterator_concurrent.py --threads 16 --rounds 200
    python local_iterator_concurrent.py --unit table
    # under ThreadSanitizer (build the extension with -fsanitize=thread first):
    TSAN_OPTIONS=halt_on_error=1 python local_iterator_concurrent.py --threads 8 --rounds 50
"""
from __future__ import annotations

import argparse
import sys

from util import convert, draw_perf_graphs, load_arrow_bytes, run_concurrent

DEFAULT_DATA_FILE = "stress_test_data/test_data_all_types"

can_draw = True
try:
    import matplotlib.pyplot as plt  # noqa: F401
except ImportError:
    can_draw = False


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data-file", default=DEFAULT_DATA_FILE)
    p.add_argument("--threads", type=int, default=16)
    p.add_argument("--rounds", type=int, default=200)
    p.add_argument("--unit", choices=("row", "table"), default="row")
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
    data = load_arrow_bytes(args.data_file)
    use_table = args.unit == "table"
    perf_records = [] if args.draw else None
    rc = run_concurrent(
        lambda: convert(data, use_table),
        args.threads,
        args.rounds,
        perf_records=perf_records,
    )
    if args.draw and can_draw and perf_records:
        draw_perf_graphs(perf_records)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
