#!/usr/bin/env python
"""Multithreaded stress tests for the connector's Arrow iterator on
free-threaded CPython.

These tests stress *only* the subset of connector code paths reachable
from a Snowflake stored procedure: no HTTP, no OCSP, no heartbeat
thread, no telemetry, no auth -- just the compiled Arrow iterator
and its per-type converters. Inside a stored procedure the connector's
``SnowflakeRestful`` is replaced by ``_StoredProcRestful`` which short-
circuits every network call into a C++ ``_snowflake.execute_sql``
binding, so the only Python-level multithreading exposure left is the
result-fetch path: cursor -> Arrow IPC bytes -> ``PyArrowRowIterator``
-> per-row converters.

Strategy
========

On a free-threaded interpreter (``python3.13t`` / ``python3.14t``, or
any build run with ``-X gil=0``) the GIL no longer serialises Python
bytecode, and -- crucially -- ``PyGILState_Ensure`` no longer provides
mutual exclusion either. Several places in the Arrow iterator's C++
backend cache an imported Python module / class lazily using a
``static py::UniqueRef`` with a check-then-set guard:

    static py::UniqueRef pyDatetimeDate;
    if (pyDatetimeDate.empty()) {
        py::importPythonModule("datetime", ...);
        py::importFromModule(..., "date", pyDatetimeDate);  // <- assigns
    }

C++11 "magic statics" only protect the *constructor* call of
``pyDatetimeDate`` -- the subsequent import-and-assign body is racy
under free-threading. Same pattern exists on:

  * ``Logger::log`` -- ``m_pyLogger`` (exercised by every
    ``CArrowIterator`` constructor via ``logger->debug(...)``)
  * ``DateConverter::initPyDatetimeDate``
  * ``TimeConverter::m_pyDatetimeTime``
  * ``DecimalBaseConverter::initPyDecimalConstructor``

To trip those races deterministically we (a) run each test in a fresh
subprocess so the static caches start cold, (b) generate Arrow IPC
payloads up-front in the parent so the worker threads only do
iterator construction and iteration, and (c) use a
``threading.Barrier`` so all workers cross the first-touch boundary
within microseconds of each other.

Pass criteria
=============

The subprocess must exit 0 and emit no:

  * ``RuntimeWarning`` mentioning the GIL  (CPython's defensive
    re-enable on a misdeclared extension)
  * ``Fatal Python error`` / ``Segmentation fault`` / ``Aborted``
  * uncaught Python exception from a worker thread
  * ``sys.unraisablehook`` callback (raised in __del__ etc.)

Skip criteria
=============

These tests are no-ops on GIL-enabled interpreters because the GIL
already serialises the lazy init. They also skip if ``pyarrow`` is
not installed (needed only to *generate* the Arrow IPC bytes in the
parent; the workers themselves don't need it).
"""
from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

_HAS_GIL_INTROSPECTION = hasattr(sys, "_is_gil_enabled")
_IS_FREETHREADED_RUNTIME = _HAS_GIL_INTROSPECTION and not sys._is_gil_enabled()


try:
    import pyarrow  # noqa: F401

    _HAS_PYARROW = True
except ImportError:
    _HAS_PYARROW = False


pytestmark = [
    pytest.mark.skipif(
        not _IS_FREETHREADED_RUNTIME,
        reason="free-threading stress tests only meaningful on a "
        "no-GIL interpreter (python3.13t / 3.14t or -X gil=0); "
        "on a GIL-enabled build the GIL trivially serialises the "
        "lazy init paths these tests target.",
    ),
    pytest.mark.skipif(
        not _HAS_PYARROW,
        reason="pyarrow is required to generate the Arrow IPC "
        "payloads the worker threads iterate over.",
    ),
]


# ---------------------------------------------------------------------
# Subprocess driver
# ---------------------------------------------------------------------
#
# Every test spawns ``sys.executable -X dev -W always -c '<worker>'`` so
# (a) static C++ caches start cold and any race manifests on the very
# first multi-threaded touch, (b) ``-X dev`` turns on extra runtime
# checks including ``sys.unraisablehook`` integration, and (c) ``-W
# always`` ensures every warning surfaces in stderr instead of being
# filtered by an earlier import.
#
# We pass the worker script via ``-c`` rather than a temp file so the
# test is self-contained and survives ``pytest -k`` selection without
# any fixture dance.


_SUBPROC_PRELUDE = """
import faulthandler, io, sys, threading, traceback

faulthandler.enable()  # SIGSEGV/SIGABRT -> python traceback to stderr

_UNRAISABLE = []

def _unraisable_hook(unraisable):
    _UNRAISABLE.append(
        f"{unraisable.exc_type.__name__}: {unraisable.exc_value!r} "
        f"(in {unraisable.object!r})"
    )

sys.unraisablehook = _unraisable_hook

_WORKER_EXCS = []
_WORKER_LOCK = threading.Lock()

def _run_safely(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except BaseException:  # noqa: BLE001 - we want to capture EVERYTHING
        with _WORKER_LOCK:
            _WORKER_EXCS.append(traceback.format_exc())
        raise

def _summarise_and_exit():
    if _WORKER_EXCS:
        print("WORKER_EXCEPTIONS:", file=sys.stderr)
        for e in _WORKER_EXCS:
            print(e, file=sys.stderr)
        sys.exit(3)
    if _UNRAISABLE:
        print("UNRAISABLE:", file=sys.stderr)
        for u in _UNRAISABLE:
            print(u, file=sys.stderr)
        sys.exit(4)
    sys.exit(0)
"""


_PAYLOAD_BUILDER = """
import datetime, decimal, random
import pyarrow as pa
from io import BytesIO

def _build(stype, vals, meta):
    s = BytesIO()
    schema = pa.schema([pa.field("c", stype, True, meta)])
    batch = pa.RecordBatch.from_pylist(
        [{"c": v} for v in vals], schema=schema
    )
    with pa.RecordBatchStreamWriter(s, schema) as w:
        w.write_batch(batch)
    return s.getvalue()

random.seed(0)

PAYLOAD_DATE = _build(
    pa.date32(),
    [datetime.date(2024, 1, i % 28 + 1) for i in range(64)],
    {"logicalType": "DATE"},
)
PAYLOAD_TIME = _build(
    pa.int64(),
    [random.randint(0, 86_399_999_999_999) for _ in range(64)],
    {"logicalType": "TIME", "scale": "9"},
)
PAYLOAD_DECIMAL = _build(
    pa.decimal128(10, 2),
    [decimal.Decimal(f"{random.randint(0, 1000)}.{random.randint(0, 99):02d}")
     for _ in range(64)],
    {"logicalType": "FIXED", "precision": "10", "scale": "2"},
)
PAYLOAD_INT = _build(
    pa.int64(),
    [random.randint(-2**40, 2**40) for _ in range(64)],
    {"logicalType": "FIXED", "precision": "18", "scale": "0"},
)
PAYLOAD_STRING = _build(
    pa.string(),
    [f"row-{i:05d}" for i in range(64)],
    {"logicalType": "TEXT"},
)
"""


def _run_stress(worker_body: str, *, timeout: int = 60) -> None:
    """Run ``worker_body`` (a snippet that uses PAYLOAD_* and _run_safely)
    in a fresh subprocess and assert clean exit.
    """
    script = (
        _SUBPROC_PRELUDE
        + _PAYLOAD_BUILDER
        + "\n"
        + textwrap.dedent(worker_body)
        + "\n_summarise_and_exit()\n"
    )
    proc = subprocess.run(
        [sys.executable, "-X", "dev", "-W", "always", "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    if proc.returncode != 0:
        pytest.fail(
            "Free-threading stress subprocess failed (exit "
            f"{proc.returncode}).\n"
            f"--- stderr ---\n{proc.stderr}\n"
            f"--- stdout ---\n{proc.stdout}"
        )

    gil_warnings = [
        line
        for line in proc.stderr.splitlines()
        if "global interpreter lock" in line.lower()
    ]
    if gil_warnings:
        pytest.fail(
            "Free-threading stress subprocess emitted GIL re-enable "
            f"warning(s):\n{chr(10).join(gil_warnings)}\n"
            f"--- full stderr ---\n{proc.stderr}"
        )


# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------


def test_concurrent_logger_init() -> None:
    """Stress ``Logger::log`` lazy init.

    Every ``CArrowIterator`` constructor ends with
    ``logger->debug(__FILE__, __func__, __LINE__, "Arrow BatchSize: %d", ...)``,
    which routes into ``Logger::log`` whose first call lazily imports
    ``snowflake.connector.snow_logging`` and stores the result on
    ``m_pyLogger``. We spawn many threads that each construct an iterator
    simultaneously; on a free-threaded build without ``std::call_once``,
    all of them race into ``setupPyLogger()``.
    """
    _run_stress(
        """
        from snowflake.connector.nanoarrow_arrow_iterator import (
            PyArrowRowIterator,
        )
        from snowflake.connector.arrow_context import ArrowConverterContext

        N_THREADS = 32
        N_ITERS_PER_THREAD = 16
        barrier = threading.Barrier(N_THREADS)

        def worker():
            ctx = ArrowConverterContext({"timezone": "UTC"})
            barrier.wait()
            for _ in range(N_ITERS_PER_THREAD):
                it = PyArrowRowIterator(
                    None, PAYLOAD_INT, ctx, False, False, False, True,
                )
                # Constructor logs "Arrow BatchSize: ..." - that's the
                # racy path. We still iterate so the test also exercises
                # the int converter, which has no lazy Python cache and
                # serves as a control.
                for _row in it:
                    pass

        threads = [
            threading.Thread(target=_run_safely, args=(worker,))
            for _ in range(N_THREADS)
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        """
    )


def test_concurrent_date_converter_first_touch() -> None:
    """Stress ``DateConverter::initPyDatetimeDate``.

    First row of the first batch triggers ``initPyDatetimeDate()`` which
    imports ``datetime.date`` and caches it on a function-local static.
    On a free-threaded build, N threads all on row 0 of their own
    iterator race the import + assign.
    """
    _run_stress(
        """
        from snowflake.connector.nanoarrow_arrow_iterator import (
            PyArrowRowIterator,
        )
        from snowflake.connector.arrow_context import ArrowConverterContext

        N_THREADS = 32
        N_ITERS_PER_THREAD = 8
        barrier = threading.Barrier(N_THREADS)

        def worker():
            ctx = ArrowConverterContext({"timezone": "UTC"})
            # Build the iterator BEFORE the barrier so all threads
            # cross the first-touch boundary (first next() -> first
            # DateConverter::toPyObject -> first initPyDatetimeDate call)
            # within microseconds of each other.
            iters = [
                PyArrowRowIterator(
                    None, PAYLOAD_DATE, ctx, False, False, False, True,
                )
                for _ in range(N_ITERS_PER_THREAD)
            ]
            barrier.wait()
            for it in iters:
                for _row in it:
                    pass

        threads = [
            threading.Thread(target=_run_safely, args=(worker,))
            for _ in range(N_THREADS)
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        """
    )


def test_concurrent_time_converter_first_touch() -> None:
    """Stress ``TimeConverter::m_pyDatetimeTime`` lazy init.

    Same pattern as the date test but exercises the time converter,
    which also has an ``if (empty()) { import + assign }`` pattern.
    """
    _run_stress(
        """
        from snowflake.connector.nanoarrow_arrow_iterator import (
            PyArrowRowIterator,
        )
        from snowflake.connector.arrow_context import ArrowConverterContext

        N_THREADS = 32
        N_ITERS_PER_THREAD = 8
        barrier = threading.Barrier(N_THREADS)

        def worker():
            ctx = ArrowConverterContext({"timezone": "UTC"})
            iters = [
                PyArrowRowIterator(
                    None, PAYLOAD_TIME, ctx, False, False, False, True,
                )
                for _ in range(N_ITERS_PER_THREAD)
            ]
            barrier.wait()
            for it in iters:
                for _row in it:
                    pass

        threads = [
            threading.Thread(target=_run_safely, args=(worker,))
            for _ in range(N_THREADS)
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        """
    )


def test_concurrent_decimal_converter_first_touch() -> None:
    """Stress ``DecimalBaseConverter::initPyDecimalConstructor`` lazy
    init. Same pattern; targets the ``decimal.Decimal`` cache.
    """
    _run_stress(
        """
        from snowflake.connector.nanoarrow_arrow_iterator import (
            PyArrowRowIterator,
        )
        from snowflake.connector.arrow_context import ArrowConverterContext

        N_THREADS = 32
        N_ITERS_PER_THREAD = 8
        barrier = threading.Barrier(N_THREADS)

        def worker():
            ctx = ArrowConverterContext({"timezone": "UTC"})
            iters = [
                PyArrowRowIterator(
                    None, PAYLOAD_DECIMAL, ctx, False, False, False, True,
                )
                for _ in range(N_ITERS_PER_THREAD)
            ]
            barrier.wait()
            for it in iters:
                for _row in it:
                    pass

        threads = [
            threading.Thread(target=_run_safely, args=(worker,))
            for _ in range(N_THREADS)
        ]
        for t in threads: t.start()
        for t in threads: t.join()
        """
    )


def test_mixed_converter_first_touch_storm() -> None:
    """Maximum-contention test: each worker thread is pinned to a
    different converter, so the first-touch storm hits all four lazy-
    init sites (logger + date + time + decimal) simultaneously.

    This mirrors a real stored-procedure workload where multiple
    cursors fetch result sets of different types in parallel.
    """
    _run_stress(
        """
        from snowflake.connector.nanoarrow_arrow_iterator import (
            PyArrowRowIterator,
        )
        from snowflake.connector.arrow_context import ArrowConverterContext

        PAYLOADS = [
            PAYLOAD_DATE,
            PAYLOAD_TIME,
            PAYLOAD_DECIMAL,
            PAYLOAD_INT,
            PAYLOAD_STRING,
        ]
        N_THREADS_PER_TYPE = 8
        N_ITERS_PER_THREAD = 16
        TOTAL = len(PAYLOADS) * N_THREADS_PER_TYPE
        barrier = threading.Barrier(TOTAL)

        def worker(payload):
            ctx = ArrowConverterContext({"timezone": "UTC"})
            iters = [
                PyArrowRowIterator(
                    None, payload, ctx, False, False, False, True,
                )
                for _ in range(N_ITERS_PER_THREAD)
            ]
            barrier.wait()
            for it in iters:
                for _row in it:
                    pass

        threads = []
        for p in PAYLOADS:
            for _ in range(N_THREADS_PER_TYPE):
                threads.append(
                    threading.Thread(target=_run_safely, args=(worker, p))
                )
        for t in threads: t.start()
        for t in threads: t.join()
        """,
        timeout=120,
    )
