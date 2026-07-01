#!/usr/bin/env python
"""Regression tests for free-threaded (no-GIL) CPython support.

Guards the Cython ``freethreading_compatible`` directive and the C++
``std::call_once`` lazy-init fixes: importing the connector on a
free-threaded interpreter must not re-enable the GIL, and must not
regress the GIL-enabled build.

Tests run in a subprocess so import-time side-effects are observable
from a clean state -- pytest may have already imported the connector
before any test function runs.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

_HAS_GIL_INTROSPECTION = hasattr(sys, "_is_gil_enabled")


def _run_in_subprocess(script: str) -> subprocess.CompletedProcess[str]:
    """Run ``script`` in a fresh interpreter for a deterministic first-import measurement.

    In-process import is unusable: pytest has already imported the connector,
    so ``sys.modules`` caching hides GIL-state changes and warning deduplication
    suppresses any RuntimeWarning.
    """
    return subprocess.run(
        [sys.executable, "-W", "always", "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.skipif(
    not _HAS_GIL_INTROSPECTION,
    reason="sys._is_gil_enabled() requires Python 3.13+",
)
def test_connector_import_does_not_emit_gil_reenable_warning() -> None:
    """Importing the connector must not emit a RuntimeWarning about the GIL.

    C extensions declaring ``Py_MOD_GIL_USED`` cause CPython to re-enable the
    GIL at import time and emit such a warning. On GIL-enabled builds the
    warning never fires, but the test still exercises the import path.
    """
    proc = _run_in_subprocess(
        """
        import warnings
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            import snowflake.connector  # noqa: F401
            import snowflake.connector.nanoarrow_arrow_iterator  # noqa: F401
        gil_warnings = [
            (w.category.__name__, str(w.message))
            for w in caught
            if issubclass(w.category, RuntimeWarning)
            and 'global interpreter lock' in str(w.message).lower()
        ]
        if gil_warnings:
            import sys
            for cat, msg in gil_warnings:
                print(f'GIL_WARNING: {cat}: {msg}', file=sys.stderr)
            sys.exit(2)
        """
    )
    assert proc.returncode == 0, (
        f"Connector import emitted a GIL re-enable warning "
        f"(subprocess exit {proc.returncode}).\n"
        f"This typically means a compiled extension was added without "
        f"`# cython: freethreading_compatible = True` (Cython) or the "
        f"equivalent Py_mod_gil slot (hand-written extensions).\n"
        f"--- subprocess stderr ---\n{proc.stderr}\n"
        f"--- subprocess stdout ---\n{proc.stdout}"
    )


@pytest.mark.skipif(
    not _HAS_GIL_INTROSPECTION or sys._is_gil_enabled(),
    reason="requires a free-threaded interpreter with the GIL disabled "
    "(e.g. `python3.14t` or `python3.14 -X gil=0`)",
)
def test_connector_import_leaves_gil_disabled_on_freethreaded_build() -> None:
    """On a free-threaded build, the GIL must remain disabled after import.

    Stronger than the warning check: catches paths that re-enable the GIL
    without emitting a RuntimeWarning.
    """
    proc = _run_in_subprocess(
        """
        import sys
        import snowflake.connector  # noqa: F401
        import snowflake.connector.nanoarrow_arrow_iterator  # noqa: F401
        sys.exit(0 if sys._is_gil_enabled() is False else 1)
        """
    )
    assert proc.returncode == 0, (
        f"GIL was enabled after importing the connector on a free-threaded "
        f"interpreter (subprocess exit {proc.returncode}). The "
        f"`freethreading_compatible` directive or an equivalent Py_mod_gil "
        f"slot may be missing from a connector C extension.\n"
        f"--- subprocess stderr ---\n{proc.stderr}\n"
        f"--- subprocess stdout ---\n{proc.stdout}"
    )


@pytest.mark.skipif(
    not _HAS_GIL_INTROSPECTION or not sys._is_gil_enabled(),
    reason="requires a GIL-enabled interpreter (e.g. python3.14, " "not python3.14t)",
)
def test_connector_import_on_gil_build_leaves_gil_enabled() -> None:
    """On a GIL-enabled build, importing the connector must not disable the GIL.

    Catches the symmetric regression where ``freethreading_compatible``
    accidentally affects a non-free-threaded interpreter.
    """
    proc = _run_in_subprocess(
        """
        import sys
        import snowflake.connector  # noqa: F401
        import snowflake.connector.nanoarrow_arrow_iterator  # noqa: F401
        sys.exit(0 if sys._is_gil_enabled() is True else 1)
        """
    )
    assert proc.returncode == 0, (
        f"Unexpected GIL state after importing the connector on a "
        f"GIL-enabled interpreter (subprocess exit {proc.returncode}).\n"
        f"--- subprocess stderr ---\n{proc.stderr}\n"
        f"--- subprocess stdout ---\n{proc.stdout}"
    )
