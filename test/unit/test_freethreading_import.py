#!/usr/bin/env python
"""Regression tests for free-threaded (no-GIL) CPython support.

These tests guard the contract added in commit b75ab69e (Cython
``freethreading_compatible`` directive) and the C++ ``std::call_once``
fixes in commit ea1da38d: importing the connector on a free-threaded
interpreter must not re-enable the GIL, and must not regress the
GIL-enabled build either.

The three tests below give a positive-and-negative acknowledgement that
the wiring works end-to-end:

    1. Universal (3.13+): no GIL re-enable warning is emitted by any of
       the connector's compiled extensions during import. Runs on both
       ``python3.14`` (where the warning never fires anyway, so the
       assertion is trivially true) and ``python3.14t`` (where it
       catches an accidental Py_MOD_GIL_USED slot).

    2. 3.14t-only: after import, ``sys._is_gil_enabled()`` is still
       ``False``. Catches both the explicit re-enable above and any
       subtle path that flips the GIL back on at import time.

    3. 3.14-only: after import, ``sys._is_gil_enabled()`` is still
       ``True``. Catches the symmetric regression where the
       ``freethreading_compatible`` directive accidentally breaks the
       GIL-enabled build.

Together (1) + (2) prove the directive does what it should on a
free-threaded interpreter; (1) + (3) prove it is a no-op on the
GIL-enabled interpreter.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

_HAS_GIL_INTROSPECTION = hasattr(sys, "_is_gil_enabled")


def _run_in_subprocess(script: str) -> subprocess.CompletedProcess[str]:
    """Run ``script`` in a fresh interpreter so the connector's import-time
    behaviour is observable from a clean state.

    We can't just ``import snowflake.connector`` in-process: pytest itself
    almost certainly already imported it (via plugins, conftest, or other
    tests), so any GIL re-enable warning would have fired before the test
    function even ran, and ``sys.modules`` would already contain the
    compiled extension. A fresh subprocess gives us a deterministic
    "first import" measurement every time.
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
    """Importing the connector must not trigger CPython's defensive GIL
    re-enable warning.

    On a free-threaded interpreter, C extensions that declare
    ``Py_MOD_GIL_USED`` cause CPython to silently re-enable the GIL at
    import time and emit a ``RuntimeWarning``. This test asserts that no
    such warning is emitted -- i.e. every compiled extension the
    connector ships declares ``Py_MOD_GIL_NOT_USED`` (in our case via
    Cython's ``freethreading_compatible`` directive).

    The check is also run on GIL-enabled builds, where the warning never
    fires; the assertion is trivially true there, but the test still
    exercises the import path so a packaging regression that fails to
    install the .so at all would surface as an import error.
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
    """Negative ack: on a free-threaded build, the GIL stays disabled after
    importing the connector. Stronger than the warning check because it
    also catches subtle paths that might flip the GIL back on (e.g. a
    transitive C dependency that re-enables it at module init time
    without emitting a warning).
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
    """Positive ack: on a regular GIL-enabled 3.13+ build, importing the
    connector still works and the GIL stays enabled. Catches the
    symmetric regression where the ``freethreading_compatible`` directive
    accidentally breaks the GIL build, or where a hand-written extension
    flips the GIL off unexpectedly.
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
