"""Regression tests for Arrow result fetching without pandas (the ``arrow`` extra).

``snowflake.connector.options`` resolves its optional dependencies once at
first import, and pytest has already imported the connector, so the
pandas/pyarrow availability matrix cannot be exercised in-process. The probes
run in a subprocess where the unwanted package is made unimportable through a
shim on PYTHONPATH.

The probes are marked ``pandas`` so they run in the CI environment that
installs both pandas and pyarrow; each subprocess then blocks the package it
needs absent.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest


def _run_probe(tmp_path, blocked_package: str, probe: str) -> None:
    (tmp_path / f"{blocked_package}.py").write_text(
        f"raise ImportError('{blocked_package} intentionally unavailable')\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(tmp_path), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    completed = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(probe)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.pandas
def test_arrow_support_does_not_require_pandas(tmp_path):
    """With pandas unimportable, Arrow support must still be fully available."""
    _run_probe(
        tmp_path,
        "pandas",
        """
        from types import SimpleNamespace

        from snowflake.connector import options
        from snowflake.connector.errors import ProgrammingError
        from snowflake.connector.result_batch import ArrowResultBatch

        assert options.installed_pyarrow is True
        assert options.installed_pandas is False

        batch = SimpleNamespace(
            _schema=[SimpleNamespace(name="VALUE", type_code=0)]
        )
        table = ArrowResultBatch._create_empty_table(batch)
        assert table.schema == options.pyarrow.schema(
            [options.pyarrow.field("VALUE", options.pyarrow.int64())]
        )

        try:
            ArrowResultBatch._check_can_use_pandas(batch)
        except ProgrammingError:
            pass
        else:
            raise AssertionError("pandas fetch support should remain unavailable")
        """,
    )


@pytest.mark.pandas
def test_pandas_support_still_requires_pyarrow(tmp_path):
    """With pandas importable but pyarrow missing, pandas features must fail fast."""
    _run_probe(
        tmp_path,
        "pyarrow",
        """
        import pandas  # noqa: F401 -- the scenario is pandas installed without pyarrow

        from snowflake.connector import options
        from snowflake.connector.errors import MissingDependencyError

        assert options.installed_pyarrow is False
        # pandas fetch APIs and write_pandas require pyarrow, so pandas support is
        # reported unavailable and using the pandas module fails fast
        assert options.installed_pandas is False
        try:
            options.pandas.DataFrame
        except MissingDependencyError:
            pass
        else:
            raise AssertionError("options.pandas should fail fast without pyarrow")
        """,
    )
