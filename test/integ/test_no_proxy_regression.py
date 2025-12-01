#!/usr/bin/env python
"""Integration test for SNOW-2865839 regression with real Snowflake connection."""
from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.aws


@pytest.mark.skipolddriver
def test_put_baseline(conn_cnx, tmp_path):
    """Baseline test: PUT works on real Snowflake without proxy."""
    # Create test file
    test_file = tmp_path / "test_data.csv"
    test_file.write_text("col1,col2\n1,2\n3,4\n")

    # Use REAL Snowflake connection (no proxy)
    with conn_cnx() as conn:
        with conn.cursor() as cur:
            # Create temp stage
            stage_name = f"test_baseline_stage_{os.getpid()}"
            cur.execute(f"CREATE TEMPORARY STAGE {stage_name}")

            # Execute PUT operation
            put_result = cur.execute(
                f"PUT 'file://{test_file}' @{stage_name}"
            ).fetchall()

            # Verify PUT succeeded
            assert len(put_result) > 0
            assert put_result[0][6] == "UPLOADED"

            # Verify file is on stage
            ls_result = cur.execute(f"LIST @{stage_name}").fetchall()
            assert len(ls_result) > 0
