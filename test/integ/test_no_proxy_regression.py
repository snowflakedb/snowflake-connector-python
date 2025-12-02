#!/usr/bin/env python
"""Integration test for SNOW-2865839 regression with real Snowflake connection.

These tests verify that proxy settings (including NO_PROXY) work correctly.

Requirements:
    mitmproxy is installed automatically via the [development] extras in setup.cfg

The mitm_proxy fixture (session-scoped):
    - Starts a transparent HTTPS proxy once for all tests
    - Returns proxy information (does NOT auto-configure)
    - Tests control proxy usage via:
      1. mitm_proxy.set_env_vars(monkeypatch) - for environment variables
      2. conn_cnx(proxy_host=..., proxy_port=...) - for connection params

Important:
    When connecting through mitmproxy, you MUST set disable_ocsp_checks=True
    because mitmproxy performs MITM with self-signed certificates that cannot
    be validated via OCSP.
"""
from __future__ import annotations

import pytest

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from ..randomize import random_string

pytestmark = pytest.mark.aws


@pytest.mark.skipolddriver
def test_put_with_https_proxy_baseline(conn_cnx, tmp_path, mitm_proxy, monkeypatch):
    """Step 1: PUT through mitmproxy (no NO_PROXY yet).

    Establishes that transparent HTTPS proxy works with real Snowflake.
    This proves traffic flows through the proxy for all endpoints.
    """
    test_file = tmp_path / "test_data.csv"
    test_file.write_text("col1,col2\n1,2\n3,4\n")

    # Explicitly configure environment to use the proxy
    mitm_proxy.set_env_vars(monkeypatch)

    # Connect to REAL Snowflake through mitmproxy
    # Must disable OCSP checks since mitmproxy presents self-signed certs for MITM
    with conn_cnx(disable_ocsp_checks=True) as conn:
        with conn.cursor() as cur:
            stage_name = random_string(5, "test_proxy_baseline_")
            cur.execute(f"CREATE TEMPORARY STAGE {stage_name}")

            put_result = cur.execute(
                f"PUT 'file://{test_file}' @{stage_name}"
            ).fetchall()

            assert len(put_result) > 0
            assert put_result[0][6] == "UPLOADED"

            ls_result = cur.execute(f"LIST @{stage_name}").fetchall()
            assert len(ls_result) > 0
