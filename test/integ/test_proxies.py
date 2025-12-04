#!/usr/bin/env python
"""Integration test for proxy with real Snowflake connection.

Requirements:
    mitmproxy is installed automatically via the [development] extras in setup.cfg
    (Python 3.10+ only - mitmproxy has dependency conflicts on Python 3.9)

Important:
    When connecting through mitmproxy, you MUST set disable_ocsp_checks=True
    because mitmproxy performs MITM with self-signed certificates that cannot
    be validated via OCSP.
"""
from __future__ import annotations

import sys

import pytest

from snowflake.connector.compat import IS_WINDOWS

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from ..randomize import random_string


@pytest.mark.skipolddriver
@pytest.mark.skipif(
    sys.version_info < (3, 10),
    reason="mitmproxy not installed for Python 3.9 due to dependency conflicts",
)
def test_put_with_https_proxy(conn_cnx, tmp_path, mitm_proxy, monkeypatch):
    test_file = tmp_path / "test_data.csv"
    test_file.write_text("col1,col2\n1,2\n3,4\n")

    # Explicitly configure environment to use the proxy
    mitm_proxy.set_env_vars(monkeypatch)

    # Connect to REAL Snowflake through mitmproxy
    # Must disable OCSP checks since mitmproxy presents self-signed certs for MITM
    with conn_cnx(
        disable_ocsp_checks=True,
        login_timeout=60,  # Increase timeout for Windows proxy connection
        network_timeout=60,  # Increase socket read timeout for proxy connections
    ) as conn:
        with conn.cursor() as cur:
            stage_name = random_string(5, "test_proxy_")
            cur.execute(f"CREATE TEMPORARY STAGE {stage_name}")

            # Use str().replace() for cross-platform file URI compatibility (like other tests)
            filename = str(test_file).replace("\\", "/")
            put_result = cur.execute(
                f"PUT 'file://{filename}' @{stage_name}"
            ).fetchall()

            assert len(put_result) > 0
            assert put_result[0][6] == "UPLOADED"

            ls_result = cur.execute(f"LIST @{stage_name}").fetchall()
            assert len(ls_result) > 0


@pytest.mark.skipolddriver
@pytest.mark.skipif(
    sys.version_info < (3, 10) or IS_WINDOWS,
    reason="mitmproxy not installed for Python 3.9 due to dependency conflicts",
)
def test_put_with_https_proxy_and_no_proxy_regression(
    conn_cnx, tmp_path, mitm_proxy, monkeypatch
):
    """SNOW-2865839: PUT fails with TypeError when HTTPS_PROXY and NO_PROXY are set.

    From bug report:
    "HTTPS_PROXY=http://localhost:8080 NO_PROXY='google.com' python test.py"
    causes TypeError during PUT operations.

    Bug flow:
    1. HTTPS_PROXY set (mitmproxy)
    2. NO_PROXY set with ANY value (e.g., "google.com")
    3. Execute PUT operation
    4. storage_client passes bytes URL to use_session()
    5. Without fix: TypeError: inet_aton() argument 1 must be str, not bytes
    6. With fix: PUT succeeds
    """
    test_file = tmp_path / "test_data.csv"
    test_file.write_text("col1,col2\n1,2\n3,4\n")

    # Configure environment to use mitmproxy
    mitm_proxy.set_env_vars(monkeypatch)

    # Set NO_PROXY with arbitrary value (from bug report)
    monkeypatch.setenv("NO_PROXY", "google.com")

    with conn_cnx(
        disable_ocsp_checks=True,
        login_timeout=60,  # Increase timeout for Windows proxy connection
        network_timeout=60,  # Increase socket read timeout for proxy connections for Windows
    ) as conn:
        with conn.cursor() as cur:
            stage_name = random_string(5, "test_no_proxy_")
            cur.execute(f"CREATE TEMPORARY STAGE {stage_name}")

            # This is where the bug occurs - storage_client passes bytes URL
            # Use str().replace() for cross-platform file URI compatibility (like other tests)
            filename = str(test_file).replace("\\", "/")
            put_result = cur.execute(
                f"PUT 'file://{filename}' @{stage_name}"
            ).fetchall()

            assert len(put_result) > 0
            assert put_result[0][6] == "UPLOADED"

            ls_result = cur.execute(f"LIST @{stage_name}").fetchall()
            assert len(ls_result) > 0
