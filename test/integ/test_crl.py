#!/usr/bin/env python
"""
CRL (Certificate Revocation List) Validation Integration Tests

These tests verify that CRL validation works correctly with real Snowflake connections
in different modes: DISABLED, ADVISORY, and ENABLED.
"""
from __future__ import annotations

import tempfile

import pytest


@pytest.mark.skipolddriver
def test_crl_validation_enabled_mode(conn_cnx):
    """Test that connection works with CRL validation in ENABLED mode."""
    # ENABLED mode should work for normal Snowflake connections since they typically
    # have valid certificates with proper CRL distribution points
    with conn_cnx(
        cert_revocation_check_mode="ENABLED",
        allow_certificates_without_crl_url=True,  # Allow certs without CRL URLs
        crl_connection_timeout_ms=5000,  # 5 second timeout
        crl_read_timeout_ms=5000,  # 5 second timeout
        disable_ocsp_checks=True,
    ) as cnx:
        assert cnx, "Connection should succeed with CRL validation in ENABLED mode"

        # Verify we can execute a simple query
        cur = cnx.cursor()
        cur.execute("SELECT 1")
        result = cur.fetchone()
        assert result[0] == 1, "Query should execute successfully"
        cur.close()

        # Verify CRL settings were applied
        assert cnx.cert_revocation_check_mode == "ENABLED"
        assert cnx.allow_certificates_without_crl_url is True


@pytest.mark.skipolddriver
def test_crl_validation_advisory_mode(conn_cnx):
    """Test that connection works with CRL validation in ADVISORY mode."""
    # ADVISORY mode should be more lenient and allow connections even if CRL checks fail
    with conn_cnx(
        cert_revocation_check_mode="ADVISORY",
        allow_certificates_without_crl_url=False,  # Don't allow certs without CRL URLs
        crl_connection_timeout_ms=3000,  # 3 second timeout
        crl_read_timeout_ms=3000,  # 3 second timeout
        enable_crl_cache=True,  # Enable caching
        crl_cache_validity_hours=1,  # Cache for 1 hour
    ) as cnx:
        assert cnx, "Connection should succeed with CRL validation in ADVISORY mode"

        # Verify we can execute a simple query
        cur = cnx.cursor()
        cur.execute("SELECT CURRENT_VERSION()")
        result = cur.fetchone()
        assert result[0], "Query should return a version string"
        cur.close()

        # Verify CRL settings were applied
        assert cnx.cert_revocation_check_mode == "ADVISORY"
        assert cnx.allow_certificates_without_crl_url is False
        assert cnx.enable_crl_cache is True


@pytest.mark.skipolddriver
def test_crl_validation_disabled_mode(conn_cnx):
    """Test that connection works with CRL validation in DISABLED mode (default)."""
    # DISABLED mode should work without any CRL checks
    with conn_cnx(
        cert_revocation_check_mode="DISABLED",
    ) as cnx:
        assert cnx, "Connection should succeed with CRL validation in DISABLED mode"

        # Verify we can execute a simple query
        cur = cnx.cursor()
        cur.execute("SELECT 'CRL_DISABLED' as test_value")
        result = cur.fetchone()
        assert result[0] == "CRL_DISABLED", "Query should execute successfully"
        cur.close()

        # Verify CRL settings were applied
        assert cnx.cert_revocation_check_mode == "DISABLED"


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "crl_mode,allow_without_crl,should_succeed",
    [
        ("DISABLED", True, True),  # DISABLED mode always succeeds
        ("DISABLED", False, True),  # DISABLED mode always succeeds
        ("ADVISORY", True, True),  # ADVISORY mode is lenient
        ("ADVISORY", False, True),  # ADVISORY mode is lenient
        ("ENABLED", True, True),  # ENABLED with allow_without_crl should succeed
        ("ENABLED", False, True),  # ENABLED might succeed if certs have valid CRL URLs
    ],
)
def test_crl_validation_modes_parametrized(
    conn_cnx, crl_mode, allow_without_crl, should_succeed
):
    """Parametrized test for different CRL validation modes and settings."""
    try:
        with conn_cnx(
            cert_revocation_check_mode=crl_mode,
            allow_certificates_without_crl_url=allow_without_crl,
            crl_connection_timeout_ms=5000,
            crl_read_timeout_ms=5000,
        ) as cnx:
            if should_succeed:
                assert (
                    cnx
                ), f"Connection should succeed with mode={crl_mode}, allow_without_crl={allow_without_crl}"

                # Test basic functionality
                cur = cnx.cursor()
                cur.execute("SELECT 1")
                result = cur.fetchone()
                assert result[0] == 1, "Basic query should work"
                cur.close()

                # Verify settings
                assert cnx.cert_revocation_check_mode == crl_mode
                assert cnx.allow_certificates_without_crl_url == allow_without_crl
            else:
                pytest.fail(
                    f"Connection should have failed with mode={crl_mode}, allow_without_crl={allow_without_crl}"
                )

    except Exception as e:
        if should_succeed:
            pytest.fail(
                f"Connection unexpectedly failed with mode={crl_mode}, allow_without_crl={allow_without_crl}: {e}"
            )
        else:
            # Expected failure - verify it's a connection-related error
            assert (
                "revoked" in str(e).lower() or "crl" in str(e).lower()
            ), f"Expected CRL-related error, got: {e}"


@pytest.mark.skipolddriver
def test_crl_cache_configuration(conn_cnx):
    """Test CRL cache configuration options."""
    with tempfile.TemporaryDirectory() as temp_dir:
        with conn_cnx(
            cert_revocation_check_mode="ADVISORY",  # Use advisory to avoid strict failures
            enable_crl_cache=True,
            enable_crl_file_cache=True,
            crl_cache_dir=temp_dir,
            crl_cache_validity_hours=2,
            crl_cache_removal_delay_days=1,
            crl_cache_cleanup_interval_hours=1,
            crl_cache_start_cleanup=False,  # Don't start background cleanup in tests
        ) as cnx:
            assert cnx, "Connection should succeed with CRL cache configuration"

            # Verify cache settings were applied
            assert cnx.enable_crl_cache is True
            assert cnx.enable_crl_file_cache is True
            assert cnx.crl_cache_dir == temp_dir
            assert cnx.crl_cache_validity_hours == 2
            assert cnx.crl_cache_removal_delay_days == 1
            assert cnx.crl_cache_cleanup_interval_hours == 1
            assert cnx.crl_cache_start_cleanup is False

            # Test basic functionality
            cur = cnx.cursor()
            cur.execute("SELECT 'cache_test' as result")
            result = cur.fetchone()
            assert (
                result[0] == "cache_test"
            ), "Query should work with cache configuration"
            cur.close()
