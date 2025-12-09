"""
Pytest configuration for async authentication tests.

This module applies a default timeout to all tests in the test/auth/aio/ directory
to prevent tests from hanging indefinitely when waiting for external authentication
services (Snowflake connections, browser interactions, MFA, OAuth flows, etc.).
"""

from __future__ import annotations

import pytest

# Default timeout for all auth/aio tests (in seconds)
# These tests involve external services and browser automation,
# so they need sufficient time to complete but should not hang indefinitely.
DEFAULT_AUTH_TEST_TIMEOUT = 60  # seper test


def pytest_collection_modifyitems(items) -> None:
    """Apply default timeout to all tests in this directory."""
    for item in items:
        # Only add timeout if not already set
        if not any(mark.name == "timeout" for mark in item.iter_markers()):
            item.add_marker(pytest.mark.timeout(DEFAULT_AUTH_TEST_TIMEOUT))
