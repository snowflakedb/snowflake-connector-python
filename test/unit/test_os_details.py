#!/usr/bin/env python
"""Tests for os_details module."""

from __future__ import annotations

from unittest import mock

import pytest

from snowflake.connector.os_details import extract_linux_os_release, get_os_details

MOCK_OS_RELEASE = """NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
VERSION_ID=20251019.0.436919
ANSI_COLOR="38;2;23;147;209"
HOME_URL="https://archlinux.org/"
DOCUMENTATION_URL="https://wiki.archlinux.org/"
SUPPORT_URL="https://bbs.archlinux.org/"
BUG_REPORT_URL="https://gitlab.archlinux.org/groups/archlinux/-/issues"
PRIVACY_POLICY_URL="https://terms.archlinux.org/docs/privacy-policy/"
LOGO=archlinux-logo"""


def test_extract_linux_os_release(tmp_path):
    """Test extracting OS release information from a file."""
    # Create a temporary os-release file
    os_release_file = tmp_path / "os-release"
    os_release_file.write_text(MOCK_OS_RELEASE)

    # Mock the file path
    with mock.patch("builtins.open", mock.mock_open(read_data=MOCK_OS_RELEASE)):
        result = extract_linux_os_release()

    # Verify only allowed keys are extracted
    assert result == {
        "NAME": "Arch Linux",
        "PRETTY_NAME": "Arch Linux",
        "ID": "arch",
        "BUILD_ID": "rolling",
        "VERSION_ID": "20251019.0.436919",
    }

    # Verify disallowed keys are not included
    assert "ANSI_COLOR" not in result
    assert "HOME_URL" not in result
    assert "LOGO" not in result


def test_extract_linux_os_release_with_quoted_values():
    """Test parsing values with and without quotes."""
    test_content = """NAME="Ubuntu"
ID=ubuntu
VERSION="22.04.1 LTS (Jammy Jellyfish)"
VERSION_ID=22.04"""

    with mock.patch("builtins.open", mock.mock_open(read_data=test_content)):
        result = extract_linux_os_release()

    assert result == {
        "NAME": "Ubuntu",
        "ID": "ubuntu",
        "VERSION": "22.04.1 LTS (Jammy Jellyfish)",
        "VERSION_ID": "22.04",
    }


def test_extract_linux_os_release_file_not_found():
    """Test handling when os-release file doesn't exist."""
    with mock.patch("builtins.open", side_effect=FileNotFoundError()):
        with pytest.raises(FileNotFoundError):
            extract_linux_os_release()


def test_get_os_details_on_linux():
    """Test get_os_details returns data on Linux."""
    # Reset the cache
    import snowflake.connector.os_details as os_details_module

    os_details_module._cached_os_details = None
    os_details_module._cache_initialized = False

    with mock.patch("platform.system", return_value="Linux"):
        with mock.patch("builtins.open", mock.mock_open(read_data=MOCK_OS_RELEASE)):
            result = get_os_details()

    assert result is not None
    assert result["NAME"] == "Arch Linux"
    assert result["ID"] == "arch"


def test_get_os_details_on_non_linux():
    """Test get_os_details returns None on non-Linux platforms."""
    # Reset the cache
    import snowflake.connector.os_details as os_details_module

    os_details_module._cached_os_details = None
    os_details_module._cache_initialized = False

    with mock.patch("platform.system", return_value="Darwin"):
        result = get_os_details()

    assert result is None


def test_get_os_details_caching():
    """Test that get_os_details caches the result."""
    # Reset the cache
    import snowflake.connector.os_details as os_details_module

    os_details_module._cached_os_details = None
    os_details_module._cache_initialized = False

    with mock.patch("platform.system", return_value="Linux"):
        with mock.patch(
            "builtins.open", mock.mock_open(read_data=MOCK_OS_RELEASE)
        ) as mock_file:
            # First call
            result1 = get_os_details()
            # Second call
            result2 = get_os_details()

            # File should only be opened once due to caching
            assert mock_file.call_count == 1
            assert result1 is result2


def test_get_os_details_error_handling():
    """Test get_os_details handles errors gracefully."""
    # Reset the cache
    import snowflake.connector.os_details as os_details_module

    os_details_module._cached_os_details = None
    os_details_module._cache_initialized = False

    with mock.patch("platform.system", return_value="Linux"):
        with mock.patch("builtins.open", side_effect=IOError("Permission denied")):
            result = get_os_details()

    # Should return None on error, not raise
    assert result is None


def test_os_release_empty_file():
    """Test handling of empty os-release file."""
    with mock.patch("builtins.open", mock.mock_open(read_data="")):
        result = extract_linux_os_release()

    assert result == {}


def test_os_release_malformed_lines():
    """Test handling of malformed lines in os-release."""
    test_content = """NAME="Ubuntu"
MALFORMED LINE WITHOUT EQUALS
ID=ubuntu
=invalid
ANOTHER_BAD_LINE
VERSION_ID=22.04"""

    with mock.patch("builtins.open", mock.mock_open(read_data=test_content)):
        result = extract_linux_os_release()

    # Should skip malformed lines and continue
    assert result == {
        "NAME": "Ubuntu",
        "ID": "ubuntu",
        "VERSION_ID": "22.04",
    }
