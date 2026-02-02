#!/usr/bin/env python
"""Module for extracting OS details from /etc/os-release on Linux systems."""

from __future__ import annotations

import logging
import platform
import re

logger = logging.getLogger(__name__)

# Allowed keys to extract from /etc/os-release
ALLOWED_KEYS = [
    "NAME",
    "PRETTY_NAME",
    "ID",
    "BUILD_ID",
    "IMAGE_ID",
    "IMAGE_VERSION",
    "VERSION",
    "VERSION_ID",
]

# Regex to parse: KEY=value or KEY="value"
OS_RELEASE_KEY_VALUE_REGEX = re.compile(r'^([A-Z0-9_]+)=(?:"([^"]*)"|(.*))$')

# Cache the OS details so we only read the file once
_cached_os_details: dict[str, str] | None = None
_cache_initialized = False


def extract_linux_os_release() -> dict[str, str]:
    """
    Extract OS details from /etc/os-release file.

    Returns:
        Dictionary containing OS details with keys from ALLOWED_KEYS.

    Raises:
        FileNotFoundError: If /etc/os-release does not exist.
        IOError: If there's an error reading the file.
    """
    result: dict[str, str] = {}

    with open("/etc/os-release", encoding="utf-8") as f:
        contents = f.read()

    for line in contents.split("\n"):
        match = OS_RELEASE_KEY_VALUE_REGEX.match(line)
        if match:
            key, quoted_value, unquoted_value = match.groups()
            if key in ALLOWED_KEYS:
                result[key] = (
                    quoted_value if quoted_value is not None else unquoted_value
                )

    return result


def get_os_details() -> dict[str, str] | None:
    """
    Get OS details from /etc/os-release (Linux only).

    This function caches the result on first call. Returns None on non-Linux
    platforms or if there's an error reading the file.

    Returns:
        Dictionary containing OS details, or None if unavailable or on error.
    """
    global _cached_os_details, _cache_initialized

    if _cache_initialized:
        return _cached_os_details

    _cache_initialized = True

    # Only attempt to read os-release on Linux
    if platform.system() != "Linux":
        _cached_os_details = None
        return None

    try:
        _cached_os_details = extract_linux_os_release()
        return _cached_os_details
    except Exception as e:
        logger.debug("Error extracting OS details: %s", e)
        _cached_os_details = None
        return None
