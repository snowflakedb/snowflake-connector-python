"""XP (Execution Platform) Support Module.

This package provides XP-specific implementations for the Snowflake connector,
including environment detection, network layer, and storage client.
"""

from __future__ import annotations

import logging
from functools import lru_cache

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def is_xp_environment() -> bool:
    """Check if running in Snowflake XP (stored procedure/UDF context).

    This function attempts to import both the _snowflake and _sfstream modules,
    which are only available when running inside Snowflake's Execution Platform.

    Returns:
        True if running in XP environment (both modules available), False otherwise.
    """
    try:
        import _sfstream  # noqa: F401
        import _snowflake  # noqa: F401

        logger.debug(
            "Detected XP environment (_snowflake and _sfstream modules available)"
        )
        return True
    except ImportError:
        logger.debug("Not in XP environment (XP modules not available)")
        return False


__all__ = ["is_xp_environment"]
