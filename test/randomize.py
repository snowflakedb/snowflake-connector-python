#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

"""
This module was added back to the repository for compatibility with the old driver tests that
rely on random_string from this file for functionality.
"""

from __future__ import annotations

import random
import string
from typing import Sequence


def random_string(
    length: int,
    prefix: str = "",
    suffix: str = "",
    choices: Sequence[str] = string.ascii_lowercase,
) -> str:
    """Our convenience function to generate random string for object names.
    Args:
        length: How many random characters to choose from choices.
        prefix: Prefix to add to random string generated.
        suffix: Suffix to add to random string generated.
        choices: A generator of things to choose from.
    """
    random_part = "".join([random.choice(choices) for _ in range(length)])
    return "".join([prefix, random_part, suffix])
