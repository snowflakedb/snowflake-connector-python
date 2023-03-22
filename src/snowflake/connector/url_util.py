#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import re
import urllib.parse
from logging import getLogger

logger = getLogger(__name__)


URL_VALIDATOR = re.compile(
    "^http(s?)\\:\\/\\/[0-9a-zA-Z]([-.\\w]*[0-9a-zA-Z@:])*(:(0-9)*)*(\\/?)([a-zA-Z0-9\\-\\.\\?\\,\\&\\(\\)\\/\\\\\\+&%\\$#_=@]*)?$"
)


def is_valid_url(url: str) -> bool:
    """Confirms if the provided URL is a valid HTTP/ HTTPs URL

    Args:
        url: the URL that needs to be validated

    Returns:
        true/ false depending on whether the URL is valid or not
    """
    return bool(URL_VALIDATOR.match(url))


def url_encode_str(target: str | None) -> str:
    """Converts a target string into escaped URL safe string

    Args:
        target: string to be URL encoded

    Returns:
        URL encoded string
    """
    if target is None:
        logger.debug("The string to be URL encoded is None")
        return ""
    return urllib.parse.quote_plus(target, safe="")
