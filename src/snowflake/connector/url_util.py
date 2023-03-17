#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from logging import getLogger
import re
import urllib.parse

logger = getLogger(__name__)

class SnowflakeURLUtil:
    url_validator = re.compile(
        "^http(s?)\\:\\/\\/[0-9a-zA-Z]([-.\\w]*[0-9a-zA-Z@:])*(:(0-9)*)*(\\/?)([a-zA-Z0-9\\-\\.\\?\\,\\&\\(\\)\\/\\\\\\+&%\\$#_=@]*)?$")

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Confirms if the provided URL is a valid HTTP/ HTTPs URL

        Args:
            url: the URL that needs to be validated

        Returns:
            true/ false depending on whether the URL is valid or not
        """
        return SnowflakeURLUtil.url_validator.match(url)

    @staticmethod
    def url_encode_str(target: str) -> str:
        """ Converts a target string into escaped URL safe string

        Args:
            target: string to be URL encoded

        Returns:
            URL encoded string
        """
        if target is None:
            logger.debug("The string to be URL encoded is None")
            return ""
        return urllib.parse.quote_plus(target, safe='')
