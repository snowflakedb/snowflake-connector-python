from __future__ import annotations

import re
import urllib.parse
from logging import getLogger
from typing import Iterable

from .constants import _TOP_LEVEL_DOMAIN_REGEX
from .vendored import requests

logger = getLogger(__name__)


def is_valid_url(url: str) -> bool:
    """Confirms if the provided URL is a valid HTTP/HTTPS URL."""
    if not isinstance(url, str):
        return False
    if any(c <= "\x20" for c in url):
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except ValueError:
        return False


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


def extract_top_level_domain_from_hostname(hostname: str | None = None) -> str:
    if not hostname:
        return "com"
    # RFC1034 for TLD spec, and https://data.iana.org/TLD/tlds-alpha-by-domain.txt for full TLD list
    match = re.search(_TOP_LEVEL_DOMAIN_REGEX, hostname)
    return (match.group(0)[1:] if match else "com").lower()


def should_bypass_proxies(url: str | bytes, no_proxy: Iterable[str] | None) -> bool:
    return requests.utils.should_bypass_proxies(url, no_proxy)
