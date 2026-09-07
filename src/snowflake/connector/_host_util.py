#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

"""Host normalization and recognition shared by every subsystem that turns a
connection host into the authority of a URL the connector builds itself.

Kept subsystem-agnostic so that WORKLOAD_IDENTITY attestation and OCSP cache-URL
derivation match hosts identically; a second, slightly different rule in either
place is what this module exists to prevent. The suffix list itself lives in
``constants`` so the data stays next to the connector's other TLD constants.
"""

from __future__ import annotations

from typing import Iterable

from .constants import _SNOWFLAKE_ALLOWED_HOST_SUFFIXES

# Maps only ASCII A-Z to a-z.
#
# Deliberately not str.lower(): full Unicode case folding maps some characters
# into ASCII, so a host containing U+212A KELVIN SIGN folds
# "snowfla<U+212A>ecomputing.com" into "snowflakecomputing.com" and would match a
# recognized suffix while DNS still resolves the original, unrelated name.
# Leaving non-ASCII untouched lets is_ldh_host reject it instead.
_ASCII_LOWERCASE_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
)

# Characters legal in a DNS hostname label, plus '_': account labels
# legitimately contain one.
_LDH_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")


def normalize_host(host: str | None) -> str:
    """Normalizes a host (or a configured host suffix) into the single string that
    every subsequent check and every derived URL must use.

    Trims, lower-cases ASCII only, drops everything from the first ':' onward,
    then strips exactly one trailing '.' (FQDN form).

    The port must be dropped before the trailing dot: a host in FQDN form
    carrying an explicit port ("acct.snowflakecomputing.com.:443") still has the
    dot immediately before the colon, and removing the dot first would leave it
    attached to the label and match no suffix.
    """
    if not host:
        return ""
    normalized = host.strip().translate(_ASCII_LOWERCASE_TABLE)
    if ":" in normalized:
        normalized = normalized.split(":", 1)[0]
    if normalized.endswith("."):
        normalized = normalized[:-1]
    return normalized


def is_ldh_host(normalized_host: str) -> bool:
    """Whether an already-normalized host is made only of characters legal in a
    DNS hostname: every dot-separated label non-empty and drawn from
    ``[a-z0-9_-]``.

    This is an allow-list, not a list of forbidden delimiters, and that
    distinction is load-bearing. A host is only safe to interpolate into a URL
    authority if it cannot carry a character that some URL parser treats as
    ending the host, and enumerating such characters does not work: parsers
    variously terminate the authority at a space, ';', "'", a percent-escape, or
    a full-width look-alike of '.', '#' or '?'. Since a host whose trailing
    labels are a recognized Snowflake domain can still begin with an unrelated
    name, a parser that stops early resolves that unrelated name instead.

    Args:
        normalized_host: output of :func:`normalize_host`.
    """
    if not normalized_host:
        return False
    return all(
        label and _LDH_CHARACTERS.issuperset(label)
        for label in normalized_host.split(".")
    )


def has_recognized_snowflake_suffix(
    normalized_host: str,
    extra_suffixes: Iterable[str] | None = None,
) -> bool:
    """Whether an already-normalized host ends at one of the recognized Snowflake
    suffixes, matched on a label boundary so that only a listed suffix and its
    subdomains qualify. The bare apex is accepted by the equality branch.

    Args:
        normalized_host: output of :func:`normalize_host`.
        extra_suffixes: additional already-normalized suffixes to accept.
            Additive only: callers cannot use this to disable the built-in list.
    """
    if not normalized_host:
        return False
    suffixes: tuple[str, ...] = _SNOWFLAKE_ALLOWED_HOST_SUFFIXES
    if extra_suffixes:
        suffixes = (*suffixes, *extra_suffixes)
    return any(
        normalized_host == suffix or normalized_host.endswith(f".{suffix}")
        for suffix in suffixes
        if suffix
    )
