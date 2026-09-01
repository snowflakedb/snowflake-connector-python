"""Tests for the v2 token cache key: normalization, building, and golden hash."""
from __future__ import annotations

import hashlib
import json

import pytest

from snowflake.connector.token_cache import (
    TokenKey,
    TokenType,
    _InvalidTokenKeyError,
    build_cache_key,
    normalize_identifier,
    normalize_url,
)

# ---------------------------------------------------------------------------
# normalize_url
# ---------------------------------------------------------------------------


def test_normalize_url_strips_https_scheme():
    assert normalize_url("https://example.com") == "EXAMPLE.COM"


def test_normalize_url_strips_http_scheme():
    assert normalize_url("http://example.com") == "EXAMPLE.COM"


def test_normalize_url_no_scheme():
    assert normalize_url("example.com") == "EXAMPLE.COM"


def test_normalize_url_preserves_port_and_path():
    assert (
        normalize_url("https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0")
        == "LOGIN.MICROSOFTONLINE.COM:443/TENANT-ID/OAUTH2/V2.0"
    )


def test_normalize_url_strips_userinfo():
    assert normalize_url("https://user:pass@example.com/path") == "EXAMPLE.COM/PATH"


def test_normalize_url_drops_query_and_fragment():
    assert normalize_url("https://example.com/path?q=1#frag") == "EXAMPLE.COM/PATH"


def test_normalize_url_trims_root_trailing_slash():
    assert normalize_url("https://example.com/") == "EXAMPLE.COM"


def test_normalize_url_keeps_non_root_trailing_slash_stripped():
    assert normalize_url("https://example.com/path/") == "EXAMPLE.COM/PATH"


def test_normalize_url_uppercases():
    assert (
        normalize_url("https://myorg-myaccount.privatelink.snowflakecomputing.com")
        == "MYORG-MYACCOUNT.PRIVATELINK.SNOWFLAKECOMPUTING.COM"
    )


# ---------------------------------------------------------------------------
# normalize_identifier
# ---------------------------------------------------------------------------


def test_normalize_identifier_unquoted_uppercased():
    assert normalize_identifier("north_america") == "NORTH_AMERICA"


def test_normalize_identifier_quoted_segment_verbatim():
    assert normalize_identifier('"First Last"') == '"First Last"'


def test_normalize_identifier_mixed():
    assert (
        normalize_identifier('"First Last"@long-corporate-domain.example.com')
        == '"First Last"@LONG-CORPORATE-DOMAIN.EXAMPLE.COM'
    )


def test_normalize_identifier_role_with_quoted_spaces():
    assert (
        normalize_identifier('"Analyst Role With Spaces":north_america:prod:readonly')
        == '"Analyst Role With Spaces":NORTH_AMERICA:PROD:READONLY'
    )


def test_normalize_identifier_empty():
    assert normalize_identifier("") == ""


# ---------------------------------------------------------------------------
# build_cache_key — validation
# ---------------------------------------------------------------------------


def test_build_cache_key_rejects_empty_snowflake():
    key = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        idp="https://example.com",
        snowflake="",
        username="user",
        role="",
    )
    with pytest.raises(_InvalidTokenKeyError):
        build_cache_key(key)


def test_build_cache_key_rejects_empty_username():
    key = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        idp="https://example.com",
        snowflake="https://example.snowflakecomputing.com",
        username="",
        role="",
    )
    with pytest.raises(_InvalidTokenKeyError):
        build_cache_key(key)


# ---------------------------------------------------------------------------
# Golden hash (LOCK — must not change)
# ---------------------------------------------------------------------------


def test_golden_hash():
    """Assert that the cache key hash is stable and must not change between releases.

    Quoted identifier segments (e.g. ``"FIRST LAST"``) contain uppercase content
    because ``normalize_identifier`` preserves them verbatim — the content inside
    quotes must already be in the correct case before normalization is called.
    """
    idp_raw = "https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0"
    snowflake_raw = "https://myorg-myaccount.privatelink.snowflakecomputing.com"
    # Quoted segments have uppercase content because normalize_identifier preserves them verbatim.
    username_raw = '"FIRST LAST"@long-corporate-domain.example.com'
    role_raw = '"ANALYST ROLE WITH SPACES":north_america:prod:readonly'

    canonical = json.dumps(
        {
            "idp": normalize_url(idp_raw),
            "role": normalize_identifier(role_raw),
            "snowflake": normalize_url(snowflake_raw),
            "token_type": "DPOP_BUNDLED_ACCESS_TOKEN",
            "username": normalize_identifier(username_raw),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert f"SnowflakeTokenCache.v2.{digest}" == (
        "SnowflakeTokenCache.v2."
        "75ff2ad65a68afb402f125f62894697673c5ef3d863aba466d16b7a81053d1f4"
    )


# ---------------------------------------------------------------------------
# build_cache_key — prefix and format
# ---------------------------------------------------------------------------


def test_build_cache_key_prefix():
    key = TokenKey(
        token_type=TokenType.OAUTH_ACCESS_TOKEN,
        idp="https://login.example.com/oauth2",
        snowflake="https://org.snowflakecomputing.com",
        username="alice",
        role="analyst",
    )
    result = build_cache_key(key)
    assert result.startswith("SnowflakeTokenCache.v2.")


def test_build_cache_key_hash_is_lowercase_hex():
    key = TokenKey(
        token_type=TokenType.ID_TOKEN,
        idp="https://host.example.com",
        snowflake="https://host.example.com",
        username="bob",
        role="",
    )
    suffix = build_cache_key(key).split(".")[-1]
    assert suffix == suffix.lower()
    assert len(suffix) == 64


# ---------------------------------------------------------------------------
# Dimension isolation — different field → different key
# ---------------------------------------------------------------------------


def _base_key(**overrides) -> TokenKey:
    defaults = dict(
        token_type=TokenType.OAUTH_ACCESS_TOKEN,
        idp="https://idp.example.com/oauth2",
        snowflake="https://org.snowflakecomputing.com",
        username="alice",
        role="analyst",
    )
    defaults.update(overrides)
    return TokenKey(**defaults)


def test_different_snowflake_host_yields_different_key():
    k1 = build_cache_key(_base_key(snowflake="https://org1.snowflakecomputing.com"))
    k2 = build_cache_key(_base_key(snowflake="https://org2.snowflakecomputing.com"))
    assert k1 != k2


def test_different_idp_yields_different_key():
    k1 = build_cache_key(_base_key(idp="https://idp1.example.com/oauth2"))
    k2 = build_cache_key(_base_key(idp="https://idp2.example.com/oauth2"))
    assert k1 != k2


def test_different_role_yields_different_key():
    k1 = build_cache_key(_base_key(role="analyst"))
    k2 = build_cache_key(_base_key(role="sysadmin"))
    assert k1 != k2


def test_different_token_type_yields_different_key():
    k1 = build_cache_key(_base_key(token_type=TokenType.OAUTH_ACCESS_TOKEN))
    k2 = build_cache_key(_base_key(token_type=TokenType.OAUTH_REFRESH_TOKEN))
    assert k1 != k2


def test_mfa_empty_role_yields_stable_distinct_key():
    mfa_key = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        idp="https://org.snowflakecomputing.com",
        snowflake="https://org.snowflakecomputing.com",
        username="alice",
        role="",
    )
    id_token_key = TokenKey(
        token_type=TokenType.ID_TOKEN,
        idp="https://org.snowflakecomputing.com",
        snowflake="https://org.snowflakecomputing.com",
        username="alice",
        role="",
    )
    mfa_result = build_cache_key(mfa_key)
    assert mfa_result == build_cache_key(mfa_key)
    assert mfa_result != build_cache_key(id_token_key)


def test_different_username_yields_different_key():
    k1 = build_cache_key(_base_key(username="alice"))
    k2 = build_cache_key(_base_key(username="bob"))
    assert k1 != k2


# ---------------------------------------------------------------------------
# Normalization is applied consistently
# ---------------------------------------------------------------------------


def test_case_insensitive_for_url_fields():
    """Uppercase and lowercase URLs produce the same key."""
    k_lower = build_cache_key(
        _base_key(
            idp="https://idp.example.com/oauth2",
            snowflake="https://org.snowflakecomputing.com",
        )
    )
    k_upper = build_cache_key(
        _base_key(
            idp="https://IDP.EXAMPLE.COM/OAUTH2",
            snowflake="https://ORG.SNOWFLAKECOMPUTING.COM",
        )
    )
    assert k_lower == k_upper


def test_scheme_stripped_from_url():
    k_with_scheme = build_cache_key(
        _base_key(snowflake="https://org.snowflakecomputing.com")
    )
    k_no_scheme = build_cache_key(_base_key(snowflake="org.snowflakecomputing.com"))
    assert k_with_scheme == k_no_scheme
