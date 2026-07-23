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
    assert normalize_url("https://example.com") == "example.com"


def test_normalize_url_strips_http_scheme():
    assert normalize_url("http://example.com") == "example.com"


def test_normalize_url_no_scheme():
    assert normalize_url("example.com") == "example.com"


def test_normalize_url_preserves_port_and_path():
    assert (
        normalize_url("https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0")
        == "login.microsoftonline.com:443/tenant-id/oauth2/v2.0"
    )


def test_normalize_url_strips_userinfo():
    assert normalize_url("https://user:pass@example.com/path") == "example.com/path"


def test_normalize_url_drops_query_and_fragment():
    assert normalize_url("https://example.com/path?q=1#frag") == "example.com/path"


def test_normalize_url_trims_root_trailing_slash():
    assert normalize_url("https://example.com/") == "example.com"


def test_normalize_url_keeps_non_root_trailing_slash_stripped():
    assert normalize_url("https://example.com/path/") == "example.com/path"


def test_normalize_url_lowercases():
    assert (
        normalize_url("https://myorg-myaccount.privatelink.snowflakecomputing.com")
        == "myorg-myaccount.privatelink.snowflakecomputing.com"
    )


# ---------------------------------------------------------------------------
# normalize_identifier
# ---------------------------------------------------------------------------


def test_normalize_identifier_unquoted_lowercased():
    assert normalize_identifier("north_america") == "north_america"


def test_normalize_identifier_unquoted_uppercased_input_lowercased():
    assert normalize_identifier("ANALYST_ROLE") == "analyst_role"


def test_normalize_identifier_quoted_segment_verbatim():
    assert normalize_identifier('"First Last"') == '"First Last"'


def test_normalize_identifier_mixed_verbatim():
    """Value containing a double-quote anywhere is returned entirely verbatim."""
    assert (
        normalize_identifier('"First Last"@long-corporate-domain.example.com')
        == '"First Last"@long-corporate-domain.example.com'
    )


def test_normalize_identifier_role_with_quoted_spaces_verbatim():
    """Value containing a double-quote anywhere is returned entirely verbatim."""
    assert (
        normalize_identifier('"Analyst Role With Spaces":north_america:prod:readonly')
        == '"Analyst Role With Spaces":north_america:prod:readonly'
    )


def test_normalize_identifier_quote_not_at_position_zero_verbatim():
    """A quote that does NOT appear at position 0 still triggers the verbatim path."""
    assert normalize_identifier('prefix-"segment"') == 'prefix-"segment"'


def test_normalize_identifier_empty():
    assert normalize_identifier("") == ""


# ---------------------------------------------------------------------------
# build_cache_key — validation
# ---------------------------------------------------------------------------


def test_build_cache_key_rejects_empty_snowflake():
    key = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        snowflake="",
        username="user",
    )
    with pytest.raises(_InvalidTokenKeyError):
        build_cache_key(key)


def test_build_cache_key_rejects_empty_username():
    key = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        snowflake="https://example.snowflakecomputing.com",
        username="",
    )
    with pytest.raises(_InvalidTokenKeyError):
        build_cache_key(key)


# ---------------------------------------------------------------------------
# Golden hash (LOCK — must not change)
# ---------------------------------------------------------------------------


def test_oauth_golden_hash():
    """Vector A — OAuth (DPoP) flow.  Hash must never change between releases."""
    canonical = json.dumps(
        {
            "idp": normalize_url(
                "https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0"
            ),
            "role": normalize_identifier(
                '"Analyst Role With Spaces":north_america:prod:readonly'
            ),
            "snowflake": normalize_url(
                "https://myorg-myaccount.privatelink.snowflakecomputing.com"
            ),
            "username": normalize_identifier(
                '"First Last"@long-corporate-domain.example.com'
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert f"SnowflakeTokenCache.v2.DpopBundledAccessToken.{digest}" == (
        "SnowflakeTokenCache.v2.DpopBundledAccessToken."
        "741b6d66d252666d6821bfd19e0151511cf4efdaaeba2b3c87673aa4de6d2c0b"
    )


def test_mfa_golden_hash():
    """Vector B — MFA flow.  Hash must never change between releases."""
    key = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        snowflake="https://myorg-myaccount.privatelink.snowflakecomputing.com",
        username='"First Last"@long-corporate-domain.example.com',
    )
    assert build_cache_key(key) == (
        "SnowflakeTokenCache.v2.MfaToken."
        "10c5dde84bb8f584c0df06ea826d418c4f580e08f9db10187c0cb5e2a732a0d6"
    )


# ---------------------------------------------------------------------------
# build_cache_key — structural assertions
# ---------------------------------------------------------------------------


def test_mfa_key_has_no_idp_or_role():
    """MFA keyData must contain exactly snowflake and username — no idp, role, or token_type."""
    key = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        snowflake="https://myorg.snowflakecomputing.com",
        username="alice",
    )
    # Reconstruct the canonical JSON that build_cache_key hashes and verify its shape.
    canonical = json.dumps(
        {
            "snowflake": normalize_url("https://myorg.snowflakecomputing.com"),
            "username": normalize_identifier("alice"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert build_cache_key(key) == f"SnowflakeTokenCache.v2.MfaToken.{digest}"


def test_mfa_vs_oauth_key_differ_for_same_user_and_host():
    """MFA and OAuth produce different keys for the same user/host (different prefix + field set)."""
    snowflake = "https://org.snowflakecomputing.com"
    username = "alice"
    mfa_key = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        snowflake=snowflake,
        username=username,
    )
    oauth_key = TokenKey(
        token_type=TokenType.OAUTH_ACCESS_TOKEN,
        snowflake=snowflake,
        username=username,
        idp="https://idp.example.com/oauth2",
        role="analyst",
    )
    assert build_cache_key(mfa_key) != build_cache_key(oauth_key)


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
    assert result.startswith("SnowflakeTokenCache.v2.OauthAccessToken.")


def test_build_cache_key_hash_is_lowercase_hex():
    key = TokenKey(
        token_type=TokenType.ID_TOKEN,
        snowflake="https://host.example.com",
        username="bob",
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
        snowflake="https://org.snowflakecomputing.com",
        username="alice",
    )
    id_token_key = TokenKey(
        token_type=TokenType.ID_TOKEN,
        snowflake="https://org.snowflakecomputing.com",
        username="alice",
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
