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


def test_normalize_url_strips_userinfo_and_lowercases_path():
    assert (
        normalize_url("https://user:pass@host.example.com/Path")
        == "host.example.com/path"
    )


def test_normalize_url_preserves_at_sign_in_path():
    assert (
        normalize_url("https://host.example.com/oauth/@handle/token")
        == "host.example.com/oauth/@handle/token"
    )


def test_normalize_url_drops_query_at_before_userinfo_when_url_has_no_path():
    assert normalize_url("https://host.example.com?user=a@b") == "host.example.com"
    assert (
        normalize_url("https://host.example.com?user=@evil.com") == "host.example.com"
    )
    assert normalize_url("https://host.example.com#@evil.com") == "host.example.com"


def test_normalize_url_preserves_at_sign_in_path_with_query_and_fragment():
    assert (
        normalize_url("https://host.example.com/oauth/@handle/token?x=1#frag")
        == "host.example.com/oauth/@handle/token"
    )


def test_normalize_url_drops_query_and_fragment():
    assert normalize_url("https://example.com/path?q=1#frag") == "example.com/path"


def test_normalize_url_trims_root_trailing_slash():
    assert normalize_url("https://example.com/") == "example.com"


def test_normalize_url_strips_non_root_trailing_slash():
    assert normalize_url("https://example.com/path/") == "example.com/path"


def test_normalize_url_strips_all_trailing_slashes():
    assert (
        normalize_url("https://idp.example.com/oauth/token/")
        == "idp.example.com/oauth/token"
    )
    assert (
        normalize_url("https://idp.example.com/oauth/token///")
        == "idp.example.com/oauth/token"
    )


def test_normalize_url_strips_uppercase_scheme_and_preserves_explicit_port():
    assert normalize_url("HTTPS://Example.COM:443/") == "example.com:443"


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


def test_build_cache_key_rejects_empty_idp_for_oauth():
    key = TokenKey(
        token_type=TokenType.OAUTH_ACCESS_TOKEN,
        snowflake="https://example.snowflakecomputing.com",
        username="user",
        idp="",
        role="analyst",
    )
    with pytest.raises(_InvalidTokenKeyError):
        build_cache_key(key)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"snowflake": "https://", "username": "user"},
        {"snowflake": "https://user:pass@", "username": "user"},
        {
            "snowflake": "https://example.snowflakecomputing.com",
            "username": "user",
            "token_type": TokenType.OAUTH_ACCESS_TOKEN,
            "idp": "https://",
            "role": "analyst",
        },
    ],
)
def test_build_cache_key_rejects_values_that_normalize_to_empty(kwargs):
    fields = {
        "token_type": TokenType.MFA_TOKEN,
        "snowflake": "https://example.snowflakecomputing.com",
        "username": "user",
        **kwargs,
    }
    with pytest.raises(_InvalidTokenKeyError):
        build_cache_key(TokenKey(**fields))


def test_build_cache_key_allows_empty_idp_and_role_for_mfa():
    key = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        snowflake="https://example.snowflakecomputing.com",
        username="user",
    )
    assert build_cache_key(key).startswith("SnowflakeTokenCache.v2.MfaToken.")


# ---------------------------------------------------------------------------
# Golden hash (LOCK — must not change)
# ---------------------------------------------------------------------------


def test_oauth_golden_hash():
    """Vector A — OAuth (DPoP) flow. Byte-exact key from raw inputs."""
    key = TokenKey(
        token_type=TokenType.DPOP_BUNDLED_ACCESS_TOKEN,
        idp="https://login.microsoftonline.com:443/tenant-id/oauth2/v2.0",
        role='"Analyst Role With Spaces":north_america:prod:readonly',
        snowflake="https://myorg-myaccount.privatelink.snowflakecomputing.com",
        username='"First Last"@long-corporate-domain.example.com',
    )
    assert build_cache_key(key) == (
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


def test_non_ascii_username_is_hashed_as_utf8_not_json_escaped():
    key = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        snowflake="https://example.snowflakecomputing.com",
        username="café",
    )
    snowflake_norm = normalize_url(key.snowflake)
    username_norm = normalize_identifier(key.username)
    canonical = json.dumps(
        {"snowflake": snowflake_norm, "username": username_norm},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert "\\u00e9" not in canonical
    assert "é" in canonical
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert build_cache_key(key) == f"SnowflakeTokenCache.v2.MfaToken.{digest}"


# ---------------------------------------------------------------------------
# build_cache_key — structural assertions
# ---------------------------------------------------------------------------


def test_mfa_key_has_no_idp_or_role():
    """MFA keyData is exactly snowflake and username; idp, role, and token_type are absent."""
    snowflake = "https://myorg.snowflakecomputing.com"
    username = "alice"
    without_extras = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        snowflake=snowflake,
        username=username,
    )
    with_extras = TokenKey(
        token_type=TokenType.MFA_TOKEN,
        snowflake=snowflake,
        username=username,
        idp="https://idp.example.com/oauth/token",
        role="ANALYST",
    )
    canonical = json.dumps(
        {
            "snowflake": normalize_url(snowflake),
            "username": normalize_identifier(username),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    expected = f"SnowflakeTokenCache.v2.MfaToken.{digest}"
    assert build_cache_key(without_extras) == expected
    assert build_cache_key(with_extras) == expected


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
