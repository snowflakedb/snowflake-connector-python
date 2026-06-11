#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

"""Unit tests for OAuth token caching infinite loop fix."""

import unittest.mock as mock
from unittest.mock import Mock, patch

import pytest

from snowflake.connector.auth import AuthByOauthCode
from snowflake.connector.token_cache import TokenCache, TokenKey, TokenType

pytestmark = pytest.mark.skipolddriver


@pytest.fixture()
def mock_connection():
    """Create a mock SnowflakeConnection."""
    conn = Mock()
    conn._authenticator = "oauth_authorization_code"
    conn.service_name = None
    conn.account = "test_account"
    conn.user = "test_user"
    conn.host = "test.snowflakecomputing.com"
    return conn


@pytest.fixture()
def mock_token_cache():
    """Create a mock TokenCache."""
    cache = Mock(spec=TokenCache)
    cache.retrieve = Mock(return_value=None)
    cache.store = Mock()
    cache.remove = Mock()
    return cache


@pytest.fixture()
def omit_oauth_urls_check():
    """Skip OAuth URL validation."""

    def get_first_two_args(authorization_url: str, redirect_uri: str, *args, **kwargs):
        return authorization_url, redirect_uri

    with mock.patch(
        "snowflake.connector.auth.oauth_code.AuthByOauthCode._validate_oauth_code_uris",
        side_effect=get_first_two_args,
    ):
        yield


class TestOAuthTokenCacheLoading:
    """Tests for _load_tokens_from_cache() - ensures tokens are loaded ONCE per connection."""

    def test_load_tokens_from_cache_loads_once(
        self, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify _load_tokens_from_cache() loads tokens only once."""
        mock_token_cache.retrieve.return_value = "test_access_token"

        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=True,
        )

        # First call should load from cache
        result1 = auth._load_tokens_from_cache("test_user")
        assert result1 is True
        assert auth._access_token == "test_access_token"

        # Second call should NOT load from cache again (already loaded)
        mock_token_cache.retrieve.reset_mock()
        result2 = auth._load_tokens_from_cache("test_user")
        assert result2 is True
        mock_token_cache.retrieve.assert_not_called()

    def test_load_tokens_from_cache_loads_both_tokens(
        self, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify both access and refresh tokens are loaded."""

        def mock_retrieve(key: TokenKey):
            if key.tokenType == TokenType.OAUTH_ACCESS_TOKEN:
                return "test_access_token"
            elif key.tokenType == TokenType.OAUTH_REFRESH_TOKEN:
                return "test_refresh_token"
            return None

        mock_token_cache.retrieve.side_effect = mock_retrieve

        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=True,
        )

        result = auth._load_tokens_from_cache("test_user")
        assert result is True
        assert auth._access_token == "test_access_token"
        assert auth._refresh_token == "test_refresh_token"
        # Should have called retrieve twice (access + refresh)
        assert mock_token_cache.retrieve.call_count == 2


class TestOAuthTokenCacheStorage:
    """Tests for _store_tokens() - ensures ACL is preserved by never calling remove()."""

    def test_store_tokens_never_calls_remove(
        self, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify _store_tokens() only calls store(), never remove() - preserves ACL."""
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=True,
        )
        auth._update_cache_keys("test_user")

        # Store tokens
        auth._store_tokens("new_access_token", "new_refresh_token")

        # Should call store() but NEVER remove()
        assert mock_token_cache.store.call_count == 2  # access + refresh
        mock_token_cache.remove.assert_not_called()

    def test_store_tokens_updates_memory_and_cache(
        self, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify _store_tokens() updates both in-memory and cached tokens."""
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=True,
        )
        auth._update_cache_keys("test_user")

        auth._store_tokens("new_access_token", "new_refresh_token")

        # Check in-memory
        assert auth._access_token == "new_access_token"
        assert auth._refresh_token == "new_refresh_token"

        # Check cache calls
        assert mock_token_cache.store.call_count == 2


class TestOAuthReauthenticateNoLoop:
    """Tests for reauthenticate() - ensures it doesn't call prepare() (prevents infinite loop)."""

    def test_reauthenticate_calls_request_tokens_directly(
        self, mock_connection, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify reauthenticate() calls _request_tokens() directly, NOT prepare()
        and never goes through conn.authenticate_with_retry (which is what caused the loop).
        """
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=False,  # No refresh token
        )
        auth._update_cache_keys("test_user")

        # Mock _request_tokens to return new tokens
        with patch.object(
            auth, "_request_tokens", return_value=("new_access", "new_refresh")
        ) as mock_request_tokens:
            with patch.object(auth, "prepare") as mock_prepare:
                result = auth.reauthenticate(conn=mock_connection)

                # Should call _request_tokens, NOT prepare()
                mock_request_tokens.assert_called_once()
                mock_prepare.assert_not_called()
                # Must NOT recurse via conn.authenticate_with_retry - that was the bug
                mock_connection.authenticate_with_retry.assert_not_called()
                assert result == {"success": True}

    def test_reauthenticate_does_not_recurse_through_authenticate_with_retry(
        self, mock_connection, mock_token_cache, omit_oauth_urls_check
    ):
        """Regression test: simulate the recursion path and verify it terminates.

        The original bug was: reauthenticate -> conn.authenticate_with_retry ->
        _authenticate -> prepare -> (cache miss) -> _request_tokens. If reauthenticate
        ever calls authenticate_with_retry again, we recurse forever. This test wires
        the mock so any such call would loop, then asserts the loop never starts."""
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=False,
        )
        auth._update_cache_keys("test_user")

        # If reauthenticate ever calls conn.authenticate_with_retry, simulate the
        # framework re-entering reauthenticate - which would have looped pre-fix.
        recursion_depth = {"count": 0}

        def fake_authenticate_with_retry(*_args, **_kwargs):
            recursion_depth["count"] += 1
            if recursion_depth["count"] > 5:
                raise RuntimeError("Infinite loop detected in reauthenticate")
            return auth.reauthenticate(conn=mock_connection)

        mock_connection.authenticate_with_retry.side_effect = (
            fake_authenticate_with_retry
        )

        with patch.object(
            auth, "_request_tokens", return_value=("new_access", "new_refresh")
        ):
            result = auth.reauthenticate(conn=mock_connection)

        # The recursion guard must never have fired
        assert recursion_depth["count"] == 0
        assert result == {"success": True}

    def test_reauthenticate_uses_cached_refresh_token(
        self, mock_connection, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify reauthenticate() uses in-memory refresh token without reading cache again."""
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=True,
        )
        auth._update_cache_keys("test_user")

        # Set in-memory refresh token (simulating it was loaded earlier)
        auth._refresh_token = "existing_refresh_token"

        # Mock _do_refresh_token to succeed
        with patch.object(auth, "_do_refresh_token") as mock_refresh:

            def set_access_token(*args, **kwargs):
                auth._access_token = "refreshed_access_token"

            mock_refresh.side_effect = set_access_token

            result = auth.reauthenticate(conn=mock_connection)

            # Should call _do_refresh_token using in-memory token
            mock_refresh.assert_called_once()
            # Should NOT read from cache again
            mock_token_cache.retrieve.assert_not_called()
            assert result == {"success": True}

    def test_reauthenticate_fails_when_request_tokens_returns_none(
        self, mock_connection, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify reauthenticate() does not return success with a None access token."""
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=False,
        )
        auth._update_cache_keys("test_user")

        # Make _handle_failure observable - the production code routes the failure
        # through Error.errorhandler_wrapper which can either raise or call back
        # depending on the connection config. Patching it lets us assert the
        # failure path was entered without depending on raise/return semantics.
        with patch.object(auth, "_request_tokens", return_value=(None, None)):
            with patch.object(auth, "_handle_failure") as mock_handle_failure:
                result = auth.reauthenticate(conn=mock_connection)

                mock_handle_failure.assert_called_once()
                assert result == {"success": False}
                # Must not have stored a None access token in the cache
                mock_token_cache.store.assert_not_called()


class TestOAuthOfflineAccessScope:
    """Tests for conditional offline_access scope - only added for external IdPs."""

    def test_offline_access_not_added_for_snowflake_idp(self, omit_oauth_urls_check):
        """Verify offline_access is NOT added when Snowflake is the OAuth provider."""
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            refresh_token_enabled=True,
        )

        # Snowflake as IdP should NOT have offline_access
        assert "offline_access" not in auth._scope
        assert auth._scope == "session:role:test"

    def test_offline_access_added_for_external_idp(self, omit_oauth_urls_check):
        """Verify offline_access IS added for external OAuth providers (Okta, etc.)."""
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://okta.example.com/oauth/authorize",
            "https://okta.example.com/oauth/token",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            refresh_token_enabled=True,
        )

        # External IdP should have offline_access
        assert "offline_access" in auth._scope
        assert auth._scope == "session:role:test offline_access"

    def test_offline_access_not_added_when_refresh_disabled(
        self, omit_oauth_urls_check
    ):
        """Verify offline_access is not added when refresh tokens are disabled."""
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://okta.example.com/oauth/authorize",
            "https://okta.example.com/oauth/token",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            refresh_token_enabled=False,  # Disabled
        )

        # Should NOT have offline_access when disabled
        assert "offline_access" not in auth._scope
        assert auth._scope == "session:role:test"

    def test_is_snowflake_as_idp_rejects_host_substring_spoof(
        self, omit_oauth_urls_check
    ):
        """Verify _is_snowflake_as_idp uses parsed hostname, not substring match.

        A URL like "https://acme.snowflakecomputing.com.attacker.example/oauth"
        contains the host as a substring but parses to a different hostname.
        Substring match would treat this as Snowflake-as-IdP and (a) skip the
        offline_access scope, (b) be a security smell. Hostname comparison rejects
        it correctly.
        """
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://acme.snowflakecomputing.com.attacker.example/oauth/authorize",
            "https://acme.snowflakecomputing.com.attacker.example/oauth/token",
            "http://localhost:8080",
            "session:role:test",
            "acme.snowflakecomputing.com",
            refresh_token_enabled=True,
        )

        # The spoof URL must NOT be classified as Snowflake-as-IdP, so
        # offline_access must be appended (external IdP behavior).
        assert "offline_access" in auth._scope
        assert auth._scope == "session:role:test offline_access"

    def test_is_snowflake_as_idp_only_one_url_matches(self, omit_oauth_urls_check):
        """Verify both authentication_url and token_request_url must match the host.

        If only one of them points at Snowflake and the other points elsewhere,
        the IdP is effectively external and offline_access should be appended.
        """
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://okta.example.com/oauth/token",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            refresh_token_enabled=True,
        )

        # Mixed URLs - treat as external IdP, must append offline_access
        assert "offline_access" in auth._scope


class TestOAuthPrepareUsesCache:
    """Tests for prepare() - ensures it uses _load_tokens_from_cache()."""

    def test_prepare_uses_cached_tokens(
        self, mock_connection, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify prepare() uses cached tokens and doesn't call _request_tokens()."""
        mock_token_cache.retrieve.return_value = "cached_access_token"

        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=False,
        )

        with patch.object(auth, "_request_tokens") as mock_request_tokens:
            auth.prepare(
                conn=mock_connection,
                authenticator="oauth_authorization_code",
                service_name=None,
                account="test_account",
                user="test_user",
            )

            # Should NOT call _request_tokens (token was cached)
            mock_request_tokens.assert_not_called()
            assert auth._access_token == "cached_access_token"

    def test_prepare_requests_new_tokens_when_cache_empty(
        self, mock_connection, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify prepare() requests new tokens when cache is empty."""
        mock_token_cache.retrieve.return_value = None  # Empty cache

        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=False,
        )

        with patch.object(
            auth, "_request_tokens", return_value=("new_access", "new_refresh")
        ) as mock_request_tokens:
            auth.prepare(
                conn=mock_connection,
                authenticator="oauth_authorization_code",
                service_name=None,
                account="test_account",
                user="test_user",
            )

            # Should call _request_tokens (cache was empty)
            mock_request_tokens.assert_called_once()


class TestOAuthStoreTokensNullKeyGuard:
    """Tests for _store_tokens() null key guard - prevents store(None, ...) when user unset."""

    def test_store_tokens_no_error_when_cache_keys_not_set(
        self, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify _store_tokens() is safe when _update_cache_keys() has not been called."""
        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=True,
        )
        # Deliberately NOT calling _update_cache_keys - _user is unset

        # Should not raise, and should not call store() with a None key
        auth._store_tokens("some_access_token", "some_refresh_token")

        # In-memory tokens are updated
        assert auth._access_token == "some_access_token"
        assert auth._refresh_token == "some_refresh_token"
        # Cache store must NOT be called because key would be None
        mock_token_cache.store.assert_not_called()


class TestOAuthResetTemporaryState:
    """Tests that _reset_temporary_state() resets _tokens_loaded_from_cache."""

    def test_reset_temporary_state_clears_loaded_flag(
        self, mock_token_cache, omit_oauth_urls_check
    ):
        """Verify _reset_temporary_state() resets the one-time-load guard."""
        mock_token_cache.retrieve.return_value = "cached_access_token"

        auth = AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=False,
        )

        # First load - marks flag True
        auth._load_tokens_from_cache("test_user")
        assert auth._tokens_loaded_from_cache is True

        # reset_secrets() calls _reset_temporary_state()
        auth.reset_secrets()
        assert auth._tokens_loaded_from_cache is False

        # A subsequent load should hit the cache again
        mock_token_cache.retrieve.reset_mock()
        auth._load_tokens_from_cache("test_user")
        mock_token_cache.retrieve.assert_called()


class TestOAuthRefreshTokenEviction:
    """Tests for _invalidate_refresh_token() - evicts dead tokens from keychain on IdP rejection."""

    def _make_auth(self, mock_token_cache, refresh_token_enabled=True):
        return AuthByOauthCode(
            "app",
            "clientId",
            "clientSecret",
            "https://test.snowflakecomputing.com/oauth/authorize",
            "https://test.snowflakecomputing.com/oauth/token-request",
            "http://localhost:8080",
            "session:role:test",
            "test.snowflakecomputing.com",
            token_cache=mock_token_cache,
            refresh_token_enabled=refresh_token_enabled,
        )

    def test_invalidate_refresh_token_removes_from_cache(
        self, mock_token_cache, omit_oauth_urls_check
    ):
        """_invalidate_refresh_token() clears memory and calls cache.remove()."""
        auth = self._make_auth(mock_token_cache)
        auth._update_cache_keys("test_user")
        auth._refresh_token = "stale_refresh_token"

        auth._invalidate_refresh_token()

        assert auth._refresh_token is None
        mock_token_cache.remove.assert_called_once()
        mock_token_cache.store.assert_not_called()

    def test_do_refresh_token_evicts_on_idp_rejection(
        self, mock_connection, mock_token_cache, omit_oauth_urls_check
    ):
        """When IdP responds but rejects the refresh token (no access_token in body),
        the stale refresh token is removed from the keychain."""
        auth = self._make_auth(mock_token_cache)
        auth._update_cache_keys("test_user")
        auth._refresh_token = "stale_refresh_token"

        # IdP returns a response but without access_token (e.g. {"error": "invalid_token"})
        bad_response = Mock()
        bad_response.data = b'{"error": "invalid_token"}'

        with patch.object(
            auth, "_get_refresh_token_response", return_value=bad_response
        ):
            auth._do_refresh_token(conn=mock_connection)

        assert auth._refresh_token is None
        mock_token_cache.remove.assert_called_once()

    def test_do_refresh_token_keeps_keychain_on_network_error(
        self, mock_connection, mock_token_cache, omit_oauth_urls_check
    ):
        """When refresh fails due to a network error (resp=None), the keychain
        entry is preserved - it may still be valid once connectivity is restored."""
        auth = self._make_auth(mock_token_cache)
        auth._update_cache_keys("test_user")
        auth._refresh_token = "valid_refresh_token"

        with patch.object(auth, "_get_refresh_token_response", return_value=None):
            auth._do_refresh_token(conn=mock_connection)

        assert auth._refresh_token is None  # cleared from memory
        mock_token_cache.remove.assert_not_called()  # keychain untouched
