from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from snowflake.connector.options import installed_keyring
from snowflake.connector.token_cache import (
    KeyringTokenCache,
    TokenKey,
    TokenType,
    build_cache_key,
)

pytestmark = pytest.mark.skipif(
    not installed_keyring,
    reason="keyring is not installed",
)


@pytest.fixture
def mock_keyring():
    with patch("snowflake.connector.token_cache.keyring") as kr:
        kr.errors = MagicMock()
        kr.errors.KeyringError = type("KeyringError", (Exception,), {})
        yield kr


@pytest.fixture
def cache():
    return KeyringTokenCache()


KEY = TokenKey(
    token_type=TokenType.OAUTH_ACCESS_TOKEN,
    idp="https://idp.example.com/oauth2",
    snowflake="myhost.snowflakecomputing.com",
    username="ALICE",
    role="",
)
FINAL_KEY = build_cache_key(KEY)
ACCOUNT = KEY.username.upper()


class TestStore:
    def test_stores_using_v2_key_as_service(self, cache, mock_keyring):
        cache.store(KEY, "tok123")
        mock_keyring.set_password.assert_called_once_with(FINAL_KEY, ACCOUNT, "tok123")

    def test_v2_key_starts_with_prefix(self, cache, mock_keyring):
        cache.store(KEY, "tok123")
        service = mock_keyring.set_password.call_args.args[0]
        assert service.startswith("SnowflakeTokenCache.v2.")

    def test_v2_key_differs_from_legacy_string_key(self, cache, mock_keyring):
        cache.store(KEY, "tok123")
        service = mock_keyring.set_password.call_args.args[0]
        legacy_service = f"{KEY.snowflake.upper()}:{KEY.username.upper()}:{KEY.token_type.value}"
        assert service != legacy_service, "v2 key should differ from legacy key"


class TestRetrieve:
    def test_retrieves_from_v2_key(self, cache, mock_keyring):
        mock_keyring.get_password.return_value = "tok123"
        assert cache.retrieve(KEY) == "tok123"
        mock_keyring.get_password.assert_called_once_with(FINAL_KEY, ACCOUNT)

    def test_falls_back_to_legacy_and_migrates(self, cache, mock_keyring):
        legacy_service = f"{KEY.snowflake.upper()}:{KEY.username.upper()}:{KEY.token_type.value}"
        mock_keyring.get_password.side_effect = [None, "legacy_tok"]
        result = cache.retrieve(KEY)
        assert result == "legacy_tok"
        mock_keyring.get_password.assert_has_calls(
            [
                call(FINAL_KEY, ACCOUNT),
                call(legacy_service, ACCOUNT),
            ]
        )
        mock_keyring.set_password.assert_called_once_with(FINAL_KEY, ACCOUNT, "legacy_tok")
        mock_keyring.delete_password.assert_called_once_with(legacy_service, ACCOUNT)

    def test_returns_none_when_not_found_anywhere(self, cache, mock_keyring):
        mock_keyring.get_password.return_value = None
        assert cache.retrieve(KEY) is None

    def test_legacy_delete_failure_is_nonfatal(self, cache, mock_keyring):
        mock_keyring.get_password.side_effect = [None, "legacy_tok"]
        mock_keyring.delete_password.side_effect = Exception("denied")
        result = cache.retrieve(KEY)
        assert result == "legacy_tok"
        mock_keyring.set_password.assert_called_once()


class TestRemove:
    def test_removes_using_v2_key(self, cache, mock_keyring):
        cache.remove(KEY)
        mock_keyring.delete_password.assert_called_once_with(FINAL_KEY, ACCOUNT)


class TestMultiAccount:
    def test_different_accounts_produce_different_keys(self, cache, mock_keyring):
        """Keys for different accounts never collide."""
        mock_keyring.get_password.return_value = None
        key1 = TokenKey(
            token_type=TokenType.OAUTH_ACCESS_TOKEN,
            idp="https://idp.example.com/oauth2",
            snowflake="account1.snowflakecomputing.com",
            username="USER",
            role="",
        )
        key2 = TokenKey(
            token_type=TokenType.OAUTH_ACCESS_TOKEN,
            idp="https://idp.example.com/oauth2",
            snowflake="account2.snowflakecomputing.com",
            username="USER",
            role="",
        )
        cache.store(key1, "val1")
        cache.store(key2, "val2")
        services = [c.args[0] for c in mock_keyring.set_password.call_args_list]
        assert services[0] != services[1], "different accounts must have different keys"

    def test_different_roles_produce_different_keys(self, cache, mock_keyring):
        """Keys for different roles never collide."""
        mock_keyring.get_password.return_value = None
        key1 = TokenKey(
            token_type=TokenType.OAUTH_ACCESS_TOKEN,
            idp="https://idp.example.com/oauth2",
            snowflake="account.snowflakecomputing.com",
            username="USER",
            role="ANALYST",
        )
        key2 = TokenKey(
            token_type=TokenType.OAUTH_ACCESS_TOKEN,
            idp="https://idp.example.com/oauth2",
            snowflake="account.snowflakecomputing.com",
            username="USER",
            role="SYSADMIN",
        )
        cache.store(key1, "val1")
        cache.store(key2, "val2")
        services = [c.args[0] for c in mock_keyring.set_password.call_args_list]
        assert services[0] != services[1], "different roles must have different keys"
