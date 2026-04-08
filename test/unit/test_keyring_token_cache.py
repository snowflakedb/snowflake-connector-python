from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from snowflake.connector.options import installed_keyring
from snowflake.connector.token_cache import KeyringTokenCache, TokenKey, TokenType

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


SERVICE = KeyringTokenCache.SERVICE_NAME
KEY = TokenKey(
    user="ALICE",
    host="myhost.snowflakecomputing.com",
    tokenType=TokenType.OAUTH_ACCESS_TOKEN,
)
ACCOUNT = KEY.hash_key()


class TestStore:
    def test_stores_under_unified_service_with_hashed_account(
        self, cache, mock_keyring
    ):
        cache.store(KEY, "tok123")
        mock_keyring.set_password.assert_called_once_with(
            SERVICE,
            ACCOUNT,
            "tok123",
        )
        assert ACCOUNT != KEY.string_key(), "account should be a hash, not plaintext"


class TestRetrieve:
    def test_retrieves_from_unified_service(self, cache, mock_keyring):
        mock_keyring.get_password.return_value = "tok123"
        assert cache.retrieve(KEY) == "tok123"
        mock_keyring.get_password.assert_called_once_with(SERVICE, ACCOUNT)

    def test_falls_back_to_legacy_and_migrates(self, cache, mock_keyring):
        mock_keyring.get_password.side_effect = [None, "legacy_tok"]
        result = cache.retrieve(KEY)
        assert result == "legacy_tok"
        mock_keyring.get_password.assert_has_calls(
            [
                call(SERVICE, ACCOUNT),
                call(KEY.string_key(), KEY.user.upper()),
            ]
        )
        mock_keyring.set_password.assert_called_once_with(
            SERVICE,
            ACCOUNT,
            "legacy_tok",
        )
        mock_keyring.delete_password.assert_called_once_with(
            KEY.string_key(),
            KEY.user.upper(),
        )

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
    def test_removes_from_unified_service(self, cache, mock_keyring):
        cache.remove(KEY)
        mock_keyring.delete_password.assert_called_once_with(SERVICE, ACCOUNT)


class TestServiceNameConstant:
    def test_all_token_types_share_service(self, cache, mock_keyring):
        mock_keyring.get_password.return_value = None
        for tt in TokenType:
            k = TokenKey(user="BOB", host="host.com", tokenType=tt)
            cache.store(k, "val")
        services = [c.args[0] for c in mock_keyring.set_password.call_args_list]
        assert all(s == SERVICE for s in services)
