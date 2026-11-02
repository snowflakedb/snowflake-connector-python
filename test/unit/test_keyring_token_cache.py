from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from snowflake.connector.options import installed_keyring
from snowflake.connector.token_cache import (
    KeyringTokenCache,
    TokenKey,
    TokenType,
    _legacy_hash_key,
    _legacy_string_key,
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
SERVICE = KeyringTokenCache.KEYRING_SERVICE_NAME


class TestStore:
    def test_stores_using_shared_service_and_v2_key(self, cache, mock_keyring):
        cache.store(KEY, "tok123")
        mock_keyring.set_password.assert_called_once_with(SERVICE, FINAL_KEY, "tok123")

    def test_v2_key_starts_with_prefix(self, cache, mock_keyring):
        cache.store(KEY, "tok123")
        account = mock_keyring.set_password.call_args.args[1]
        assert account.startswith("SnowflakeTokenCache.v2.")

    def test_v2_key_differs_from_legacy_string_key(self, cache, mock_keyring):
        cache.store(KEY, "tok123")
        account = mock_keyring.set_password.call_args.args[1]
        legacy_service = (
            f"{KEY.snowflake.upper()}:{KEY.username.upper()}:{KEY.token_type.value}"
        )
        assert account != legacy_service, "v2 key should differ from legacy key"


class TestRetrieve:
    def test_retrieves_from_v2_key(self, cache, mock_keyring):
        mock_keyring.get_password.return_value = "tok123"
        assert cache.retrieve(KEY) == "tok123"
        mock_keyring.get_password.assert_called_once_with(SERVICE, FINAL_KEY)

    def test_does_not_read_legacy_layouts(self, cache, mock_keyring):
        mock_keyring.get_password.return_value = None
        assert cache.retrieve(KEY) is None
        mock_keyring.get_password.assert_called_once_with(SERVICE, FINAL_KEY)
        mock_keyring.set_password.assert_not_called()

    def test_does_not_read_pr7_five_field_v2_key(self, cache, mock_keyring):
        import hashlib
        import json

        stale_v2 = (
            "SnowflakeTokenCache.v2."
            + hashlib.sha256(
                json.dumps(
                    {
                        "idp": KEY.idp,
                        "role": KEY.role,
                        "snowflake": KEY.snowflake,
                        "token_type": "OAUTH_ACCESS_TOKEN",
                        "username": KEY.username,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        )

        def fake_get(service, account):
            if service == stale_v2:
                return "stale-pr7-token"
            return None

        mock_keyring.get_password.side_effect = fake_get
        assert cache.retrieve(KEY) is None
        mock_keyring.get_password.assert_called_once_with(SERVICE, FINAL_KEY)

    def test_oauth_legacy_string_key_uses_idp_host(self, cache, mock_keyring):
        """OAuth legacy keys must be built from the IdP hostname, not the SF host."""
        legacy_string = _legacy_string_key(KEY)
        assert legacy_string == "IDP.EXAMPLE.COM:ALICE:OAUTH_ACCESS_TOKEN"

    def test_mfa_legacy_string_key_is_user_host_swapped(self, cache, mock_keyring):
        """MFA/ID legacy keys are USER:HOST:TYPE because the old call site passed args
        in the wrong positional order (TokenKey(host, user, type) into (user, host, type)).
        """
        mfa_key = TokenKey(
            token_type=TokenType.MFA_TOKEN,
            idp="myhost.snowflakecomputing.com",
            snowflake="myhost.snowflakecomputing.com",
            username="ALICE",
            role="",
        )
        legacy_string = _legacy_string_key(mfa_key)
        # Old storage: USER:HOST:TYPE (swapped), not HOST:USER:TYPE
        assert legacy_string == "ALICE:MYHOST.SNOWFLAKECOMPUTING.COM:MFA_TOKEN"

    def test_returns_none_when_not_found_anywhere(self, cache, mock_keyring):
        mock_keyring.get_password.return_value = None
        assert cache.retrieve(KEY) is None


class TestRemove:
    def test_removes_using_v2_key_and_legacy_layouts(self, cache, mock_keyring):
        cache.remove(KEY)
        mock_keyring.delete_password.assert_has_calls(
            [
                call(SERVICE, FINAL_KEY),
                call(cache.SERVICE_NAME, _legacy_hash_key(KEY)),
                call(_legacy_string_key(KEY), ACCOUNT),
            ]
        )


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
        accounts = [c.args[1] for c in mock_keyring.set_password.call_args_list]
        assert accounts[0] != accounts[1], "different accounts must have different keys"

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
        accounts = [c.args[1] for c in mock_keyring.set_password.call_args_list]
        assert accounts[0] != accounts[1], "different roles must have different keys"
