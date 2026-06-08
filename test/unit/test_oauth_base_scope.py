#!/usr/bin/env python
from __future__ import annotations

import pytest

from snowflake.connector.auth._oauth_base import AuthByOAuthBase


class _DummyOAuth(AuthByOAuthBase):
    """Minimal concrete subclass so we can instantiate the ABC for testing."""

    def _request_tokens(self, **kwargs):  # pragma: no cover - not exercised
        raise NotImplementedError

    def _get_oauth_type_id(self) -> str:  # pragma: no cover
        return "dummy"


@pytest.mark.parametrize(
    "token_request_url,initial_scope,expected_scope",
    [
        # External IdP (Okta): offline_access is appended (existing behavior)
        (
            "https://example.okta.com/oauth2/v1/token",
            "session:role:ANALYST",
            "session:role:ANALYST offline_access",
        ),
        # External IdP, empty scope: offline_access still appended
        (
            "https://example.okta.com/oauth2/v1/token",
            "",
            "offline_access",
        ),
        # Snowflake custom OAuth without refresh_token in scope: host check alone
        # skips offline_access (invalid_scope regression from #2885)
        (
            "https://abc123.snowflakecomputing.com/oauth/token-request",
            "session:role:ANALYST",
            "session:role:ANALYST",
        ),
        # Snowflake custom OAuth: offline_access is NOT appended (regression test)
        (
            "https://abc123.snowflakecomputing.com/oauth/token-request",
            "refresh_token session:role:ANALYST",
            "refresh_token session:role:ANALYST",
        ),
        # Snowflake .cn region without refresh_token in scope: also skipped
        (
            "https://abc123.snowflakecomputing.cn/oauth/token-request",
            "session:role:ANALYST",
            "session:role:ANALYST",
        ),
        # Snowflake .cn region: also skipped
        (
            "https://abc123.snowflakecomputing.cn/oauth/token-request",
            "refresh_token session:role:ANALYST",
            "refresh_token session:role:ANALYST",
        ),
        # User explicitly requested refresh_token against external IdP:
        # respect intent, don't double-append
        (
            "https://example.okta.com/oauth2/v1/token",
            "refresh_token session:role:ANALYST",
            "refresh_token session:role:ANALYST",
        ),
    ],
)
def test_offline_access_scope_handling(
    token_request_url, initial_scope, expected_scope
):
    auth = _DummyOAuth(
        client_id="cid",
        client_secret="csecret",
        token_request_url=token_request_url,
        scope=initial_scope,
        token_cache=None,
        refresh_token_enabled=True,
    )
    assert auth._scope == expected_scope


def test_offline_access_not_appended_when_refresh_disabled():
    auth = _DummyOAuth(
        client_id="cid",
        client_secret="csecret",
        token_request_url="https://example.okta.com/oauth2/v1/token",
        scope="session:role:ANALYST",
        token_cache=None,
        refresh_token_enabled=False,
    )
    assert auth._scope == "session:role:ANALYST"
