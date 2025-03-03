#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import pytest

from snowflake.connector.auth import AuthNoAuth


@pytest.mark.skipolddriver
def test_auth_no_auth():
    """Simple test for AuthNoAuth."""
    auth = AuthNoAuth()

    body = {"data": {}}
    old_body = body
    auth.update_body(body)
    # update_body should be no-op for SP auth, therefore the body content should remain the same.
    assert body == old_body, f"body is {body}, old_body is {old_body}"

    # assertion_content should always return None in SP auth.
    assert auth.assertion_content is None, auth.assertion_content

    # reauthenticate should always return success.
    expected_reauth_response = {"success": True}
    reauth_response = auth.reauthenticate()
    assert (
        reauth_response == expected_reauth_response
    ), f"reauthenticate() is expected to return {expected_reauth_response}, but returns {reauth_response}"

    # It also returns success response even if we pass extra keyword argument(s).
    reauth_response = auth.reauthenticate(foo="bar")
    assert (
        reauth_response == expected_reauth_response
    ), f'reauthenticate(foo="bar") is expected to return {expected_reauth_response}, but returns {reauth_response}'
