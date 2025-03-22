#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import unittest
from unittest.mock import Mock

import pytest

import snowflake.connector


@pytest.mark.skipolddriver
def test_auth_no_auth():
    """Simple test for AuthNoAuth."""

    # AuthNoAuth does not exist in old drivers, so we import at test level to
    # skip importing it for old driver tests.
    from snowflake.connector.auth.no_auth import AuthNoAuth

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


@pytest.mark.skipolddriver
def test_authenticate_for_no_auth():
    from snowflake.connector.auth import Auth
    from snowflake.connector.auth.no_auth import AuthNoAuth

    rest = None
    auth = Auth(rest)

    # Verify that when using AuthNoAuth, we can successfully call authenticate
    # even under these conditions
    #   - None account is provided
    #   - None user is provided
    #   - restful client is not set up
    auth.authenticate(AuthNoAuth(), account=None, user=None)


class TestHeartbeatExecutionFlowForNoAuth(unittest.TestCase):
    @pytest.mark.skipolddriver
    def test_hearbeat_execution_flow_for_no_auth(self):
        """Tests the heartbeat execution flow no-auth connections.

        No-auth connection relies on these facts
          - connection uses _heartbeat_tick method to perform heartbeat check
          - _heartbeat_tick method calls connection._rest._heartbeat method to
            send out the actual heartbeat request
          - client_session_keep_alive_heartbeat_frequency (setter) calls
            master_validity_in_seconds of the restful client to get the
            reasonable value range.
          - _validate_client_session_keep_alive_heartbeat_frequency calls
            master_validity_in_seconds of the restful client to get the
            reasonable value range.
        And this test serves as a simple indicator to tell developers when a
        code change breaks such assumptions.
        """
        # AuthNoAuth does not exist in old drivers, so we import at test level
        # to skip importing it for old driver tests.
        from snowflake.connector.auth.no_auth import AuthNoAuth

        no_auth = AuthNoAuth()
        conn = snowflake.connector.connect(auth_class=no_auth)
        # Simulate how we inject special restful client for no-auth connection.
        # And the tests verify that even with only the attributes listed below
        # available in conn._rest, the tested heartbeat functionalities are
        # still working as intended.
        conn._rest = Mock(spec=["_heartbeat", "master_validity_in_seconds"])
        conn._rest.master_validity_in_seconds = 100

        breaking_change_error_message = """
            Unexpected execution flow for heartbeat, this means potential
            changes to heartbeat mechanism that will break no-auth connection
            feature. Please contact the owner of AuthNoAuth before proceeding.
            Details: {details}
        """

        # Check that _heartbeat_tick is working as intended.
        try:
            conn._heartbeat_tick()
            conn._rest._heartbeat.assert_called_once()
        except Exception as e:
            raise AssertionError(breaking_change_error_message.format(details=str(e)))

        # Check that client_session_keep_alive_heartbeat_frequency setter is
        # working as intended with such a bare minimum set of interfaces
        # exposed in conn._rest.
        try:
            conn.client_session_keep_alive_heartbeat_frequency = 123
        except Exception as e:
            raise AssertionError(breaking_change_error_message.format(details=str(e)))

        # Check that _validate_client_session_keep_alive_heartbeat_frequency is
        # working as intended with such a bare minimum set of interfaces
        # exposed in conn._rest.
        try:
            conn._validate_client_session_keep_alive_heartbeat_frequency()
        except Exception as e:
            raise AssertionError(breaking_change_error_message.format(details=str(e)))

        # Indirect way to check that
        # client_session_keep_alive_heartbeat_frequency setter calls
        # master_validity_in_seconds in conn._rest.
        conn._rest = Mock(spec=["_heartbeat"])
        missing_master_validity_in_seconds_message = (
            "has no attribute 'master_validity_in_seconds'"
        )
        validity_dependency_change_template = (
            "{method} no longer relies on rest.master_validity_in_seconds"
        )
        try:
            # Verify that client_session_keep_alive_heartbeat_frequency setter
            # fails when conn._rest.master_validity_in_seconds method is
            # unavailable.
            with self.assertRaises(AttributeError) as context:
                conn.client_session_keep_alive_heartbeat_frequency = 123
            self.assertIn(
                missing_master_validity_in_seconds_message,
                str(context.exception),
            )
        except Exception:
            # This means there might be change breaking heartbeat mechanism for
            # no-auth connections.
            raise RuntimeError(
                breaking_change_error_message.format(
                    details=validity_dependency_change_template.format(
                        method="client_session_keep_alive_heartbeat_frequency (setter)"
                    )
                )
            )

        # Likewise, this is an indirect way to check that
        # _validate_client_session_keep_alive_heartbeat_frequency calls
        # master_validity_in_seconds in conn._rest.
        try:
            # Verify that _validate_client_session_keep_alive_heartbeat_frequency
            # fails when conn._rest.master_validity_in_seconds method is
            # unavailable.
            with self.assertRaises(AttributeError) as context:
                conn._validate_client_session_keep_alive_heartbeat_frequency()
            self.assertIn(
                missing_master_validity_in_seconds_message,
                str(context.exception),
            )
        except Exception:
            # This means there might be change breaking heartbeat mechanism for
            # no-auth connections.
            raise RuntimeError(
                breaking_change_error_message.format(
                    details=validity_dependency_change_template.format(
                        method="_validate_client_session_keep_alive_heartbeat_frequency"
                    )
                )
            )
