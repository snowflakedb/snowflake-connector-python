#!/usr/bin/env python
"""Tests for the secondary_roles connection parameter."""

from __future__ import annotations

import json
from unittest.mock import Mock, PropertyMock

import pytest

from snowflake.connector.auth import Auth, AuthByDefault
from snowflake.connector.constants import OCSPMode
from snowflake.connector.description import CLIENT_NAME, CLIENT_VERSION
from snowflake.connector.network import SnowflakeRestful

from .mock_utils import mock_connection


def _init_rest_with_secondary_roles(application, secondary_roles, post_request):
    """Initialize a REST client with secondary_roles configured."""
    connection = mock_connection()
    connection.errorhandler = Mock(return_value=None)
    connection._ocsp_mode = Mock(return_value=OCSPMode.FAIL_OPEN)
    connection.cert_revocation_check_mode = "TEST_CRL_MODE"
    connection._secondary_roles = secondary_roles
    type(connection).application = PropertyMock(return_value=application)
    type(connection)._internal_application_name = PropertyMock(return_value=CLIENT_NAME)
    type(connection)._internal_application_version = PropertyMock(
        return_value=CLIENT_VERSION
    )

    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )
    rest._post_request = post_request
    return rest


def _create_mock_auth_success_response():
    """Create a mock auth response that captures the request body."""
    captured_body = {}

    def mock_post_request(url, headers, body, **kwargs):
        captured_body["body"] = json.loads(body)
        return {
            "success": True,
            "message": None,
            "data": {
                "token": "TOKEN",
                "masterToken": "MASTER_TOKEN",
            },
        }

    return mock_post_request, captured_body


class TestSecondaryRolesParameter:
    """Tests for secondary_roles connection parameter."""

    @pytest.mark.parametrize(
        "secondary_roles_value,expected_value",
        [
            ("ALL", "ALL"),
            ("all", "ALL"),
            ("All", "ALL"),
            ("NONE", "NONE"),
            ("none", "NONE"),
            ("None", "NONE"),
            ("DEFAULT", "DEFAULT"),
            ("default", "DEFAULT"),
        ],
    )
    def test_secondary_roles_included_in_auth_body(
        self, secondary_roles_value, expected_value
    ):
        """Test that secondary_roles is included in the auth request body and uppercased."""
        mock_post_request, captured_body = _create_mock_auth_success_response()
        rest = _init_rest_with_secondary_roles(
            "testapplication", secondary_roles_value, mock_post_request
        )

        auth = Auth(rest)
        auth_instance = AuthByDefault("testpassword")
        auth.authenticate(auth_instance, "testaccount", "testuser")

        # Verify SECONDARY_ROLES is in the request body with correct (uppercased) value
        assert "body" in captured_body
        assert "data" in captured_body["body"]
        assert "SECONDARY_ROLES" in captured_body["body"]["data"]
        assert captured_body["body"]["data"]["SECONDARY_ROLES"] == expected_value

    def test_secondary_roles_not_included_when_none(self):
        """Test that SECONDARY_ROLES is not included when not specified."""
        mock_post_request, captured_body = _create_mock_auth_success_response()
        rest = _init_rest_with_secondary_roles(
            "testapplication", None, mock_post_request
        )

        auth = Auth(rest)
        auth_instance = AuthByDefault("testpassword")
        auth.authenticate(auth_instance, "testaccount", "testuser")

        # Verify SECONDARY_ROLES is NOT in the request body
        assert "body" in captured_body
        assert "data" in captured_body["body"]
        assert "SECONDARY_ROLES" not in captured_body["body"]["data"]

    def test_secondary_roles_not_included_when_empty_string(self):
        """Test that SECONDARY_ROLES is not included when empty string."""
        mock_post_request, captured_body = _create_mock_auth_success_response()
        rest = _init_rest_with_secondary_roles("testapplication", "", mock_post_request)

        auth = Auth(rest)
        auth_instance = AuthByDefault("testpassword")
        auth.authenticate(auth_instance, "testaccount", "testuser")

        # Verify SECONDARY_ROLES is NOT in the request body (empty string is falsy)
        assert "body" in captured_body
        assert "data" in captured_body["body"]
        assert "SECONDARY_ROLES" not in captured_body["body"]["data"]


class TestSecondaryRolesInConnectionConfig:
    """Tests for secondary_roles in connection DEFAULT_CONFIGURATION."""

    def test_secondary_roles_in_default_configuration(self):
        """Test that secondary_roles is a valid connection parameter."""
        from snowflake.connector.connection import DEFAULT_CONFIGURATION

        assert "secondary_roles" in DEFAULT_CONFIGURATION
        default_value, accepted_types = DEFAULT_CONFIGURATION["secondary_roles"]
        assert default_value is None
        assert type(None) in accepted_types
        assert str in accepted_types


class TestSecondaryRolesInWhitelist:
    """Tests for SECONDARY_ROLES in authentication request key whitelist."""

    def test_secondary_roles_in_whitelist(self):
        """Test that SECONDARY_ROLES is in the authentication request key whitelist."""
        from snowflake.connector.auth._auth import AUTHENTICATION_REQUEST_KEY_WHITELIST

        assert "SECONDARY_ROLES" in AUTHENTICATION_REQUEST_KEY_WHITELIST
