#!/usr/bin/env python
"""Unit tests for Auth.base_auth_data method."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from snowflake.connector.auth import Auth
from snowflake.connector.description import (
    COMPILER,
    IMPLEMENTATION,
    OPERATING_SYSTEM,
    PLATFORM,
    PYTHON_VERSION,
)
from snowflake.connector.version import VERSION


@pytest.fixture
def mock_ocsp_mode():
    """Create a mock OCSP mode object."""
    ocsp_mode = Mock()
    ocsp_mode.name = "FAIL_OPEN"
    return ocsp_mode


@pytest.fixture
def mock_session_manager():
    """Create a mock session manager."""
    session_manager = Mock()
    session_manager.clone = Mock(return_value=Mock())
    return session_manager


@pytest.fixture
def mock_dependencies():
    """Patch external dependencies that base_auth_data calls."""
    with patch(
        "snowflake.connector.auth._auth.detect_platforms"
    ) as mock_detect_platforms, patch(
        "snowflake.connector.auth._auth.get_os_details"
    ) as mock_get_os_details, patch(
        "snowflake.connector.auth._auth.get_application_path"
    ) as mock_get_application_path, patch(
        "snowflake.connector.auth._auth.build_minicore_usage_for_session"
    ) as mock_build_minicore:
        mock_detect_platforms.return_value = ["AWS", "DOCKER"]
        mock_get_os_details.return_value = {"NAME": "Ubuntu", "VERSION": "22.04"}
        mock_get_application_path.return_value = "/usr/bin/python"
        mock_build_minicore.return_value = {"ISA": "x86_64", "CORE_VERSION": "1.2.3"}
        yield {
            "detect_platforms": mock_detect_platforms,
            "get_os_details": mock_get_os_details,
            "get_application_path": mock_get_application_path,
            "build_minicore": mock_build_minicore,
        }


class TestBaseAuthData:
    """Tests for Auth.base_auth_data static method."""

    def test_returns_dict_with_data_key(
        self, mock_ocsp_mode, mock_session_manager, mock_dependencies
    ):
        """Test that base_auth_data returns a dictionary with 'data' key."""
        result = Auth.base_auth_data(
            user="testuser",
            account="testaccount",
            application="testapp",
            internal_application_name="PythonConnector",
            internal_application_version="3.0.0",
            ocsp_mode=mock_ocsp_mode,
            cert_revocation_check_mode="CRL",
            session_manager=mock_session_manager,
        )

        assert isinstance(result, dict)
        assert "data" in result

    def test_contains_required_client_fields(
        self, mock_ocsp_mode, mock_session_manager, mock_dependencies
    ):
        """Test that the result contains all required client identification fields."""
        result = Auth.base_auth_data(
            user="testuser",
            account="testaccount",
            application="testapp",
            internal_application_name="PythonConnector",
            internal_application_version="3.0.0",
            ocsp_mode=mock_ocsp_mode,
            cert_revocation_check_mode="CRL",
            session_manager=mock_session_manager,
        )

        data = result["data"]
        assert data["CLIENT_APP_ID"] == "PythonConnector"
        assert data["CLIENT_APP_VERSION"] == "3.0.0"
        assert data["SVN_REVISION"] == VERSION[3]
        assert data["ACCOUNT_NAME"] == "testaccount"
        assert data["LOGIN_NAME"] == "testuser"

    def test_contains_client_environment(
        self, mock_ocsp_mode, mock_session_manager, mock_dependencies
    ):
        """Test that CLIENT_ENVIRONMENT is present with expected fields."""
        result = Auth.base_auth_data(
            user="testuser",
            account="testaccount",
            application="testapp",
            internal_application_name="PythonConnector",
            internal_application_version="3.0.0",
            ocsp_mode=mock_ocsp_mode,
            cert_revocation_check_mode="CRL",
            session_manager=mock_session_manager,
        )

        client_env = result["data"]["CLIENT_ENVIRONMENT"]
        assert "APPLICATION" in client_env
        assert "APPLICATION_PATH" in client_env
        assert "OS" in client_env
        assert "OS_VERSION" in client_env
        assert "PYTHON_VERSION" in client_env
        assert "PYTHON_RUNTIME" in client_env
        assert "PYTHON_COMPILER" in client_env
        assert "OCSP_MODE" in client_env
        assert "CERT_REVOCATION_CHECK_MODE" in client_env
        assert "TRACING" in client_env
        assert "PLATFORM" in client_env
        assert "OS_DETAILS" in client_env

    def test_client_environment_values(
        self, mock_ocsp_mode, mock_session_manager, mock_dependencies
    ):
        """Test that CLIENT_ENVIRONMENT contains correct values."""
        result = Auth.base_auth_data(
            user="testuser",
            account="testaccount",
            application="MyApplication",
            internal_application_name="PythonConnector",
            internal_application_version="3.0.0",
            ocsp_mode=mock_ocsp_mode,
            cert_revocation_check_mode="CRL",
            session_manager=mock_session_manager,
        )

        client_env = result["data"]["CLIENT_ENVIRONMENT"]
        assert client_env["APPLICATION"] == "MyApplication"
        assert client_env["APPLICATION_PATH"] == "/usr/bin/python"
        assert client_env["OS"] == OPERATING_SYSTEM
        assert client_env["OS_VERSION"] == PLATFORM
        assert client_env["PYTHON_VERSION"] == PYTHON_VERSION
        assert client_env["PYTHON_RUNTIME"] == IMPLEMENTATION
        assert client_env["PYTHON_COMPILER"] == COMPILER
        assert client_env["OCSP_MODE"] == "FAIL_OPEN"
        assert client_env["CERT_REVOCATION_CHECK_MODE"] == "CRL"
        assert client_env["PLATFORM"] == ["AWS", "DOCKER"]
        assert client_env["OS_DETAILS"] == {"NAME": "Ubuntu", "VERSION": "22.04"}

    def test_timeout_parameters(
        self, mock_ocsp_mode, mock_session_manager, mock_dependencies
    ):
        """Test that timeout parameters are correctly included."""
        result = Auth.base_auth_data(
            user="testuser",
            account="testaccount",
            application="testapp",
            internal_application_name="PythonConnector",
            internal_application_version="3.0.0",
            ocsp_mode=mock_ocsp_mode,
            cert_revocation_check_mode="CRL",
            login_timeout=120,
            network_timeout=300,
            socket_timeout=60,
            session_manager=mock_session_manager,
        )

        client_env = result["data"]["CLIENT_ENVIRONMENT"]
        assert client_env["LOGIN_TIMEOUT"] == 120
        assert client_env["NETWORK_TIMEOUT"] == 300
        assert client_env["SOCKET_TIMEOUT"] == 60

    def test_timeout_parameters_none_by_default(
        self, mock_ocsp_mode, mock_session_manager, mock_dependencies
    ):
        """Test that timeout parameters are None when not specified."""
        result = Auth.base_auth_data(
            user="testuser",
            account="testaccount",
            application="testapp",
            internal_application_name="PythonConnector",
            internal_application_version="3.0.0",
            ocsp_mode=mock_ocsp_mode,
            cert_revocation_check_mode="CRL",
            session_manager=mock_session_manager,
        )

        client_env = result["data"]["CLIENT_ENVIRONMENT"]
        assert client_env["LOGIN_TIMEOUT"] is None
        assert client_env["NETWORK_TIMEOUT"] is None
        assert client_env["SOCKET_TIMEOUT"] is None

    def test_detect_platforms_called_with_correct_args(
        self, mock_ocsp_mode, mock_session_manager, mock_dependencies
    ):
        """Test that detect_platforms is called with correct arguments."""
        cloned_manager = Mock()
        mock_session_manager.clone.return_value = cloned_manager

        Auth.base_auth_data(
            user="testuser",
            account="testaccount",
            application="testapp",
            internal_application_name="PythonConnector",
            internal_application_version="3.0.0",
            ocsp_mode=mock_ocsp_mode,
            cert_revocation_check_mode="CRL",
            platform_detection_timeout_seconds=5.0,
            session_manager=mock_session_manager,
        )

        mock_session_manager.clone.assert_called_once_with(max_retries=0)
        mock_dependencies["detect_platforms"].assert_called_once_with(
            platform_detection_timeout_seconds=5.0,
            session_manager=cloned_manager,
        )

    def test_minicore_usage_merged_into_client_environment(
        self, mock_ocsp_mode, mock_session_manager, mock_dependencies
    ):
        """Test that build_minicore_usage_for_session results are merged into CLIENT_ENVIRONMENT."""
        result = Auth.base_auth_data(
            user="testuser",
            account="testaccount",
            application="testapp",
            internal_application_name="PythonConnector",
            internal_application_version="3.0.0",
            ocsp_mode=mock_ocsp_mode,
            cert_revocation_check_mode="CRL",
            session_manager=mock_session_manager,
        )

        client_env = result["data"]["CLIENT_ENVIRONMENT"]
        # These come from build_minicore_usage_for_session mock
        assert client_env["ISA"] == "x86_64"
        assert client_env["CORE_VERSION"] == "1.2.3"

    def test_creates_session_manager_when_http_config_provided(
        self, mock_ocsp_mode, mock_dependencies
    ):
        """Test that a session manager is created when http_config is provided and session_manager is None."""
        mock_http_config = Mock()
        mock_http_config.to_base_dict.return_value = {
            "proxy_host": None,
            "proxy_port": None,
        }

        with patch(
            "snowflake.connector.auth._auth.SessionManagerFactory"
        ) as mock_factory, patch(
            "snowflake.connector.auth._auth.HttpConfig"
        ) as mock_http_config_class:
            mock_sync_config = Mock()
            mock_http_config_class.return_value = mock_sync_config

            created_manager = Mock()
            created_manager.clone = Mock(return_value=Mock())
            mock_factory.get_manager.return_value = created_manager

            Auth.base_auth_data(
                user="testuser",
                account="testaccount",
                application="testapp",
                internal_application_name="PythonConnector",
                internal_application_version="3.0.0",
                ocsp_mode=mock_ocsp_mode,
                cert_revocation_check_mode="CRL",
                http_config=mock_http_config,
                session_manager=None,
            )

            mock_http_config.to_base_dict.assert_called_once()
            mock_http_config_class.assert_called_once()
            mock_factory.get_manager.assert_called_once_with(config=mock_sync_config)
            created_manager.clone.assert_called_once_with(max_retries=0)

    def test_does_not_create_session_manager_when_already_provided(
        self, mock_ocsp_mode, mock_session_manager, mock_dependencies
    ):
        """Test that no new session manager is created when one is already provided."""
        mock_http_config = Mock()

        with patch(
            "snowflake.connector.auth._auth.SessionManagerFactory"
        ) as mock_factory:
            Auth.base_auth_data(
                user="testuser",
                account="testaccount",
                application="testapp",
                internal_application_name="PythonConnector",
                internal_application_version="3.0.0",
                ocsp_mode=mock_ocsp_mode,
                cert_revocation_check_mode="CRL",
                http_config=mock_http_config,
                session_manager=mock_session_manager,
            )

            mock_factory.get_manager.assert_not_called()

    def test_does_not_create_session_manager_when_http_config_none(
        self, mock_ocsp_mode, mock_dependencies
    ):
        """Test that no session manager is created when http_config is None."""
        # Create a minimal mock for session_manager since we need one for detect_platforms
        mock_session_manager = Mock()
        mock_session_manager.clone = Mock(return_value=Mock())

        with patch(
            "snowflake.connector.auth._auth.SessionManagerFactory"
        ) as mock_factory:
            Auth.base_auth_data(
                user="testuser",
                account="testaccount",
                application="testapp",
                internal_application_name="PythonConnector",
                internal_application_version="3.0.0",
                ocsp_mode=mock_ocsp_mode,
                cert_revocation_check_mode="CRL",
                http_config=None,
                session_manager=mock_session_manager,
            )

            mock_factory.get_manager.assert_not_called()
