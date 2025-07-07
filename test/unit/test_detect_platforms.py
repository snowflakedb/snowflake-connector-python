#!/usr/bin/env python
"""
Unit tests for the detect_platforms() function in snowflake.connector.auth._auth module.

The detect_platforms() function is a nested function within Auth.base_auth_data() that detects
various cloud platforms and environments by checking environment variables, making HTTP requests
to metadata endpoints, and using AWS STS calls. It runs multiple platform detection functions
in parallel using ThreadPoolExecutor.

Platforms detected:
- AWS Lambda (via LAMBDA_TASK_ROOT environment variable)
- EC2 instances (via IMDSFetcher)
- AWS identity (via boto3 STS calls)
- Azure VMs (via metadata endpoints)
- Azure Functions (via environment variables)
- Azure managed identity (combination of VM/Function detection and identity headers)
- GCE VMs (via metadata endpoints)
- GCE Cloud Run services (via environment variables)
- GCE Cloud Run jobs (via environment variables)
- GCP identity (via metadata endpoints)
- GitHub Actions (via GITHUB_ACTIONS environment variable)

These tests use comprehensive mocking to:
1. Mock all external dependencies (HTTP requests, boto3, IMDS fetcher)
2. Test individual platform detection scenarios
3. Test combinations of multiple platforms
4. Test error handling (timeouts, HTTP errors, invalid responses)
5. Test edge cases (missing environment variables, failed API calls)

The tests ensure the function gracefully handles failures and returns appropriate platform lists.
"""
from __future__ import annotations

import os
from unittest.mock import Mock, patch

import requests

from snowflake.connector.auth._auth import Auth
from snowflake.connector.constants import OCSPMode


class MockResponse:
    """Mock response object for requests."""

    def __init__(self, status_code=200, content=b"", text="", headers=None):
        self.status_code = status_code
        self.content = content
        self.text = text
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code} Error")


class TestDetectPlatforms:
    """Test suite for the detect_platforms function."""

    def get_detect_platforms_func(self):
        """Extract the detect_platforms function from base_auth_data."""
        auth_data = Auth.base_auth_data(
            user="test_user",
            account="test_account",
            application="test_app",
            internal_application_name="test_internal",
            internal_application_version="1.0.0",
            ocsp_mode=OCSPMode.FAIL_OPEN,
        )
        # The function is nested, so we need to call base_auth_data to get access to it
        # We'll extract it by patching the environment and checking the result
        return auth_data["data"]["CLIENT_ENVIRONMENT"]["PLATFORM"]

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_no_platforms_detected(self, mock_requests, mock_boto3, mock_imds_fetcher):
        """Test when no platforms are detected."""
        # Mock all detection methods to return False
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert result == []

    @patch.dict(os.environ, {"LAMBDA_TASK_ROOT": "/var/task"}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_aws_lambda_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        """Test AWS Lambda detection via environment variable."""
        # Mock other methods to return False
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "is_aws_lambda" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_ec2_instance_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        """Test EC2 instance detection via IMDS."""
        # Mock IMDS to return valid response
        mock_imds_instance = Mock()
        mock_response = Mock()
        mock_response.content = b'{"region": "us-east-1"}'
        mock_imds_instance._get_request.return_value = mock_response
        mock_imds_instance._fetch_metadata_token.return_value = "test-token"
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "is_ec2_instance" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_aws_identity_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        """Test AWS identity detection via STS."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        # Mock boto3 to return valid caller identity
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {
            "Arn": "arn:aws:iam::123456789012:user/test-user"
        }
        mock_boto3.client.return_value = mock_sts_client

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "has_aws_identity" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_aws_identity_assumed_role(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        """Test AWS identity detection with assumed role ARN."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        # Mock boto3 to return assumed role ARN
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {
            "Arn": "arn:aws:sts::123456789012:assumed-role/test-role/session"
        }
        mock_boto3.client.return_value = mock_sts_client

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "has_aws_identity" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_aws_identity_invalid_arn(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        """Test AWS identity detection with invalid ARN."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        # Mock boto3 to return invalid ARN
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {
            "Arn": "arn:aws:s3:::my-bucket"  # Invalid ARN for WIF
        }
        mock_boto3.client.return_value = mock_sts_client

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "has_aws_identity" not in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_azure_vm_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        """Test Azure VM detection via metadata endpoint."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Mock requests to return success for Azure VM metadata
        def mock_get(url, **kwargs):
            if "169.254.169.254/metadata/instance" in url:
                return MockResponse(status_code=200)
            elif "169.254.169.254/metadata/identity" in url:
                return MockResponse(status_code=200)
            else:
                raise requests.RequestException("No metadata")

        # Configure mock requests
        mock_requests.get.side_effect = mock_get
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "is_azure_vm" in result
        assert "azure_managed_identity" in result

    @patch.dict(
        os.environ,
        {
            "FUNCTIONS_WORKER_RUNTIME": "python",
            "FUNCTIONS_EXTENSION_VERSION": "~4",
            "AzureWebJobsStorage": "DefaultEndpointsProtocol=https;AccountName=test",
            "IDENTITY_HEADER": "test-header",
        },
        clear=True,
    )
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_azure_function_detection(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        """Test Azure Function detection via environment variables."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "is_azure_function" in result
        assert "azure_managed_identity" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_gce_vm_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        """Test GCE VM detection via metadata endpoint."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Mock requests to return success for GCE metadata
        def mock_get(url, **kwargs):
            if "metadata.google.internal" in url:
                return MockResponse(
                    status_code=200, headers={"Metadata-Flavor": "Google"}
                )
            elif "metadata/computeMetadata/v1/instance/service-accounts" in url:
                return MockResponse(
                    status_code=200, text="test@test.iam.gserviceaccount.com"
                )
            else:
                raise requests.RequestException("No metadata")

        # Configure mock requests
        mock_requests.get.side_effect = mock_get
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "is_gce_vm" in result
        assert "has_gcp_identity" in result

    @patch.dict(
        os.environ,
        {
            "K_SERVICE": "test-service",
            "K_REVISION": "test-revision",
            "K_CONFIGURATION": "test-config",
        },
        clear=True,
    )
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_gce_cloud_run_service_detection(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        """Test GCE Cloud Run service detection via environment variables."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "is_gce_cloud_run_service" in result

    @patch.dict(
        os.environ,
        {"CLOUD_RUN_JOB": "test-job", "CLOUD_RUN_EXECUTION": "test-execution"},
        clear=True,
    )
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_gce_cloud_run_job_detection(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        """Test GCE Cloud Run job detection via environment variables."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "is_gce_cloud_run_job" in result

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_github_actions_detection(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        """Test GitHub Actions detection via environment variable."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "is_github_action" in result

    @patch.dict(
        os.environ,
        {
            "LAMBDA_TASK_ROOT": "/var/task",
            "GITHUB_ACTIONS": "true",
            "K_SERVICE": "test-service",
            "K_REVISION": "test-revision",
            "K_CONFIGURATION": "test-config",
        },
        clear=True,
    )
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_multiple_platforms_detection(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        """Test detection of multiple platforms simultaneously."""
        # Mock IMDS to succeed for EC2
        mock_imds_instance = Mock()
        mock_response = Mock()
        mock_response.content = b'{"region": "us-east-1"}'
        mock_imds_instance._get_request.return_value = mock_response
        mock_imds_instance._fetch_metadata_token.return_value = "test-token"
        mock_imds_fetcher.return_value = mock_imds_instance

        # Mock boto3 to return valid caller identity
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {
            "Arn": "arn:aws:iam::123456789012:user/test-user"
        }
        mock_boto3.client.return_value = mock_sts_client

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        # Should detect multiple platforms
        assert "is_aws_lambda" in result
        assert "is_ec2_instance" in result
        assert "has_aws_identity" in result
        assert "is_github_action" in result
        assert "is_gce_cloud_run_service" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_timeout_handling(self, mock_requests, mock_boto3, mock_imds_fetcher):
        """Test that timeouts are handled gracefully."""
        # Mock IMDS to timeout
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("Timeout")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "Timeout"
        )

        # Configure mock requests
        mock_requests.get.side_effect = requests.exceptions.Timeout("Timeout")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert result == []

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_http_error_handling(self, mock_requests, mock_boto3, mock_imds_fetcher):
        """Test that HTTP errors are handled gracefully."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("HTTP Error")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "HTTP Error"
        )

        # Mock requests to return 404
        mock_requests.get.return_value = MockResponse(status_code=404)
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert result == []

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_gcp_identity_http_error(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        """Test GCP identity detection with HTTP error."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Mock requests to return 401 for GCP identity endpoint
        def mock_get(url, **kwargs):
            if "metadata/computeMetadata/v1/instance/service-accounts" in url:
                response = MockResponse(status_code=401)
                response.raise_for_status = Mock(
                    side_effect=requests.HTTPError("401 Unauthorized")
                )
                return response
            else:
                raise requests.RequestException("No metadata")

        # Configure mock requests
        mock_requests.get.side_effect = mock_get
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "has_gcp_identity" not in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_azure_managed_identity_without_identity_header(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        """Test Azure managed identity detection without IDENTITY_HEADER."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Mock requests to return success for Azure VM metadata but fail for managed identity
        def mock_get(url, **kwargs):
            if "169.254.169.254/metadata/instance" in url:
                return MockResponse(status_code=200)
            elif "169.254.169.254/metadata/identity" in url:
                return MockResponse(status_code=400)  # No managed identity
            else:
                raise requests.RequestException("No metadata")

        # Configure mock requests
        mock_requests.get.side_effect = mock_get
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "is_azure_vm" in result
        assert "azure_managed_identity" not in result

    @patch.dict(
        os.environ,
        {
            "FUNCTIONS_WORKER_RUNTIME": "python",
            "FUNCTIONS_EXTENSION_VERSION": "~4",
            "AzureWebJobsStorage": "DefaultEndpointsProtocol=https;AccountName=test",
            # Missing IDENTITY_HEADER
        },
        clear=True,
    )
    @patch("snowflake.connector.auth._auth.IMDSFetcher")
    @patch("snowflake.connector.auth._auth.boto3")
    @patch("snowflake.connector.auth._auth.requests")
    def test_azure_function_without_managed_identity(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        """Test Azure Function detection without managed identity."""
        # Mock IMDS to fail
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        # Configure mock requests
        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException

        result = self.get_detect_platforms_func()
        assert "is_azure_function" in result
        assert "azure_managed_identity" not in result
