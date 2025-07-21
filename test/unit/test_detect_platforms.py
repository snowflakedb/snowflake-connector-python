from __future__ import annotations

import os
from unittest.mock import Mock, patch

import requests

from snowflake.connector.platform_detection import detect_platforms


class MockResponse:
    def __init__(self, status_code=200, content=b"", text="", headers=None):
        self.status_code = status_code
        self.content = content
        self.text = text
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code} Error")


class TestDetectPlatforms:
    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_no_platforms_detected(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert result == []

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_ec2_instance_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_response = Mock()
        mock_response.content = b'{"region": "us-east-1"}'
        mock_imds_instance._get_request.return_value = mock_response
        mock_imds_instance._fetch_metadata_token.return_value = "test-token"
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "is_ec2_instance" in result

    @patch.dict(os.environ, {"LAMBDA_TASK_ROOT": "/var/task"}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_aws_lambda_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "is_aws_lambda" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_aws_identity_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {
            "Arn": "arn:aws:iam::123456789012:user/test-user"
        }
        mock_boto3.client.return_value = mock_sts_client

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "has_aws_identity" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_azure_vm_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_azure_response = MockResponse(status_code=200)

        def mock_get_side_effect(url, **kwargs):
            if "169.254.169.254" in url:
                return mock_azure_response
            else:
                raise requests.RequestException("No metadata")

        mock_requests.get.side_effect = mock_get_side_effect
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "is_azure_vm" in result

    @patch.dict(
        os.environ,
        {
            "FUNCTIONS_WORKER_RUNTIME": "python",
            "FUNCTIONS_EXTENSION_VERSION": "~4",
            "AzureWebJobsStorage": "DefaultEndpointsProtocol=https;AccountName=test",
        },
        clear=True,
    )
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_azure_function_detection(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "is_azure_function" in result

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
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_azure_function_with_managed_identity(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "is_azure_function" in result
        assert "azure_managed_identity" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_gce_vm_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_gce_response = MockResponse(
            status_code=200, headers={"Metadata-Flavor": "Google"}
        )

        def mock_get_side_effect(url, **kwargs):
            if "metadata.google.internal" in url:
                return mock_gce_response
            else:
                raise requests.RequestException("No metadata")

        mock_requests.get.side_effect = mock_get_side_effect
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "is_gce_vm" in result

    @patch.dict(
        os.environ,
        {
            "K_SERVICE": "test-service",
            "K_REVISION": "test-revision",
            "K_CONFIGURATION": "test-config",
        },
        clear=True,
    )
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_gce_cloud_run_service_detection(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        mock_requests.Timeout = requests.Timeout
        assert "is_gce_cloud_run_service" in result

    @patch.dict(
        os.environ,
        {"CLOUD_RUN_JOB": "test-job", "CLOUD_RUN_EXECUTION": "test-execution"},
        clear=True,
    )
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_gce_cloud_run_job_detection(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "is_gce_cloud_run_job" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_gcp_identity_detection(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_gcp_response = MockResponse(
            status_code=200, text="test-service-account@project.iam.gserviceaccount.com"
        )

        def mock_get_side_effect(url, **kwargs):
            if "metadata/computeMetadata" in url:
                return mock_gcp_response
            else:
                raise requests.RequestException("No metadata")

        mock_requests.get.side_effect = mock_get_side_effect
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "has_gcp_identity" in result

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_github_actions_detection(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
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
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_multiple_platforms_detection(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        mock_imds_instance = Mock()
        mock_response = Mock()
        mock_response.content = b'{"region": "us-east-1"}'
        mock_imds_instance._get_request.return_value = mock_response
        mock_imds_instance._fetch_metadata_token.return_value = "test-token"
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {
            "Arn": "arn:aws:iam::123456789012:user/test-user"
        }
        mock_boto3.client.return_value = mock_sts_client

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "is_aws_lambda" in result
        assert "is_ec2_instance" in result
        assert "has_aws_identity" in result
        assert "is_github_action" in result
        assert "is_gce_cloud_run_service" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_timeout_handling(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("Timeout")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "Timeout"
        )

        mock_requests.get.side_effect = requests.Timeout("Connection timeout")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "is_azure_vm_timeout" in result
        assert "is_gce_vm_timeout" in result
        assert "has_gcp_identity_timeout" in result
        assert "azure_managed_identity_timeout" in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_http_error_handling(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("HTTP Error")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "HTTP Error"
        )

        mock_requests.get.side_effect = requests.HTTPError("HTTP 500 Error")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout
        mock_requests.HTTPError = requests.HTTPError

        result = detect_platforms(timeout=None)
        assert result == []

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_invalid_arn_handling(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {"Arn": "invalid-arn-format"}
        mock_boto3.client.return_value = mock_sts_client

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "has_aws_identity" not in result

    @patch.dict(os.environ, {}, clear=True)
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_missing_arn_handling(self, mock_requests, mock_boto3, mock_imds_fetcher):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {"UserId": "test-user"}
        mock_boto3.client.return_value = mock_sts_client

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=None)
        assert "has_aws_identity" not in result

    @patch.dict(
        os.environ,
        {"LAMBDA_TASK_ROOT": "/var/task", "GITHUB_ACTIONS": "true"},
        clear=True,
    )
    @patch("snowflake.connector.platform_detection.IMDSFetcher")
    @patch("snowflake.connector.platform_detection.boto3")
    @patch("snowflake.connector.platform_detection.requests")
    def test_custom_timeout_parameter(
        self, mock_requests, mock_boto3, mock_imds_fetcher
    ):
        mock_imds_instance = Mock()
        mock_imds_instance._get_request.side_effect = Exception("No IMDS")
        mock_imds_fetcher.return_value = mock_imds_instance

        mock_boto3.client.return_value.get_caller_identity.side_effect = Exception(
            "No AWS"
        )

        mock_requests.get.side_effect = requests.RequestException("No metadata")
        mock_requests.RequestException = requests.RequestException
        mock_requests.Timeout = requests.Timeout

        result = detect_platforms(timeout=5.0)

        assert "is_aws_lambda" in result
        assert "is_github_action" in result
