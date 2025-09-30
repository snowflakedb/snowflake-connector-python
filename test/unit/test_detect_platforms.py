from __future__ import annotations

import os
import time
from unittest.mock import Mock, patch

import pytest

from snowflake.connector.platform_detection import detect_platforms
from snowflake.connector.vendored.requests.exceptions import RequestException
from src.snowflake.connector.vendored.requests import Response


def build_response(content: bytes = b"", status_code: int = 200, headers=None):
    response = Response()
    response._content = content
    response.status_code = status_code
    response.headers = headers
    return response


@pytest.fixture
def unavailable_metadata_service_with_request_exception(unavailable_metadata_service):
    """Customize unavailable_metadata_service to use RequestException for detect_platforms tests."""
    unavailable_metadata_service.unexpected_host_name_exception = RequestException()
    return unavailable_metadata_service


@pytest.fixture
def labels_detected_by_endpoints():
    return {
        "is_ec2_instance",
        "is_ec2_instance_timeout",
        "has_aws_identity",
        "has_aws_identity_timeout",
        "is_azure_vm",
        "is_azure_vm_timeout",
        "has_azure_managed_identity",
        "has_azure_managed_identity_timeout",
        "is_gce_vm",
        "is_gce_vm_timeout",
        "has_gcp_identity",
        "has_gcp_identity_timeout",
    }


@pytest.mark.xdist_group(name="serial_tests")
class TestDetectPlatforms:
    @pytest.fixture(autouse=True)
    def teardown(self):
        with patch.dict(os.environ, clear=True):
            detect_platforms.cache_clear()  # clear cache before each test
            yield
            detect_platforms.cache_clear()  # clear cache after each test

    def test_no_platforms_detected(
        self, unavailable_metadata_service_with_request_exception
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert result == []

    def test_ec2_instance_detection(
        self, unavailable_metadata_service_with_request_exception, fake_aws_environment
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_ec2_instance" in result

    def test_aws_lambda_detection(
        self,
        unavailable_metadata_service_with_request_exception,
        fake_aws_lambda_environment,
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_aws_lambda" in result

    @pytest.mark.parametrize(
        "arn",
        [
            "arn:aws:iam::123456789012:user/John",
            "arn:aws:sts::123456789012:assumed-role/Accounting-Role/Jane",
        ],
        ids=[
            "user",
            "assumed_role",
        ],
    )
    def test_aws_identity_detection(
        self,
        unavailable_metadata_service_with_request_exception,
        fake_aws_environment,
        arn,
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "has_aws_identity" in result

    def test_azure_vm_detection(self, fake_azure_vm_metadata_service):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_azure_vm" in result

    def test_azure_function_detection(self, fake_azure_function_metadata_service):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_azure_function" in result

    def test_azure_function_with_managed_identity(
        self, fake_azure_function_metadata_service
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_azure_function" in result
        assert "has_azure_managed_identity" in result

    def test_gce_vm_detection(self, fake_gce_metadata_service):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_gce_vm" in result

    def test_gce_cloud_run_service_detection(
        self, fake_gce_cloud_run_service_metadata_service
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_gce_cloud_run_service" in result

    def test_gce_cloud_run_job_detection(self, fake_gce_cloud_run_job_metadata_service):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_gce_cloud_run_job" in result

    def test_gcp_identity_detection(self, fake_gce_metadata_service):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "has_gcp_identity" in result

    def test_github_actions_detection(self, fake_github_actions_metadata_service):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_github_action" in result

    def test_multiple_platforms_detection(
        self,
        fake_aws_lambda_environment,
        fake_github_actions_metadata_service,
        fake_gce_cloud_run_service_metadata_service,
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_aws_lambda" in result
        assert "has_aws_identity" in result
        assert "is_github_action" in result
        assert "is_gce_cloud_run_service" in result

    def test_timeout_handling(self, unavailable_metadata_service):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_azure_vm_timeout" in result
        assert "is_gce_vm_timeout" in result
        assert "has_gcp_identity_timeout" in result
        assert "has_azure_managed_identity_timeout" in result

    def test_detect_platforms_executes_in_parallel(self):
        sleep_time = 2

        def slow_requests_get(*args, **kwargs):
            time.sleep(sleep_time)
            return build_response(
                status_code=200, headers={"Metadata-Flavor": "Google"}
            )

        def slow_boto3_client(*args, **kwargs):
            time.sleep(sleep_time)
            mock_client = Mock()
            mock_client.get_caller_identity.return_value = {
                "Arn": "arn:aws:iam::123456789012:user/TestUser"
            }
            return mock_client

        def imds_fetcher(*args, **kwargs):
            time.sleep(sleep_time)
            mock_imds_instance = Mock()
            mock_imds_instance._get_request.return_value = build_response(
                content=b"content", status_code=200
            )
            mock_imds_instance._fetch_metadata_token.return_value = "test-token"
            return mock_imds_instance

        def slow_imds_fetch_token(*args, **kwargs):
            return "test-token"

        # Mock all the network calls that run in parallel
        with patch(
            "snowflake.connector.platform_detection.SessionManager.get",
            side_effect=slow_requests_get,
        ), patch(
            "snowflake.connector.platform_detection.boto3.client",
            side_effect=slow_boto3_client,
        ), patch(
            "snowflake.connector.platform_detection.IMDSFetcher",
            side_effect=imds_fetcher,
        ):
            start_time = time.time()
            result = detect_platforms(platform_detection_timeout_seconds=10)
            end_time = time.time()

            execution_time = end_time - start_time

            # Check that I/O calls are made in parallel. We shouldn't expect more than 2x the amount of time a single
            # I/O operation takes. Which in this case is 2 seconds.
            assert (
                execution_time < 2 * sleep_time
            ), f"Expected parallel execution to take <4s, but took {execution_time:.2f}s"
            assert (
                execution_time >= sleep_time
            ), f"Expected at least 2s due to sleep, but took {execution_time:.2f}s"

            assert "is_ec2_instance" in result
            assert "has_aws_identity" in result
            assert "is_azure_vm" in result
            assert "has_azure_managed_identity" in result
            assert "is_gce_vm" in result
            assert "has_gcp_identity" in result

    @pytest.mark.parametrize(
        "arn",
        [
            "invalid-arn-format",
            "arn:aws:iam::account:root",
            "arn:aws:iam::123456789012:group/Developers",
            "arn:aws:iam::123456789012:role/S3Access",
            "arn:aws:iam::123456789012:policy/UsersManageOwnCredentials",
            "arn:aws:iam::123456789012:instance-profile/Webserver",
            "arn:aws:sts::123456789012:federated-user/John",
            "arn:aws:sts::account:self",
            "arn:aws:iam::123456789012:mfa/JaneMFA",
            "arn:aws:iam::123456789012:u2f/user/John/default",
            "arn:aws:iam::123456789012:server-certificate/ProdServerCert",
            "arn:aws:iam::123456789012:saml-provider/ADFSProvider",
            "arn:aws:iam::123456789012:oidc-provider/GoogleProvider",
            "arn:aws:iam::aws:contextProvider/IdentityCenter",
        ],
        ids=[
            "invalid_format",
            "iam_root",
            "iam_group",
            "iam_role",
            "iam_policy",
            "iam_instance_profile",
            "sts_federated_user",
            "sts_self",
            "iam_mfa",
            "iam_u2f",
            "iam_server_certificate",
            "iam_saml_provider",
            "iam_oidc_provider",
            "iam_context_provider",
        ],
    )
    def test_invalid_arn_handling(
        self,
        unavailable_metadata_service_with_request_exception,
        fake_aws_environment,
        arn,
    ):
        fake_aws_environment.caller_identity = {"Arn": arn}
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "has_aws_identity" not in result

    def test_missing_arn_handling(
        self, unavailable_metadata_service_with_request_exception, fake_aws_environment
    ):
        fake_aws_environment.caller_identity = {"UserId": "test-user"}
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "has_aws_identity" not in result

    def test_azure_managed_identity_no_token_endpoint(
        self, fake_azure_vm_metadata_service
    ):
        fake_azure_vm_metadata_service.has_token_endpoint = False
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "azure_managed_identity" not in result

    def test_azure_function_missing_identity_endpoint(
        self, unavailable_metadata_service_with_request_exception
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_azure_function" not in result

    def test_aws_ec2_empty_instance_document(
        self, unavailable_metadata_service_with_request_exception, fake_aws_environment
    ):
        fake_aws_environment.instance_document = b""
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_ec2_instance" not in result

    def test_aws_lambda_empty_task_root(
        self, unavailable_metadata_service_with_request_exception
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_aws_lambda" not in result

    def test_github_actions_missing_environment_variable(
        self, unavailable_metadata_service_with_request_exception
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_github_action" not in result

    def test_gce_cloud_run_service_missing_k_service(
        self, unavailable_metadata_service_with_request_exception
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_gce_cloud_run_service" not in result

    def test_gce_cloud_run_job_missing_cloud_run_job(
        self, unavailable_metadata_service_with_request_exception
    ):
        result = detect_platforms(platform_detection_timeout_seconds=None)
        assert "is_gce_cloud_run_job" not in result

    def test_zero_platform_detection_timeout_disables_endpoints_detection_on_cloud(
        self,
        fake_azure_vm_metadata_service,
        fake_azure_function_metadata_service,
        fake_gce_metadata_service,
        fake_gce_cloud_run_service_metadata_service,
        fake_gce_cloud_run_job_metadata_service,
        fake_github_actions_metadata_service,
        labels_detected_by_endpoints,
    ):
        result = detect_platforms(platform_detection_timeout_seconds=0)
        assert not labels_detected_by_endpoints.intersection(result)

    def test_zero_platform_detection_timeout_disables_endpoints_detection_out_of_cloud(
        self,
        unavailable_metadata_service_with_request_exception,
        labels_detected_by_endpoints,
    ):
        result = detect_platforms(platform_detection_timeout_seconds=0)
        assert not labels_detected_by_endpoints.intersection(result)
