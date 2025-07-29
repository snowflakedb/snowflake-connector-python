from __future__ import annotations

import pytest

from snowflake.connector.platform_detection import detect_platforms
from src.snowflake.connector.vendored.requests import Response


def build_response(status_code=200, headers=None):
    response = Response()
    response.status_code = status_code
    response.headers = headers
    return response


class TestDetectPlatforms:
    @pytest.fixture(autouse=True)
    def teardown(self):
        yield
        detect_platforms.cache_clear()  # clear cache after each test

    def test_no_platforms_detected(self, broken_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert result == []

    def test_ec2_instance_detection(
        self, broken_metadata_service, fake_aws_environment
    ):
        result = detect_platforms(timeout_seconds=None)
        assert "is_ec2_instance" in result

    def test_aws_lambda_detection(self, broken_metadata_service, fake_aws_environment):
        result = detect_platforms(timeout_seconds=None)
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
        self, broken_metadata_service, fake_aws_environment, arn
    ):
        result = detect_platforms(timeout_seconds=None)
        assert "has_aws_identity" in result

    def test_azure_vm_detection(self, fake_azure_vm_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_azure_vm" in result

    def test_azure_function_detection(self, fake_azure_function_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_azure_function" in result

    def test_azure_function_with_managed_identity(
        self, fake_azure_function_metadata_service
    ):
        result = detect_platforms(timeout_seconds=None)
        assert "is_azure_function" in result
        assert "azure_managed_identity" in result

    def test_gce_vm_detection(self, fake_gce_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_gce_vm" in result

    def test_gce_cloud_run_service_detection(
        self, fake_gce_cloud_run_service_metadata_service
    ):
        result = detect_platforms(timeout_seconds=None)
        assert "is_gce_cloud_run_service" in result

    def test_gce_cloud_run_job_detection(self, fake_gce_cloud_run_job_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_gce_cloud_run_job" in result

    def test_gcp_identity_detection(self, fake_gce_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "has_gcp_identity" in result

    def test_github_actions_detection(self, fake_github_actions_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_github_action" in result

    def test_multiple_platforms_detection(
        self,
        fake_aws_environment,
        fake_github_actions_metadata_service,
        fake_gce_cloud_run_service_metadata_service,
    ):
        result = detect_platforms(timeout_seconds=None)
        assert "is_aws_lambda" in result
        assert "is_ec2_instance" in result
        assert "has_aws_identity" in result
        assert "is_github_action" in result
        assert "is_gce_cloud_run_service" in result

    def test_timeout_handling(self, unavailable_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_azure_vm_timeout" in result
        assert "is_gce_vm_timeout" in result
        assert "has_gcp_identity_timeout" in result
        assert "azure_managed_identity_timeout" in result

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
        self, broken_metadata_service, fake_aws_environment, arn
    ):
        fake_aws_environment.caller_identity = {"Arn": arn}
        result = detect_platforms(timeout_seconds=None)
        assert "has_aws_identity" not in result

    def test_missing_arn_handling(self, broken_metadata_service, fake_aws_environment):
        fake_aws_environment.caller_identity = {"UserId": "test-user"}
        result = detect_platforms(timeout_seconds=None)
        assert "has_aws_identity" not in result

    def test_azure_managed_identity_wrong_issuer(self, fake_azure_vm_metadata_service):
        fake_azure_vm_metadata_service.iss = "https://fake-issuer.com"
        result = detect_platforms(timeout_seconds=None)
        assert "azure_managed_identity" not in result

    def test_azure_function_missing_identity_endpoint(self, broken_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_azure_function" not in result

    def test_aws_ec2_empty_instance_document(
        self, broken_metadata_service, fake_aws_environment
    ):
        fake_aws_environment.instance_document = b""
        result = detect_platforms(timeout_seconds=None)
        assert "is_ec2_instance" not in result

    def test_aws_lambda_empty_task_root(self, broken_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_aws_lambda" not in result

    def test_github_actions_missing_environment_variable(self, broken_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_github_action" not in result

    def test_gce_cloud_run_service_missing_k_service(self, broken_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_gce_cloud_run_service" not in result

    def test_gce_cloud_run_job_missing_cloud_run_job(self, broken_metadata_service):
        result = detect_platforms(timeout_seconds=None)
        assert "is_gce_cloud_run_job" not in result
