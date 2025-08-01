#!/usr/bin/env python
import datetime
import json
import logging
import os
from abc import ABC, abstractmethod
from time import time
from unittest import mock
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import jwt
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from snowflake.connector.vendored.requests.exceptions import ConnectTimeout, HTTPError
from snowflake.connector.vendored.requests.models import Response

logger = logging.getLogger(__name__)


def gen_dummy_id_token(
    sub="test-subject", iss="test-issuer", aud="snowflakecomputing.com"
) -> str:
    """Generates a dummy ID token using the given subject and issuer."""
    now = int(time())
    key = "secret"
    payload = {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + 60 * 60,
    }
    logger.debug(f"Generating dummy token with the following claims:\n{str(payload)}")
    return jwt.encode(
        payload=payload,
        key=key,
        algorithm="HS256",
    )


def build_response(content: bytes, status_code: int = 200, headers=None) -> Response:
    """Builds a requests.Response object with the given status code and content."""
    response = Response()
    response.status_code = status_code
    response._content = content
    response.headers = headers
    return response


class FakeMetadataService(ABC):
    """Base class for fake metadata service implementations."""

    def __init__(self):
        self.unexpected_host_name_exception = ConnectTimeout()
        self.reset_defaults()

    @abstractmethod
    def reset_defaults(self):
        """Resets any default values for test parameters.

        This is called in the constructor and when entering as a context manager.
        """
        pass

    @property
    @abstractmethod
    def expected_hostnames(self):
        """Hostnames at which this metadata service is listening.

        Used to raise a ConnectTimeout for requests not targeted to this hostname.
        """
        pass

    def handle_request(self, method, parsed_url, headers, timeout):
        return ConnectTimeout()

    def get_environment_variables(self) -> dict[str, str]:
        """Returns a dictionary of environment variables to patch in to fake the metadata service."""
        return {}

    def _handle_get(self, url, headers=None, timeout=None):
        """Handles requests.get() calls by converting them to request() format."""
        if headers is None:
            headers = {}
        return self.__call__(method="GET", url=url, headers=headers, timeout=timeout)

    def __call__(self, method, url, headers, timeout):
        """Entry point for the requests mock."""
        logger.debug(f"Received request: {method} {url} {str(headers)}")
        parsed_url = urlparse(url)

        if parsed_url.hostname not in self.expected_hostnames:
            logger.debug(
                f"Received request to unexpected hostname {parsed_url.hostname}"
            )
            raise self.unexpected_host_name_exception

        return self.handle_request(method, parsed_url, headers, timeout)

    def __enter__(self):
        """Patches the relevant HTTP calls when entering as a context manager."""
        self.reset_defaults()
        self.patchers = []
        # requests.request is used by the direct metadata service API calls from our code. This is the main
        # thing being faked here.
        self.patchers.append(
            mock.patch(
                "snowflake.connector.vendored.requests.request", side_effect=self
            )
        )
        self.patchers.append(
            mock.patch(
                "snowflake.connector.vendored.requests.get",
                side_effect=self._handle_get,
            )
        )
        # HTTPConnection.request is used by the AWS boto libraries. We're not mocking those calls here, so we
        # simply raise a ConnectTimeout to avoid making real network calls.
        self.patchers.append(
            mock.patch(
                "urllib3.connection.HTTPConnection.request",
                side_effect=ConnectTimeout(),
            )
        )
        # Patch the environment variables to fake the metadata service
        # Note that this doesn't clear, so it's additive to the existing environment.
        self.patchers.append(patch.dict(os.environ, self.get_environment_variables()))
        for patcher in self.patchers:
            patcher.__enter__()
        return self

    def __exit__(self, *args, **kwargs):
        for patcher in self.patchers:
            patcher.__exit__(*args, **kwargs)


class UnavailableMetadataService(FakeMetadataService):
    """Emulates an environment where all metadata services are unavailable."""

    def reset_defaults(self):
        pass

    @property
    def expected_hostnames(self):
        return []  # Always raise a ConnectTimeout.

    def handle_request(self, method, parsed_url, headers, timeout):
        # This should never be called because we always raise a ConnectTimeout.
        pass


class FakeAzureVmMetadataService(FakeMetadataService):
    """Emulates an environment with the Azure VM metadata service."""

    def reset_defaults(self):
        # Defaults used for generating an Entra ID token. Can be overriden in individual tests.
        self.sub = "611ab25b-2e81-4e18-92a7-b21f2bebb269"
        self.iss = "https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd"

    @property
    def expected_hostnames(self):
        return ["169.254.169.254"]

    def handle_request(self, method, parsed_url, headers, timeout):
        query_string = parse_qs(parsed_url.query)

        logger.debug("Received request for Azure VM metadata service")

        if (
            method == "GET"
            and parsed_url.path == "/metadata/instance"
            and headers.get("Metadata") == "True"
        ):
            return build_response(content=b"", status_code=200)
        elif (
            method == "GET"
            and parsed_url.path == "/metadata/identity/oauth2/token"
            and headers.get("Metadata") == "True"
            and query_string["resource"]
        ):
            resource = query_string["resource"][0]
            self.token = gen_dummy_id_token(sub=self.sub, iss=self.iss, aud=resource)
            return build_response(
                json.dumps({"access_token": self.token}).encode("utf-8")
            )
        else:
            # Reject malformed requests.
            raise HTTPError()


class FakeAzureFunctionMetadataService(FakeMetadataService):
    """Emulates an environment with the Azure Function metadata service."""

    def reset_defaults(self):
        # Defaults used for generating an Entra ID token. Can be overriden in individual tests.
        self.sub = "611ab25b-2e81-4e18-92a7-b21f2bebb269"
        self.iss = "https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd"

        self.identity_endpoint = "http://169.254.255.2:8081/msi/token"
        self.identity_header = "FD80F6DA783A4881BE9FAFA365F58E7A"
        self.functions_worker_runtime = "python"
        self.functions_extension_version = "~4"
        self.azure_web_jobs_storage = "DefaultEndpointsProtocol=https;AccountName=test"
        self.parsed_identity_endpoint = urlparse(self.identity_endpoint)

    @property
    def expected_hostnames(self):
        return [self.parsed_identity_endpoint.hostname]

    def handle_request(self, method, parsed_url, headers, timeout):
        query_string = parse_qs(parsed_url.query)

        # Reject malformed requests.
        if not (
            method == "GET"
            and parsed_url.path == self.parsed_identity_endpoint.path
            and headers.get("X-IDENTITY-HEADER") == self.identity_header
            and query_string["resource"]
        ):
            logger.warning(
                f"Received malformed request: {method} {parsed_url.path} {str(headers)} {str(query_string)}"
            )
            raise HTTPError()

        logger.debug("Received request for Azure Functions metadata service")

        resource = query_string["resource"][0]
        self.token = gen_dummy_id_token(sub=self.sub, iss=self.iss, aud=resource)
        return build_response(json.dumps({"access_token": self.token}).encode("utf-8"))

    def get_environment_variables(self) -> dict[str, str]:
        return {
            "IDENTITY_ENDPOINT": self.identity_endpoint,
            "IDENTITY_HEADER": self.identity_header,
            "FUNCTIONS_WORKER_RUNTIME": self.functions_worker_runtime,
            "FUNCTIONS_EXTENSION_VERSION": self.functions_extension_version,
            "AzureWebJobsStorage": self.azure_web_jobs_storage,
        }


class FakeGceMetadataService(FakeMetadataService):
    """Emulates an environment with the GCE metadata service."""

    def reset_defaults(self):
        # Defaults used for generating a token. Can be overriden in individual tests.
        self.sub = "123"
        self.iss = "https://accounts.google.com"

    @property
    def expected_hostnames(self):
        return ["169.254.169.254", "metadata.google.internal"]

    def handle_request(self, method, parsed_url, headers, timeout):
        query_string = parse_qs(parsed_url.query)

        logger.debug("Received request for GCE metadata service")

        if method == "GET" and parsed_url.path == "":
            return build_response(
                b"", status_code=200, headers={"Metadata-Flavor": "Google"}
            )
        elif (
            method == "GET"
            and parsed_url.path
            == "/computeMetadata/v1/instance/service-accounts/default/email"
            and headers.get("Metadata-Flavor") == "Google"
        ):
            return build_response(b"", status_code=200)
        elif (
            method == "GET"
            and parsed_url.path
            == "/computeMetadata/v1/instance/service-accounts/default/identity"
            and headers.get("Metadata-Flavor") == "Google"
            and query_string["audience"]
        ):
            audience = query_string["audience"][0]
            self.token = gen_dummy_id_token(sub=self.sub, iss=self.iss, aud=audience)
            return build_response(self.token.encode("utf-8"))
        else:
            # Reject malformed requests.
            raise HTTPError()


class FakeGceCloudRunServiceService(FakeGceMetadataService):
    """Emulates an environment with the GCE Cloud Run Service metadata service."""

    def reset_defaults(self):
        self.k_service = "test-service"
        self.k_revision = "test-revision"
        self.k_configuration = "test-configuration"
        super().reset_defaults()

    def get_environment_variables(self) -> dict[str, str]:
        return {
            "K_SERVICE": self.k_service,
            "K_REVISION": self.k_revision,
            "K_CONFIGURATION": self.k_configuration,
        }


class FakeGceCloudRunJobService(FakeGceMetadataService):
    """Emulates an environment with the GCE Cloud Run Job metadata service."""

    def reset_defaults(self):
        self.cloud_run_job = "test-job"
        self.cloud_run_execution = "test-execution"
        super().reset_defaults()

    def get_environment_variables(self) -> dict[str, str]:
        return {
            "CLOUD_RUN_JOB": self.cloud_run_job,
            "CLOUD_RUN_EXECUTION": self.cloud_run_execution,
        }


class FakeGitHubActionsService:
    """Emulates an environment running in GitHub Actions."""

    def __enter__(self):
        # This doesn't clear, so it's additive to the existing environment.
        self.os_environment_patch = patch.dict(
            os.environ, {"GITHUB_ACTIONS": "github-actions"}
        )
        self.os_environment_patch.__enter__()
        return self

    def __exit__(self, *args, **kwargs):
        self.os_environment_patch.__exit__(*args)


class FakeAwsEnvironment:
    """Emulates the AWS environment-specific functions used in wif_util.py and platform detection.py.

    Unlike the other metadata services, the HTTP calls made by AWS are deep within boto libaries, so
    emulating them here would be complex and fragile. Instead, we emulate the higher-level functions
    called by the connector code.
    """

    def __init__(self):
        # Defaults used for generating a token. Can be overriden in individual tests.
        self.arn = "arn:aws:sts::123456789:assumed-role/My-Role/i-34afe100cad287fab"
        self.caller_identity = {"Arn": self.arn}
        self.region = "us-east-1"
        self.credentials = Credentials(access_key="ak", secret_key="sk")
        self.instance_document = (
            b'{"region": "us-east-1", "instanceId": "i-1234567890abcdef0"}'
        )
        self.metadata_token = "test-token"

    def get_region(self):
        return self.region

    def get_arn(self):
        return self.arn

    def get_credentials(self):
        return self.credentials

    def sign_request(self, request: AWSRequest):
        request.headers.add_header("X-Amz-Date", datetime.time().isoformat())
        request.headers.add_header("X-Amz-Security-Token", "<TOKEN>")
        request.headers.add_header(
            "Authorization",
            f"AWS4-HMAC-SHA256 Credential=<cred>, SignedHeaders={';'.join(request.headers.keys())}, Signature=<sig>",
        )

    def fetcher_get_request(self, url_path, retry_fun, token):
        return build_response(self.instance_document)

    def fetcher_fetch_metadata_token(self):
        return self.metadata_token

    def boto3_client(self, *args, **kwargs):
        mock_client = mock.Mock()
        mock_client.get_caller_identity.return_value = self.caller_identity
        return mock_client

    def __enter__(self):
        # Patch the relevant functions to do what we want.
        self.patchers = []
        self.patchers.append(
            mock.patch(
                "boto3.session.Session.get_credentials",
                side_effect=self.get_credentials,
            )
        )
        self.patchers.append(
            mock.patch(
                "botocore.auth.SigV4Auth.add_auth", side_effect=self.sign_request
            )
        )
        self.patchers.append(
            mock.patch(
                "snowflake.connector.wif_util.get_aws_region",
                side_effect=self.get_region,
            )
        )
        self.patchers.append(
            mock.patch(
                "snowflake.connector.wif_util.get_aws_arn", side_effect=self.get_arn
            )
        )
        self.patchers.append(
            mock.patch(
                "snowflake.connector.platform_detection.IMDSFetcher._get_request",
                side_effect=self.fetcher_get_request,
            )
        )
        self.patchers.append(
            mock.patch(
                "snowflake.connector.platform_detection.IMDSFetcher._fetch_metadata_token",
                side_effect=self.fetcher_fetch_metadata_token,
            )
        )
        self.patchers.append(
            mock.patch(
                "snowflake.connector.platform_detection.boto3.client",
                side_effect=self.boto3_client,
            )
        )
        for patcher in self.patchers:
            patcher.__enter__()
        return self

    def __exit__(self, *args, **kwargs):
        for patcher in self.patchers:
            patcher.__exit__(*args, **kwargs)


class FakeAwsLambdaEnvironment(FakeAwsEnvironment):
    """Emulates an environment running in AWS Lambda."""

    def __enter__(self):
        # This doesn't clear, so it's additive to the existing environment.
        self.os_environment_patch = patch.dict(
            os.environ, {"LAMBDA_TASK_ROOT": "/var/task"}
        )
        self.os_environment_patch.__enter__()
        return super().__enter__()

    def __exit__(self, *args, **kwargs):
        self.os_environment_patch.__exit__(*args)
        super().__exit__(args, **kwargs)
