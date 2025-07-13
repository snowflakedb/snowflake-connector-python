from __future__ import annotations

import contextlib
import json
import logging
import os
from abc import ABC, abstractmethod
from contextlib import ExitStack
from time import time
from unittest import mock
from urllib.parse import parse_qs, urlparse

import jwt
from botocore.credentials import Credentials

from snowflake.connector._aws_credentials import (
    _ECS_CRED_BASE_URL,
    _IMDS_BASE_URL,
    _IMDS_ROLE_PATH,
    _IMDS_TOKEN_PATH,
)
from snowflake.connector.vendored.requests.exceptions import ConnectTimeout, HTTPError
from snowflake.connector.vendored.requests.models import Response

logger = logging.getLogger(__name__)

AZURE_VM_METADATA_HOST = "169.254.169.254"
AZURE_VM_TOKEN_PATH = "/metadata/identity/oauth2/token"

AZURE_FUNCTION_IDENTITY_ENDPOINT = "http://169.254.255.2:8081/msi/token"
AZURE_FUNCTION_IDENTITY_HEADER = "FD80F6DA783A4881BE9FAFA365F58E7A"

GCE_METADATA_HOST = "169.254.169.254"
GCE_IDENTITY_PATH = "/computeMetadata/v1/instance/service-accounts/default/identity"

AWS_REGION_ENV_KEYS = ("AWS_REGION", "AWS_DEFAULT_REGION")
AWS_CONTAINER_CRED_ENV = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
AWS_LAMBDA_FUNCTION_ENV = "AWS_LAMBDA_FUNCTION_NAME"

HDR_IDENTITY = "X-IDENTITY-HEADER"
HDR_METADATA = "Metadata"
HDR_METADATA_FLAVOR = "Metadata-Flavor"
HDR_IMDS_TOKEN_TTL = "x-aws-ec2-metadata-token-ttl-seconds"
IMDS_INSTANCE_IDENTITY_DOC = "/latest/dynamic/instance-identity/document"
IMDS_REGION_PATH = "/latest/meta-data/placement/region"

AWS_CREDENTIAL_ENV_KEYS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_ROLE_ARN",
    "AWS_EC2_METADATA_ARN",
    "AWS_SESSION_ARN",
)


def gen_dummy_id_token(
    sub: str = "test-subject",
    iss: str = "test-issuer",
    aud: str = "snowflakecomputing.com",
) -> str:
    """Generates a dummy HS256-signed JWT."""
    now = int(time())
    payload = {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "iat": now,
        "exp": now + 60 * 60,
    }
    logger.debug("Generating dummy token with claims %s", payload)
    return jwt.encode(payload, key="secret", algorithm="HS256")


def build_response(
    content: bytes,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    """Return a minimal Response object with canned body/headers."""
    resp = Response()
    resp.status_code = status_code
    resp._content = content
    if headers:
        resp.headers.update(headers)
    return resp


class FakeMetadataService(ABC):
    """Base class for cloud-metadata fakes."""

    def __init__(self) -> None:
        self.reset_defaults()
        self._context_stack: ExitStack | None = None

    @abstractmethod
    def reset_defaults(self) -> None:
        """Resets any default values for test parameters.

        This is called in the constructor and when entering as a context manager.
        """
        pass

    @abstractmethod
    def is_expected_hostname(self, host: str | None) -> bool:
        """Returns true if the passed hostname is the one at which this metadata service is listening.

        Used to raise a ConnectTimeout for requests not targeted to this hostname.
        """
        pass

    @abstractmethod
    def handle_request(
        self,
        method,
        parsed_url,
        headers,
        timeout,
    ) -> Response:
        """Main business logic for handling this request. Should return a Response object."""
        pass

    def __call__(self, method, url, headers=None, timeout=None, **_kw):
        """Entry-point for the requests monkey-patch."""
        headers = headers or {}
        parsed = urlparse(url)
        logger.debug("FakeMetadataService received %s %s %s", method, url, headers)

        if not self.is_expected_hostname(parsed.hostname):
            logger.debug(
                "Received request to unexpected hostname %s – timeout", parsed.hostname
            )
            raise ConnectTimeout()

        return self.handle_request(method.upper(), parsed, headers, timeout)

    def __enter__(self):
        """Patches the relevant HTTP calls when entering as a context manager."""
        self.reset_defaults()
        self._context_stack = ExitStack()
        self._context_stack.enter_context(
            mock.patch(
                "snowflake.connector.vendored.requests.request",
                side_effect=self,
            )
        )
        # HTTPConnection.request is used by the AWS boto libraries. We're not mocking those calls here, so we
        # simply raise a ConnectTimeout to avoid making real network calls.
        self._context_stack.enter_context(
            mock.patch(
                "urllib3.connection.HTTPConnection.request",
                side_effect=ConnectTimeout(),
            )
        )
        return self

    def __exit__(self, *exc):
        self._context_stack.close()


class NoMetadataService(FakeMetadataService):
    """Always times out – simulates an environment without any metadata service."""

    def reset_defaults(self) -> None:
        pass

    def is_expected_hostname(self, host: str | None) -> bool:
        return False

    def handle_request(self, *_):
        # This should never be called because we always raise a ConnectTimeout.
        raise AssertionError(
            "This should never be called because we always raise a ConnectTimeout."
        )


class FakeAzureVmMetadataService(FakeMetadataService):
    """Emulates an environment with the Azure VM metadata service."""

    def reset_defaults(self) -> None:
        # Defaults used for generating an Entra ID token. Can be overriden in individual tests.
        self.sub = "611ab25b-2e81-4e18-92a7-b21f2bebb269"
        self.iss = "https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd"

    def is_expected_hostname(self, host: str | None) -> bool:
        return host == AZURE_VM_METADATA_HOST

    def handle_request(self, method, parsed_url, headers, timeout):
        query_string = parse_qs(parsed_url.query)

        # Reject malformed requests.
        if not (
            method == "GET"
            and parsed_url.path == AZURE_VM_TOKEN_PATH
            and headers.get(HDR_METADATA) == "True"
            and query_string.get("resource")
        ):
            raise HTTPError()

        logger.debug("Received request for Azure VM metadata service")

        resource = query_string["resource"][0]
        self.token = gen_dummy_id_token(sub=self.sub, iss=self.iss, aud=resource)
        return build_response(json.dumps({"access_token": self.token}).encode())


class FakeAzureFunctionMetadataService(FakeMetadataService):
    """Emulates an environment with the Azure Function metadata service."""

    def reset_defaults(self) -> None:
        # Defaults used for generating an Entra ID token. Can be overriden in individual tests.
        self.sub = "611ab25b-2e81-4e18-92a7-b21f2bebb269"
        self.iss = "https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd"
        self.identity_endpoint = AZURE_FUNCTION_IDENTITY_ENDPOINT
        self.identity_header = AZURE_FUNCTION_IDENTITY_HEADER
        self.parsed_identity_endpoint = urlparse(self.identity_endpoint)
        self._stack: contextlib.ExitStack | None = None

    def __enter__(self):
        # Inject the variables *without* touching os.environ directly
        self._stack = contextlib.ExitStack()
        self._stack.enter_context(
            mock.patch.dict(
                os.environ,
                {
                    "IDENTITY_ENDPOINT": self.identity_endpoint,
                    "IDENTITY_HEADER": self.identity_header,
                },
                clear=False,
            )
        )
        self._stack.enter_context(
            mock.patch.dict(
                os.environ,
                {k: "" for k in AWS_CREDENTIAL_ENV_KEYS + AWS_REGION_ENV_KEYS},
                clear=False,
            )
        )

        return super().__enter__()

    def __exit__(self, *exc):
        self._stack.close()
        return super().__exit__(*exc)

    def is_expected_hostname(self, host: str | None) -> bool:
        return host == self.parsed_identity_endpoint.hostname

    def handle_request(self, method, parsed_url, headers, timeout):
        query_string = parse_qs(parsed_url.query)

        # Reject malformed requests.
        if not (
            method == "GET"
            and parsed_url.path == self.parsed_identity_endpoint.path
            and headers.get(HDR_IDENTITY) == self.identity_header
            and query_string["resource"]
        ):
            logger.warning(
                f"Received malformed request: {method} {parsed_url.path} {str(headers)} {str(query_string)}"
            )
            raise HTTPError()

        logger.debug("Received request for Azure Functions metadata service")

        resource = query_string["resource"][0]
        self.token = gen_dummy_id_token(self.sub, self.iss, resource)
        return build_response(json.dumps({"access_token": self.token}).encode())


class FakeGceMetadataService(FakeMetadataService):
    """Simulates GCE metadata endpoint."""

    def reset_defaults(self) -> None:
        # Defaults used for generating a token. Can be overriden in individual tests.
        self.sub = "123"
        self.iss = "https://accounts.google.com"

    def is_expected_hostname(self, host: str | None) -> bool:
        return host == GCE_METADATA_HOST

    def handle_request(self, method, parsed_url, headers, timeout):
        query_string = parse_qs(parsed_url.query)

        # Reject malformed requests.
        if not (
            method == "GET"
            and parsed_url.path == GCE_IDENTITY_PATH
            and headers.get(HDR_METADATA_FLAVOR) == "Google"
            and query_string.get("audience")
        ):
            raise HTTPError()

        logger.debug("Received request for GCE metadata service")

        audience = query_string["audience"][0]
        self.token = gen_dummy_id_token(sub=self.sub, iss=self.iss, aud=audience)
        return build_response(self.token.encode())


class _AwsMetadataService(FakeMetadataService):
    """Low-level fake for IMDSv2 and ECS endpoints."""

    def reset_defaults(self) -> None:
        self.role_name = "MyRole"
        self.access_key = "AKIA_TEST"
        self.secret_key = "SK_TEST"
        self.session_token = "STS_TOKEN"
        self.imds_token = "IMDS_TOKEN"
        self.region = "us-east-1"

    def is_expected_hostname(self, host: str | None) -> bool:
        return host in {
            urlparse(_IMDS_BASE_URL).hostname,
            urlparse(_ECS_CRED_BASE_URL).hostname,
        }

    def handle_request(self, method, parsed_url, headers, timeout):
        url = f"{parsed_url.scheme}://{parsed_url.hostname}{parsed_url.path}"

        if method == "PUT" and url == f"{_IMDS_BASE_URL}{_IMDS_TOKEN_PATH}":
            return build_response(
                self.imds_token.encode(),
                headers={HDR_IMDS_TOKEN_TTL: "21600"},
            )

        if method == "GET" and url == f"{_IMDS_BASE_URL}{_IMDS_ROLE_PATH}":
            return build_response(self.role_name.encode())

        if (
            method == "GET"
            and url == f"{_IMDS_BASE_URL}{_IMDS_ROLE_PATH}{self.role_name}"
        ):
            if self.access_key is None or self.secret_key is None:
                return build_response(b"", status_code=404)
            creds_json = json.dumps(
                {
                    "AccessKeyId": self.access_key,
                    "SecretAccessKey": self.secret_key,
                    "Token": self.session_token,
                }
            ).encode()
            return build_response(creds_json)

        ecs_uri = os.getenv(AWS_CONTAINER_CRED_ENV)
        if ecs_uri and method == "GET" and url == f"{_ECS_CRED_BASE_URL}{ecs_uri}":
            creds_json = json.dumps(
                {
                    "AccessKeyId": self.access_key,
                    "SecretAccessKey": self.secret_key,
                    "Token": self.session_token,
                }
            ).encode()
            return build_response(creds_json)

        if method == "GET" and url == f"{_IMDS_BASE_URL}{IMDS_REGION_PATH}":
            return build_response(self.region.encode())

        if method == "GET" and url == f"{_IMDS_BASE_URL}{IMDS_INSTANCE_IDENTITY_DOC}":
            return build_response(json.dumps({"region": self.region}).encode())

        raise ConnectTimeout()


class FakeAwsEnvironment:
    """
    Base context-manager for AWS runtime fakes.
    Subclasses override `_prepare_runtime()` to tweak env-vars / creds.
    """

    def __init__(self):
        # Defaults used for generating a token. Can be overriden in individual tests.
        self._region = "us-east-1"
        self.arn = "arn:aws:sts::123456789:assumed-role/My-Role/i-34afe100cad287fab"
        self.credentials: Credentials | None = Credentials(
            access_key="ak", secret_key="sk", token="tk"
        )
        self._metadata = _AwsMetadataService()
        self._stack: ExitStack | None = None

    @property
    def region(self) -> str:
        return self._region

    @region.setter
    def region(self, new_region: str) -> None:
        """Change runtime region and, **if** the env-vars already exist,
        patch them via ExitStack so they’re cleaned up on __exit__.
        """
        self._region = new_region
        self._metadata.region = new_region
        if getattr(self, "_stack", None):
            for key in AWS_REGION_ENV_KEYS:
                if key in os.environ:
                    self._stack.enter_context(
                        mock.patch.dict(os.environ, {key: new_region}, clear=False)
                    )

    def _prepare_runtime(self):
        """Sub-classes patch env / credentials here."""
        return None

    def __enter__(self):
        """Activate the fake AWS runtime.

        * Only HTTP traffic is patched – no longer stubs `get_region`
          or `load_default_credentials`.
        * Region / credential discovery is driven entirely via
          environment variables, so the real helper functions keep
          working untouched.
        """
        self._stack = ExitStack()

        # Patch outgoing HTTP calls that rely on `requests` or the low-level
        #    urllib client, routing them to our metadata stub or timing-out.
        self._stack.enter_context(
            mock.patch(
                "snowflake.connector.vendored.requests.request",
                side_effect=self._metadata,
            )
        )
        self._stack.enter_context(
            mock.patch(
                "urllib3.connection.HTTPConnection.request",
                side_effect=ConnectTimeout(),
            )
        )

        # Keep the metadata stub in sync with the final credential set.
        self._metadata.access_key = (
            self.credentials.access_key if self.credentials else None
        )
        self._metadata.secret_key = (
            self.credentials.secret_key if self.credentials else None
        )
        self._metadata.session_token = (
            self.credentials.token if self.credentials else None
        )
        self._metadata.region = self.region if self.region else None

        # Expose region & creds *only* via env vars so that the real helper
        #    chain can resolve them without monkey-patching.
        env_for_chain = {key: self.region for key in AWS_REGION_ENV_KEYS}
        if self.credentials:
            env_for_chain["AWS_ACCESS_KEY_ID"] = self.credentials.access_key
            env_for_chain["AWS_SECRET_ACCESS_KEY"] = self.credentials.secret_key
            if self.credentials.token:
                env_for_chain["AWS_SESSION_TOKEN"] = self.credentials.token

        self._stack.enter_context(
            mock.patch.dict(os.environ, env_for_chain, clear=False)
        )

        # Runtime-specific tweaks (may change creds / env).
        self._prepare_runtime()
        return self

    def __exit__(self, *exc):
        self._stack.close()


class FakeAwsEc2(FakeAwsEnvironment):
    """Default – IMDSv2 only."""

    # nothing extra needed


class FakeAwsEcs(FakeAwsEnvironment):
    """ECS/EKS task-role – exposes creds via task metadata endpoint."""

    def _prepare_runtime(self):
        self._stack.enter_context(
            mock.patch.dict(
                os.environ,
                {AWS_CONTAINER_CRED_ENV: "/v2/credentials/test-id"},
                clear=False,
            )
        )


class FakeAwsLambda(FakeAwsEnvironment):
    """Lambda runtime – temporary credentials + runtime env-vars."""

    def __init__(self):
        super().__init__()
        # Lambda always returns *session* credentials
        self.credentials = Credentials(
            access_key="ak",
            secret_key="sk",
            token="dummy-session-token",
        )

    def _prepare_runtime(self) -> None:
        # Patch env vars via mock.patch.dict so nothing touches os.environ directly
        self._stack.enter_context(
            mock.patch.dict(
                os.environ,
                {AWS_LAMBDA_FUNCTION_ENV: "dummy-fn"},
                clear=False,
            )
        )


class FakeAwsNoCreds(FakeAwsEnvironment):
    """Negative path – no credentials anywhere."""

    def _prepare_runtime(self):
        self.credentials = None
        self._stack.enter_context(
            mock.patch.dict(
                os.environ,
                {
                    "AWS_ACCESS_KEY_ID": "",
                    "AWS_SECRET_ACCESS_KEY": "",
                    "AWS_SESSION_TOKEN": "",
                    AWS_CONTAINER_CRED_ENV: "",
                },
                clear=False,
            )
        )
