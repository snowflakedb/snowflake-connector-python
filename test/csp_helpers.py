from __future__ import annotations

import datetime
import json
import logging
import os
from abc import ABC, abstractmethod
from contextlib import ExitStack
from time import time
from unittest import mock
from urllib.parse import parse_qs, urlparse

import jwt
from botocore.awsrequest import AWSRequest
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
    def reset_defaults(self) -> None: ...

    @abstractmethod
    def is_expected_hostname(self, host: str | None) -> bool: ...

    @abstractmethod
    def handle_request(
        self,
        method,
        parsed_url,
        headers,
        timeout,
    ) -> Response: ...

    def __call__(self, method, url, headers=None, timeout=None, **_kw):
        """Entry-point for the requests monkey-patch."""
        headers = headers or {}
        parsed = urlparse(url)
        logger.debug("FakeMetadataService received %s %s %s", method, url, headers)

        if not self.is_expected_hostname(parsed.hostname):
            logger.debug("Unexpected hostname %s – timeout", parsed.hostname)
            raise ConnectTimeout()

        return self.handle_request(method.upper(), parsed, headers, timeout)

    def __enter__(self):
        """Patch requests & urllib3 so no real traffic escapes."""
        self.reset_defaults()
        self._context_stack = ExitStack()
        self._context_stack.enter_context(
            mock.patch(
                "snowflake.connector.vendored.requests.request",
                side_effect=self,
            )
        )
        self._context_stack.enter_context(
            mock.patch(
                "urllib3.connection.HTTPConnection.request",
                side_effect=ConnectTimeout(),
            )
        )
        return self

    def __exit__(self, *exc):
        self._context_stack.close()  # type: ignore[arg-type]


class NoMetadataService(FakeMetadataService):
    """Always times out – simulates an environment without any metadata service."""

    def reset_defaults(self) -> None:
        pass

    def is_expected_hostname(self, host: str | None) -> bool:
        return False

    def handle_request(self, *_):
        raise ConnectTimeout()


class FakeAzureVmMetadataService(FakeMetadataService):
    """Simulates Azure VM metadata endpoint."""

    def reset_defaults(self) -> None:
        self.sub = "611ab25b-2e81-4e18-92a7-b21f2bebb269"
        self.iss = "https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd"

    def is_expected_hostname(self, host: str | None) -> bool:
        return host == "169.254.169.254"

    def handle_request(self, method, parsed_url, headers, timeout):
        qs = parse_qs(parsed_url.query)
        if not (
            method == "GET"
            and parsed_url.path == "/metadata/identity/oauth2/token"
            and headers.get("Metadata") == "True"
            and qs.get("resource")
        ):
            raise HTTPError()

        resource = qs["resource"][0]
        self.token = gen_dummy_id_token(self.sub, self.iss, resource)
        return build_response(json.dumps({"access_token": self.token}).encode())


class FakeAzureFunctionMetadataService(FakeMetadataService):
    """Simulates Azure Functions MSI endpoint."""

    def reset_defaults(self) -> None:
        self.sub = "611ab25b-2e81-4e18-92a7-b21f2bebb269"
        self.iss = "https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd"
        self.identity_endpoint = "http://169.254.255.2:8081/msi/token"
        self.identity_header = "FD80F6DA783A4881BE9FAFA365F58E7A"
        self.parsed_identity_endpoint = urlparse(self.identity_endpoint)

    def __enter__(self):
        os.environ["IDENTITY_ENDPOINT"] = self.identity_endpoint
        os.environ["IDENTITY_HEADER"] = self.identity_header
        return super().__enter__()

    def __exit__(self, *exc):
        os.environ.pop("IDENTITY_ENDPOINT", None)
        os.environ.pop("IDENTITY_HEADER", None)
        return super().__exit__(*exc)

    def is_expected_hostname(self, host: str | None) -> bool:
        return host == self.parsed_identity_endpoint.hostname

    def handle_request(self, method, parsed_url, headers, timeout):
        qs = parse_qs(parsed_url.query)
        if not (
            method == "GET"
            and parsed_url.path == self.parsed_identity_endpoint.path
            and headers.get("X-IDENTITY-HEADER") == self.identity_header
            and qs.get("resource")
        ):
            raise HTTPError()

        resource = qs["resource"][0]
        self.token = gen_dummy_id_token(self.sub, self.iss, resource)
        return build_response(json.dumps({"access_token": self.token}).encode())


class FakeGceMetadataService(FakeMetadataService):
    """Simulates GCE metadata endpoint."""

    def reset_defaults(self) -> None:
        self.sub = "123"
        self.iss = "https://accounts.google.com"

    def is_expected_hostname(self, host: str | None) -> bool:
        return host == "169.254.169.254"

    def handle_request(self, method, parsed_url, headers, timeout):
        qs = parse_qs(parsed_url.query)
        if not (
            method == "GET"
            and parsed_url.path
            == "/computeMetadata/v1/instance/service-accounts/default/identity"
            and headers.get("Metadata-Flavor") == "Google"
            and qs.get("audience")
        ):
            raise HTTPError()

        audience = qs["audience"][0]
        self.token = gen_dummy_id_token(self.sub, self.iss, audience)
        return build_response(self.token.encode())


class _AwsMetadataService(FakeMetadataService):
    """Low-level fake for IMDSv2 and ECS endpoints."""

    def reset_defaults(self) -> None:
        self.role_name = "MyRole"
        self.access_key = "AKIA_TEST"
        self.secret_key = "SK_TEST"
        self.session_token = "STS_TOKEN"
        self.imds_token = "IMDS_TOKEN"

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
                headers={"x-aws-ec2-metadata-token-ttl-seconds": "21600"},
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

        ecs_uri = os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        if ecs_uri and method == "GET" and url == f"{_ECS_CRED_BASE_URL}{ecs_uri}":
            creds_json = json.dumps(
                {
                    "AccessKeyId": self.access_key,
                    "SecretAccessKey": self.secret_key,
                    "Token": self.session_token,
                }
            ).encode()
            return build_response(creds_json)

        raise ConnectTimeout()


class FakeAwsEnvironment:
    """Context-manager fixture that fakes AWS metadata plus helper functions."""

    def __init__(self):
        self.region = "us-east-1"
        self.arn = "arn:aws:sts::123456789:assumed-role/My-Role/i-34afe100cad287fab"
        self.credentials: Credentials | None = Credentials(
            access_key="ak", secret_key="sk"
        )

        self._metadata = _AwsMetadataService()
        self._stack: ExitStack | None = None

    def get_region(self):
        return self.region

    def get_arn(self):
        return self.arn

    def get_credentials(self):
        return self.credentials

    def __enter__(self):
        # Keep metadata service in sync with the top-level attrs each time we enter
        self._metadata.access_key = (
            self.credentials.access_key if self.credentials else None
        )
        self._metadata.secret_key = (
            self.credentials.secret_key if self.credentials else None
        )
        self._metadata.session_token = (
            self.credentials.token if self.credentials else None
        )

        self._stack = ExitStack()
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
        self._stack.enter_context(
            mock.patch(
                "snowflake.connector.wif_util.get_region",
                side_effect=self.get_region,
            )
        )
        # critical: ensure driver’s helper uses our current credential state
        self._stack.enter_context(
            mock.patch(
                "snowflake.connector.wif_util.load_default_credentials",
                side_effect=self.get_credentials,
            )
        )
        return self

    def __exit__(self, *exc):
        self._stack.close()  # type: ignore[arg-type]

    # Helper occasionally used in SigV4 parity tests
    @staticmethod
    def sign_request(request: AWSRequest):
        request.headers.add_header(
            "X-Amz-Date", datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        )
        request.headers.add_header("X-Amz-Security-Token", "<TOKEN>")
        request.headers.add_header(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=<cred>, SignedHeaders=host;x-amz-date,Signature=<sig>",
        )
