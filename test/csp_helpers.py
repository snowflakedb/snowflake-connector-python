#!/usr/bin/env python
from __future__ import annotations

import datetime
import json
import logging
import os
from abc import ABC, abstractmethod
from time import time
from unittest import mock
from urllib.parse import parse_qs, urlparse

import jwt

# Boto is left as a development-dependency - to be sure our http requests correspond to the appropriate behavior and old driver tests are passing in the future
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from snowflake.connector.vendored.requests.exceptions import ConnectTimeout, HTTPError
from snowflake.connector.vendored.requests.models import Response
from snowflake.connector.wif_util import AwsCredentials

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


def build_response(content: bytes, status_code: int = 200) -> Response:
    """Builds a requests.Response object with the given status code and content."""
    response = Response()
    response.status_code = status_code
    response._content = content
    return response


class FakeMetadataService(ABC):
    """Base class for fake metadata service implementations."""

    def __init__(self):
        self.reset_defaults()

    @abstractmethod
    def reset_defaults(self):
        """Resets any default values for test parameters.

        This is called in the constructor and when entering as a context manager.
        """
        pass

    @property
    @abstractmethod
    def expected_hostname(self):
        """Hostname at which this metadata service is listening.

        Used to raise a ConnectTimeout for requests not targeted to this hostname.
        """
        pass

    @abstractmethod
    def handle_request(self, method, parsed_url, headers, timeout):
        """Main business logic for handling this request. Should return a Response object."""
        pass

    def __call__(self, method, url, headers, timeout):
        """Entry point for the requests mock."""
        logger.debug(f"Received request: {method} {url} {str(headers)}")
        parsed_url = urlparse(url)

        if not parsed_url.hostname == self.expected_hostname:
            logger.debug(
                f"Received request to unexpected hostname {parsed_url.hostname}"
            )
            raise ConnectTimeout()

        return self.handle_request(method, parsed_url, headers, timeout)

    def __enter__(self):
        """Patches the relevant HTTP calls when entering as a context manager."""
        self.reset_defaults()
        self.patchers = []
        # Session.request is used by the direct metadata service API calls from our code. This is the main
        # thing being faked here.
        self.patchers.append(
            mock.patch(
                "snowflake.connector.vendored.requests.Session.request",
                side_effect=self,
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
        for patcher in self.patchers:
            patcher.__enter__()
        return self

    def __exit__(self, *args, **kwargs):
        for patcher in self.patchers:
            patcher.__exit__(*args, **kwargs)


class NoMetadataService(FakeMetadataService):
    """Emulates an environment without any metadata service."""

    def reset_defaults(self):
        pass

    @property
    def expected_hostname(self):
        return None  # Always raise a ConnectTimeout.

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
    def expected_hostname(self):
        return "169.254.169.254"

    def handle_request(self, method, parsed_url, headers, timeout):
        query_string = parse_qs(parsed_url.query)

        # Reject malformed requests.
        if not (
            method == "GET"
            and parsed_url.path == "/metadata/identity/oauth2/token"
            and headers.get("Metadata") == "True"
            and query_string["resource"]
        ):
            raise HTTPError()

        logger.debug("Received request for Azure VM metadata service")

        resource = query_string["resource"][0]
        self.token = gen_dummy_id_token(sub=self.sub, iss=self.iss, aud=resource)
        return build_response(json.dumps({"access_token": self.token}).encode("utf-8"))


class FakeAzureFunctionMetadataService(FakeMetadataService):
    """Emulates an environment with the Azure Function metadata service."""

    def reset_defaults(self):
        # Defaults used for generating an Entra ID token. Can be overriden in individual tests.
        self.sub = "611ab25b-2e81-4e18-92a7-b21f2bebb269"
        self.iss = "https://sts.windows.net/2c0183ed-cf17-480d-b3f7-df91bc0a97cd"

        self.identity_endpoint = "http://169.254.255.2:8081/msi/token"
        self.identity_header = "FD80F6DA783A4881BE9FAFA365F58E7A"
        self.parsed_identity_endpoint = urlparse(self.identity_endpoint)

    @property
    def expected_hostname(self):
        return self.parsed_identity_endpoint.hostname

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

    def __enter__(self):
        # In addition to the normal patching, we need to set the environment variables that Azure Functions would set.
        os.environ["IDENTITY_ENDPOINT"] = self.identity_endpoint
        os.environ["IDENTITY_HEADER"] = self.identity_header
        return super().__enter__()

    def __exit__(self, *args, **kwargs):
        os.environ.pop("IDENTITY_ENDPOINT")
        os.environ.pop("IDENTITY_HEADER")
        return super().__exit__(*args, **kwargs)


class FakeGceMetadataService(FakeMetadataService):
    """Emulates an environment with the GCE metadata service."""

    def reset_defaults(self):
        # Defaults used for generating a token. Can be overriden in individual tests.
        self.sub = "123"
        self.iss = "https://accounts.google.com"

    @property
    def expected_hostname(self):
        return "169.254.169.254"

    def handle_request(self, method, parsed_url, headers, timeout):
        query_string = parse_qs(parsed_url.query)

        # Reject malformed requests.
        if not (
            method == "GET"
            and parsed_url.path
            == "/computeMetadata/v1/instance/service-accounts/default/identity"
            and headers.get("Metadata-Flavor") == "Google"
            and query_string["audience"]
        ):
            raise HTTPError()

        logger.debug("Received request for GCE metadata service")

        audience = query_string["audience"][0]
        self.token = gen_dummy_id_token(sub=self.sub, iss=self.iss, aud=audience)
        return build_response(self.token.encode("utf-8"))


class FakeAwsEnvironment:
    """Emulates AWS for both the legacy boto path and the new SDK-free helpers."""

    def __init__(self):
        # Defaults used for generating a token. Can be overriden in individual tests.
        self.arn = "arn:aws:sts::123456789:assumed-role/My-Role/i-abc123"
        self.region = "us-east-1"

        # boto-style creds (used by old tests / patches)
        self.boto_creds = Credentials("AKIA123", "SECRET123", token="SESSION_TOKEN")

        # util-style creds (returned by get_aws_credentials)
        self.util_creds = AwsCredentials(
            access_key=self.boto_creds.access_key,
            secret_key=self.boto_creds.secret_key,
            token=self.boto_creds.token,
        )

    def get_region(self, *_, **__) -> str:
        return self.region

    def get_arn(self, *_, **__) -> str:
        return self.arn

    def get_boto_credentials(self, *_, **__) -> Credentials | None:
        return self.boto_creds

    def get_aws_credentials(self, *_, **__) -> AwsCredentials | None:
        return self.util_creds

    def sign_request(self, request: AWSRequest) -> None:
        """
        Fake replacement for botocore SigV4Auth.add_auth that produces the same
        *static* parts of the Authorization header (everything before
        `Signature=`).
        """
        # Add the headers a real signer would inject
        utc_now = datetime.datetime.utcnow()
        amz_date = utc_now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = utc_now.strftime("%Y%m%d")

        request.headers["X-Amz-Date"] = amz_date
        request.headers["X-Amz-Security-Token"] = self.util_creds.token

        # Host header is already set by the test; add it if a future test forgets
        if "Host" not in request.headers:
            request.headers["Host"] = urlparse(request.url).netloc

        # Build the signed-headers list
        signed_headers = ";".join(sorted(h.lower() for h in request.headers.keys()))

        credential_scope = f"{date_stamp}/{self.region}/sts/aws4_request"

        request.headers["Authorization"] = (
            "AWS4-HMAC-SHA256 "
            f"Credential={self.util_creds.access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature=<sig>"
        )

    def __enter__(self):
        # Preserve existing env and then set creds/region for util fallback
        self._old_env = {
            k: os.environ.get(k)
            for k in (
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_REGION",
            )
        }
        os.environ.update(
            {
                "AWS_ACCESS_KEY_ID": self.util_creds.access_key,
                "AWS_SECRET_ACCESS_KEY": self.util_creds.secret_key,
                "AWS_SESSION_TOKEN": self.util_creds.token or "",
                "AWS_REGION": self.region,
            }
        )

        self.patchers = [
            # boto patches - for old driver tests
            mock.patch(
                "boto3.session.Session.get_credentials",
                side_effect=self.get_boto_credentials,
            ),
            mock.patch(
                "botocore.auth.SigV4Auth.add_auth", side_effect=self.sign_request
            ),
            # http approach patches - for new driver tests
            mock.patch(
                "snowflake.connector.wif_util.get_aws_region",
                side_effect=self.get_region,
            ),
            mock.patch(
                "snowflake.connector.wif_util.get_aws_credentials",
                side_effect=self.get_aws_credentials,
            ),
            mock.patch(
                "snowflake.connector.wif_util.get_aws_arn",
                side_effect=self.get_arn,
                create=True,
            ),
            # never contact IMDS for token
            mock.patch(
                "snowflake.connector.wif_util._imds_v2_token", return_value=None
            ),
        ]

        for patcher in self.patchers:
            patcher.__enter__()
        return self

    def __exit__(self, *args, **kwargs):
        for patcher in self.patchers:
            patcher.__exit__(*args, **kwargs)

        # restore previous env
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
