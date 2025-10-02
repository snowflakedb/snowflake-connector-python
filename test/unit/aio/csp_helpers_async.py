#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import logging
import os
from unittest import mock
from urllib.parse import urlparse

from snowflake.connector.vendored.requests.exceptions import ConnectTimeout, HTTPError

logger = logging.getLogger(__name__)


# Import shared functions
from ...csp_helpers import (
    FakeAwsEnvironment,
    FakeAzureFunctionMetadataService,
    FakeAzureVmMetadataService,
    FakeGceMetadataService,
    FakeMetadataService,
    UnavailableMetadataService,
)


def build_response(content: bytes, status_code: int = 200):
    """Builds an aiohttp-compatible response object with the given status code and content."""

    class AsyncResponse:
        def __init__(self, content, status_code):
            self.ok = status_code < 400
            self.status = status_code
            self._content = content

        async def read(self):
            return self._content

    return AsyncResponse(content, status_code)


class FakeMetadataServiceAsync(FakeMetadataService):
    def _async_request(self, method, url, headers=None, timeout=None):
        """Entry point for the aiohttp mock."""
        logger.debug(f"Received async request: {method} {url} {str(headers)}")
        parsed_url = urlparse(url)

        # Create async context manager for aiohttp response
        class AsyncResponseContextManager:
            def __init__(self, response):
                self.response = response

            async def __aenter__(self):
                return self.response

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

        # Create aiohttp-compatible response mock
        class AsyncResponse:
            def __init__(self, requests_response):
                self.ok = requests_response.ok
                self.status = requests_response.status_code
                self._content = requests_response.content

            async def read(self):
                return self._content

            async def text(self):
                return self._content.decode("utf-8")

            async def json(self):
                import json

                return json.loads(self._content.decode("utf-8"))

            def raise_for_status(self):
                if not self.ok:
                    import aiohttp

                    raise aiohttp.ClientResponseError(
                        request_info=None,
                        history=None,
                        status=self.status,
                        message=f"HTTP {self.status}",
                        headers={},
                    )

        if parsed_url.hostname not in self.expected_hostnames:
            logger.debug(
                f"Received async request to unexpected hostname {parsed_url.hostname}"
            )
            import aiohttp

            raise aiohttp.ClientError()

        # Get the response from the subclass handler, catch exceptions and convert them
        try:
            sync_response = self.handle_request(method, parsed_url, headers, timeout)
            async_response = AsyncResponse(sync_response)
            return AsyncResponseContextManager(async_response)
        except (HTTPError, ConnectTimeout) as e:
            import aiohttp

            # Convert requests exceptions to aiohttp exceptions so they get caught properly
            raise aiohttp.ClientError() from e

    def _async_get(self, url, headers=None, timeout=None, **kwargs):
        """Entry point for the aiohttp get mock."""
        return self._async_request("GET", url, headers=headers, timeout=timeout)

    def __enter__(self):
        self.reset_defaults()
        self.patchers = []
        # Mock aiohttp for async requests
        self.patchers.append(
            mock.patch("aiohttp.ClientSession.request", side_effect=self._async_request)
        )
        self.patchers.append(
            mock.patch("aiohttp.ClientSession.get", side_effect=self._async_get)
        )
        for patcher in self.patchers:
            patcher.__enter__()
        return self


class UnavailableMetadataServiceAsync(
    FakeMetadataServiceAsync, UnavailableMetadataService
):
    pass


class FakeAzureVmMetadataServiceAsync(
    FakeMetadataServiceAsync, FakeAzureVmMetadataService
):
    pass


class FakeAzureFunctionMetadataServiceAsync(
    FakeMetadataServiceAsync, FakeAzureFunctionMetadataService
):
    def __enter__(self):
        # Set environment variables first (like Azure Function service)
        os.environ["IDENTITY_ENDPOINT"] = self.identity_endpoint
        os.environ["IDENTITY_HEADER"] = self.identity_header

        # Then set up the metadata service mocks
        FakeMetadataServiceAsync.__enter__(self)
        return self

    def __exit__(self, *args, **kwargs):
        # Clean up async mocks first
        FakeMetadataServiceAsync.__exit__(self, *args, **kwargs)

        # Then clean up environment variables
        os.environ.pop("IDENTITY_ENDPOINT", None)
        os.environ.pop("IDENTITY_HEADER", None)


class FakeGceMetadataServiceAsync(FakeMetadataServiceAsync, FakeGceMetadataService):
    pass


class FakeAwsEnvironmentAsync(FakeAwsEnvironment):
    """Emulates the AWS environment-specific functions used in async wif_util.py.

    Unlike the other metadata services, the HTTP calls made by AWS are deep within boto libaries, so
    emulating them here would be complex and fragile. Instead, we emulate the higher-level functions
    called by the connector code.
    """

    async def get_region(self):
        return self.region

    async def get_credentials(self):
        return self.credentials

    def __enter__(self):
        # First call the parent's __enter__ to get base functionality
        super().__enter__()

        # Then add async-specific patches
        async def async_get_credentials():
            return self.credentials

        async def async_get_caller_identity():
            return {"Arn": self.arn}

        async def async_get_region():
            return await self.get_region()

        async def async_get_arn():
            return await self.get_arn()

        # Mock aioboto3.Session.get_credentials (IS async)
        self.patchers.append(
            mock.patch(
                "snowflake.connector.aio._wif_util.aioboto3.Session.get_credentials",
                side_effect=async_get_credentials,
            )
        )

        # Mock the async AWS region and ARN functions
        self.patchers.append(
            mock.patch(
                "snowflake.connector.aio._wif_util.get_aws_region",
                side_effect=async_get_region,
            )
        )

        # Mock the async STS client for direct aioboto3 usage
        class MockStsClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass

            async def get_caller_identity(self):
                return await async_get_caller_identity()

        def mock_session_client(service_name):
            if service_name == "sts":
                return MockStsClient()
            return None

        self.patchers.append(
            mock.patch(
                "snowflake.connector.aio._wif_util.aioboto3.Session.client",
                side_effect=mock_session_client,
            )
        )

        # Start the additional async patches
        for patcher in self.patchers[-4:]:  # Only start the new patches we just added
            patcher.__enter__()
        return self

    def __exit__(self, *args, **kwargs):
        # Call parent's exit to clean up base patches
        super().__exit__(*args, **kwargs)
