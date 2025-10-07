#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

# Please note that not all the unit tests from test/unit/test_ocsp.py is ported to this file,
# as those un-ported test cases are irrelevant to the asyncio implementation.

from __future__ import annotations

import asyncio
import functools
import os
import platform
import ssl
import time
from contextlib import asynccontextmanager
from os import environ, path
from unittest import mock

import aiohttp
import aiohttp.client_proto
import pytest

import snowflake.connector.ocsp_snowflake
from snowflake.connector.aio._ocsp_asn1crypto import SnowflakeOCSPAsn1Crypto as SFOCSP
from snowflake.connector.aio._ocsp_snowflake import OCSPCache, SnowflakeOCSP
from snowflake.connector.aio._session_manager import AioHttpConfig, SessionManager
from snowflake.connector.constants import OCSPMode
from snowflake.connector.errors import RevocationCheckError
from snowflake.connector.util_text import random_string

# Enforce worker_specific_cache_dir fixture
from ..test_ocsp import worker_specific_cache_dir  # noqa: F401

pytestmark = pytest.mark.asyncio

try:
    from snowflake.connector.cache import SFDictFileCache
    from snowflake.connector.errorcode import (
        ER_OCSP_RESPONSE_CERT_STATUS_REVOKED,
        ER_OCSP_RESPONSE_FETCH_FAILURE,
    )
    from snowflake.connector.ocsp_snowflake import OCSP_CACHE

    @pytest.fixture(autouse=True)
    def overwrite_ocsp_cache(tmpdir):
        """This fixture swaps out the actual OCSP cache for a temprary one."""
        if OCSP_CACHE is not None:
            tmp_cache_file = os.path.join(tmpdir, "tmp_cache")
            with mock.patch(
                "snowflake.connector.ocsp_snowflake.OCSP_CACHE",
                SFDictFileCache(file_path=tmp_cache_file),
            ):
                yield
            os.unlink(tmp_cache_file)

except ImportError:
    ER_OCSP_RESPONSE_CERT_STATUS_REVOKED = None
    ER_OCSP_RESPONSE_FETCH_FAILURE = None
    OCSP_CACHE = None

TARGET_HOSTS = [
    "ocspssd.us-east-1.snowflakecomputing.com",
    "sqs.us-west-2.amazonaws.com",
    "sfcsupport.us-east-1.snowflakecomputing.com",
    "sfcsupport.eu-central-1.snowflakecomputing.com",
    "sfc-eng-regression.s3.amazonaws.com",
    "sfctest0.snowflakecomputing.com",
    "sfc-ds2-customer-stage.s3.amazonaws.com",
    "snowflake.okta.com",
    "sfcdev1.blob.core.windows.net",
    "sfc-aus-ds1-customer-stage.s3-ap-southeast-2.amazonaws.com",
]

THIS_DIR = path.dirname(path.realpath(__file__))


@asynccontextmanager
async def _asyncio_connect(url, timeout=5):
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_connection(
        functools.partial(aiohttp.client_proto.ResponseHandler, loop),
        host=url,
        port=443,
        ssl=ssl.create_default_context(),
        ssl_handshake_timeout=timeout,
    )
    yield protocol
    transport.close()


@pytest.fixture(autouse=True)
def random_ocsp_response_validation_cache():
    RANDOM_FILENAME_SUFFIX_LEN = 10
    file_path = {
        "linux": os.path.join(
            "~",
            ".cache",
            "snowflake",
            f"ocsp_response_validation_cache{random_string(RANDOM_FILENAME_SUFFIX_LEN)}",
        ),
        "darwin": os.path.join(
            "~",
            "Library",
            "Caches",
            "Snowflake",
            f"ocsp_response_validation_cache{random_string(RANDOM_FILENAME_SUFFIX_LEN)}",
        ),
        "windows": os.path.join(
            "~",
            "AppData",
            "Local",
            "Snowflake",
            "Caches",
            f"ocsp_response_validation_cache{random_string(RANDOM_FILENAME_SUFFIX_LEN)}",
        ),
    }
    yield SFDictFileCache(
        entry_lifetime=3600,
        file_path=file_path,
    )
    try:
        os.unlink(file_path[platform.system().lower()])
    except Exception:
        pass


@pytest.fixture
def http_config():
    """Fixture providing an AioHttpConfig with OCSP disabled to prevent circular validation.

    When OCSP validation code uses a SessionManager, that SessionManager creates connectors
    which should NOT try to validate OCSP again (infinite loop). So we disable OCSP checks
    for the HTTP client used by OCSP validation itself.
    """
    return AioHttpConfig(
        use_pooling=False,
        trust_env=True,
        snowflake_ocsp_mode=OCSPMode.DISABLE_OCSP_CHECKS,
    )


@pytest.fixture
async def session_manager(http_config):
    """Fixture providing a SessionManager instance for OCSP tests.

    Each test gets a cloned manager to ensure test isolation. The base manager
    is closed after all tests using it are complete.
    """
    base_manager = SessionManager(config=http_config)
    try:
        # Yield a clone for each test to ensure isolation
        yield base_manager.clone()
    finally:
        await base_manager.close()


async def test_ocsp(session_manager):
    """OCSP tests."""
    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP()
    for url in TARGET_HOSTS:
        async with _asyncio_connect(url, timeout=5) as connection:
            assert await ocsp.validate(
                url, connection, session_manager=session_manager
            ), f"Failed to validate: {url}"


async def test_ocsp_wo_cache_server(session_manager):
    """OCSP Tests with Cache Server Disabled."""
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(use_ocsp_cache_server=False)
    for url in TARGET_HOSTS:
        async with _asyncio_connect(url, timeout=5) as connection:
            assert await ocsp.validate(
                url, connection, session_manager=session_manager
            ), f"Failed to validate: {url}"


async def test_ocsp_wo_cache_file(session_manager):
    """OCSP tests without File cache.

    Notes:
        Use /etc as a readonly directory such that no cache file is used.
    """
    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    try:
        OCSPCache.del_cache_file()
    except FileNotFoundError:
        # File doesn't exist, which is fine for this test
        pass
    environ["SF_OCSP_RESPONSE_CACHE_DIR"] = "/etc"
    OCSPCache.reset_cache_dir()

    try:
        ocsp = SFOCSP()
        for url in TARGET_HOSTS:
            async with _asyncio_connect(url, timeout=5) as connection:
                assert await ocsp.validate(
                    url, connection, session_manager=session_manager
                ), f"Failed to validate: {url}"
    finally:
        del environ["SF_OCSP_RESPONSE_CACHE_DIR"]
        OCSPCache.reset_cache_dir()


async def test_ocsp_fail_open_w_single_endpoint(session_manager):
    SnowflakeOCSP.clear_cache()

    try:
        OCSPCache.del_cache_file()
    except FileNotFoundError:
        # File doesn't exist, which is fine for this test
        pass

    environ["SF_OCSP_TEST_MODE"] = "true"
    environ["SF_TEST_OCSP_URL"] = "http://httpbin.org/delay/10"
    environ["SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT"] = "5"

    ocsp = SFOCSP(use_ocsp_cache_server=False)

    try:
        async with _asyncio_connect("snowflake.okta.com") as connection:
            assert await ocsp.validate(
                "snowflake.okta.com", connection, session_manager=session_manager
            ), "Failed to validate: {}".format("snowflake.okta.com")
    finally:
        del environ["SF_OCSP_TEST_MODE"]
        del environ["SF_TEST_OCSP_URL"]
        del environ["SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT"]


@pytest.mark.skipif(
    ER_OCSP_RESPONSE_CERT_STATUS_REVOKED is None,
    reason="No ER_OCSP_RESPONSE_CERT_STATUS_REVOKED is available.",
)
async def test_ocsp_fail_close_w_single_endpoint(session_manager):
    SnowflakeOCSP.clear_cache()

    environ["SF_OCSP_TEST_MODE"] = "true"
    environ["SF_TEST_OCSP_URL"] = "http://httpbin.org/delay/10"
    environ["SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT"] = "5"

    OCSPCache.del_cache_file()

    ocsp = SFOCSP(use_ocsp_cache_server=False, use_fail_open=False)

    with pytest.raises(RevocationCheckError) as ex:
        async with _asyncio_connect("snowflake.okta.com") as connection:
            await ocsp.validate(
                "snowflake.okta.com", connection, session_manager=session_manager
            )

    try:
        assert (
            ex.value.errno == ER_OCSP_RESPONSE_FETCH_FAILURE
        ), "Connection should have failed"
    finally:
        del environ["SF_OCSP_TEST_MODE"]
        del environ["SF_TEST_OCSP_URL"]
        del environ["SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT"]


async def test_ocsp_bad_validity(session_manager):
    SnowflakeOCSP.clear_cache()

    environ["SF_OCSP_TEST_MODE"] = "true"
    environ["SF_TEST_OCSP_FORCE_BAD_RESPONSE_VALIDITY"] = "true"

    try:
        OCSPCache.del_cache_file()
    except FileNotFoundError:
        # File doesn't exist, which is fine for this test
        pass

    ocsp = SFOCSP(use_ocsp_cache_server=False)
    async with _asyncio_connect("snowflake.okta.com") as connection:

        assert await ocsp.validate(
            "snowflake.okta.com", connection, session_manager=session_manager
        ), "Connection should have passed with fail open"
    del environ["SF_OCSP_TEST_MODE"]
    del environ["SF_TEST_OCSP_FORCE_BAD_RESPONSE_VALIDITY"]


async def test_ocsp_single_endpoint(session_manager):
    environ["SF_OCSP_ACTIVATE_NEW_ENDPOINT"] = "True"
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP()
    ocsp.OCSP_CACHE_SERVER.NEW_DEFAULT_CACHE_SERVER_BASE_URL = "https://snowflake.preprod3.us-west-2-dev.external-zone.snowflakecomputing.com:8085/ocsp/"
    async with _asyncio_connect("snowflake.okta.com") as connection:
        assert await ocsp.validate(
            "snowflake.okta.com", connection, session_manager=session_manager
        ), "Failed to validate: {}".format("snowflake.okta.com")

    del environ["SF_OCSP_ACTIVATE_NEW_ENDPOINT"]


async def test_ocsp_by_post_method(session_manager):
    """OCSP tests."""
    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(use_post_method=True)
    for url in TARGET_HOSTS:
        async with _asyncio_connect("snowflake.okta.com") as connection:
            assert await ocsp.validate(
                url, connection, session_manager=session_manager
            ), f"Failed to validate: {url}"


async def test_ocsp_with_file_cache(tmpdir, session_manager):
    """OCSP tests and the cache server and file."""
    tmp_dir = str(tmpdir.mkdir("ocsp_response_cache"))
    cache_file_name = path.join(tmp_dir, "cache_file.txt")

    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(ocsp_response_cache_uri="file://" + cache_file_name)
    for url in TARGET_HOSTS:
        async with _asyncio_connect("snowflake.okta.com") as connection:
            assert await ocsp.validate(
                url, connection, session_manager=session_manager
            ), f"Failed to validate: {url}"


async def test_ocsp_with_bogus_cache_files(
    tmpdir, random_ocsp_response_validation_cache, session_manager
):
    with mock.patch(
        "snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE",
        random_ocsp_response_validation_cache,
    ):
        from snowflake.connector.ocsp_snowflake import OCSPResponseValidationResult

        """Attempts to use bogus OCSP response data."""
        cache_file_name, target_hosts = await _store_cache_in_file(
            tmpdir, session_manager
        )

        ocsp = SFOCSP()
        OCSPCache.read_ocsp_response_cache_file(ocsp, cache_file_name)
        cache_data = snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE
        assert cache_data, "more than one cache entries should be stored."

        # setting bogus data
        current_time = int(time.time())
        for k, _ in cache_data.items():
            cache_data[k] = OCSPResponseValidationResult(
                ocsp_response=b"bogus",
                ts=current_time,
                validated=True,
            )

        # write back the cache file
        OCSPCache.CACHE = cache_data
        OCSPCache.write_ocsp_response_cache_file(ocsp, cache_file_name)

        # forces to use the bogus cache file but it should raise errors
        SnowflakeOCSP.clear_cache()
        ocsp = SFOCSP()
        for hostname in target_hosts:
            async with _asyncio_connect("snowflake.okta.com") as connection:
                assert await ocsp.validate(
                    hostname, connection, session_manager=session_manager
                ), f"Failed to validate: {hostname}"


async def test_ocsp_with_outdated_cache(
    tmpdir, random_ocsp_response_validation_cache, session_manager
):
    with mock.patch(
        "snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE",
        random_ocsp_response_validation_cache,
    ):
        from snowflake.connector.ocsp_snowflake import OCSPResponseValidationResult

        """Attempts to use outdated OCSP response cache file."""
        cache_file_name, target_hosts = await _store_cache_in_file(
            tmpdir, session_manager
        )

        ocsp = SFOCSP()

        # reading cache file
        OCSPCache.read_ocsp_response_cache_file(ocsp, cache_file_name)
        cache_data = snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE
        assert cache_data, "more than one cache entries should be stored."

        # setting outdated data
        current_time = int(time.time())
        for k, v in cache_data.items():
            cache_data[k] = OCSPResponseValidationResult(
                ocsp_response=v.ocsp_response,
                ts=current_time - 144 * 60 * 60,
                validated=True,
            )

        # write back the cache file
        OCSPCache.CACHE = cache_data
        OCSPCache.write_ocsp_response_cache_file(ocsp, cache_file_name)

        # forces to use the bogus cache file but it should raise errors
        SnowflakeOCSP.clear_cache()  # reset the memory cache
        SFOCSP()
        assert (
            SnowflakeOCSP.cache_size() == 0
        ), "must be empty. outdated cache should not be loaded"


async def _store_cache_in_file(tmpdir, session_manager, target_hosts=None):
    if target_hosts is None:
        target_hosts = TARGET_HOSTS
    os.environ["SF_OCSP_RESPONSE_CACHE_DIR"] = str(tmpdir)
    OCSPCache.reset_cache_dir()
    filename = path.join(str(tmpdir), "ocsp_response_cache.json")

    # cache OCSP response
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(
        ocsp_response_cache_uri="file://" + filename, use_ocsp_cache_server=False
    )
    for hostname in target_hosts:
        async with _asyncio_connect("snowflake.okta.com") as connection:
            assert await ocsp.validate(
                hostname, connection, session_manager=session_manager
            ), f"Failed to validate: {hostname}"
    assert path.exists(filename), "OCSP response cache file"
    return filename, target_hosts


async def test_ocsp_with_invalid_cache_file(session_manager):
    """OCSP tests with an invalid cache file."""
    SnowflakeOCSP.clear_cache()  # reset the memory cache
    ocsp = SFOCSP(ocsp_response_cache_uri="NEVER_EXISTS")
    for url in TARGET_HOSTS[0:1]:
        async with _asyncio_connect(url) as connection:
            assert await ocsp.validate(
                url, connection, session_manager=session_manager
            ), f"Failed to validate: {url}"


async def test_ocsp_cache_when_server_is_down(tmpdir, session_manager):
    """Test that OCSP validation handles server failures gracefully."""
    # Create a completely isolated cache for this test
    from snowflake.connector.cache import SFDictFileCache

    isolated_cache = SFDictFileCache(
        entry_lifetime=3600,
        file_path=str(tmpdir.join("isolated_ocsp_cache.json")),
    )

    with mock.patch(
        "snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE",
        isolated_cache,
    ):
        # Ensure cache starts empty
        isolated_cache.clear()

        # Simulate server being down when trying to validate certificates
        with mock.patch(
            "snowflake.connector.aio._ocsp_snowflake.SnowflakeOCSP._fetch_ocsp_response",
            new_callable=mock.AsyncMock,
            side_effect=BrokenPipeError("fake error"),
        ), mock.patch(
            "snowflake.connector.aio._ocsp_snowflake.SnowflakeOCSP.is_cert_id_in_cache",
            return_value=(
                False,
                None,
            ),  # Force cache miss to trigger _fetch_ocsp_response
        ):
            ocsp = SFOCSP(use_ocsp_cache_server=False, use_fail_open=True)

            # The main test: validation should succeed with fail-open behavior
            # even when server is down (BrokenPipeError)
            async with _asyncio_connect("snowflake.okta.com") as connection:
                result = await ocsp.validate(
                    "snowflake.okta.com", connection, session_manager=session_manager
                )

            # With fail-open enabled, validation should succeed despite server being down
            # The result should not be None (which would indicate complete failure)
            assert (
                result is not None
            ), "OCSP validation should succeed with fail-open when server is down"


async def test_concurrent_ocsp_requests(tmpdir, session_manager):
    """Run OCSP revocation checks in parallel. The memory and file caches are deleted randomly."""
    cache_file_name = path.join(str(tmpdir), "cache_file.txt")
    SnowflakeOCSP.clear_cache()  # reset the memory cache
    SFOCSP(ocsp_response_cache_uri="file://" + cache_file_name)

    target_hosts = TARGET_HOSTS * 5
    await asyncio.gather(
        *[
            _validate_certs_using_ocsp(hostname, cache_file_name, session_manager)
            for hostname in target_hosts
        ]
    )


async def _validate_certs_using_ocsp(url, cache_file_name, session_manager):
    """Validate OCSP response. Deleting memory cache and file cache randomly."""
    import logging

    logger = logging.getLogger("test")

    logging.basicConfig(level=logging.DEBUG)
    import random

    await asyncio.sleep(random.randint(0, 3))
    if random.random() < 0.2:
        logger.info("clearing up cache: OCSP_VALIDATION_CACHE")
        SnowflakeOCSP.clear_cache()
    if random.random() < 0.05:
        logger.info("deleting a cache file: %s", cache_file_name)
        try:
            # delete cache file can file because other coroutine is reading the file
            # here we just randomly delete the file such passing OSError achieves the same effect
            SnowflakeOCSP.delete_cache_file()
        except OSError:
            pass

    async with _asyncio_connect(url) as connection:
        ocsp = SFOCSP(ocsp_response_cache_uri="file://" + cache_file_name)
        await ocsp.validate(url, connection, session_manager=session_manager)
