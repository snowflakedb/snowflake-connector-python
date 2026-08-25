#!/usr/bin/env python
from __future__ import annotations

import copy
import datetime
import io
import json
import logging
import os
import platform
import time
from concurrent.futures.thread import ThreadPoolExecutor
from os import path
from unittest import mock

import asn1crypto.x509
from asn1crypto import ocsp
from asn1crypto import x509 as asn1crypto509
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

try:
    from snowflake.connector.util_text import random_string
except ImportError:
    from ..randomize import random_string

import pytest

import snowflake.connector.ocsp_snowflake
from snowflake.connector import OperationalError
from snowflake.connector.errors import RevocationCheckError
from snowflake.connector.ocsp_asn1crypto import SnowflakeOCSPAsn1Crypto as SFOCSP
from snowflake.connector.ocsp_snowflake import OCSPCache, OCSPServer, SnowflakeOCSP
from snowflake.connector.ssl_wrap_socket import _openssl_connect

try:
    from snowflake.connector.cache import SFDictFileCache
    from snowflake.connector.errorcode import (
        ER_OCSP_RESPONSE_CERT_ID_MISMATCH,
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
    ER_OCSP_RESPONSE_CERT_ID_MISMATCH = None
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


@pytest.fixture(autouse=True)
def worker_specific_cache_dir(tmpdir, request, monkeypatch):
    """Create worker-specific cache directory to avoid file lock conflicts in parallel execution.

    Note: Tests that explicitly manage their own cache directories (like test_ocsp_cache_when_server_is_down)
    should work normally - this fixture only provides isolation for the validation cache.
    """

    # Get worker ID for parallel execution (pytest-xdist)
    worker_id = os.environ.get("PYTEST_XDIST_WORKER", "master")

    # monkeypatch will automatically handle restoration

    # Set worker-specific cache directory to prevent main cache file conflicts
    worker_cache_dir = tmpdir.join(f"ocsp_cache_{worker_id}")
    worker_cache_dir.ensure(dir=True)
    monkeypatch.setenv("SF_OCSP_RESPONSE_CACHE_DIR", str(worker_cache_dir))

    # Only handle the OCSP_RESPONSE_VALIDATION_CACHE to prevent conflicts
    # Let tests manage SF_OCSP_RESPONSE_CACHE_DIR themselves if they need to
    try:
        import snowflake.connector.ocsp_snowflake as ocsp_module
        from snowflake.connector.cache import SFDictFileCache

        # Reset cache dir to pick up the new environment variable
        ocsp_module.OCSPCache.reset_cache_dir()

        # Create worker-specific validation cache file
        validation_cache_file = tmpdir.join(f"ocsp_validation_cache_{worker_id}.json")

        # Create new cache instance for this worker
        worker_validation_cache = SFDictFileCache(
            file_path=str(validation_cache_file), entry_lifetime=3600
        )

        # Store original cache to restore later
        original_validation_cache = getattr(
            ocsp_module, "OCSP_RESPONSE_VALIDATION_CACHE", None
        )

        # Replace with worker-specific cache
        ocsp_module.OCSP_RESPONSE_VALIDATION_CACHE = worker_validation_cache

        yield str(tmpdir)

        # Restore original validation cache
        if original_validation_cache is not None:
            ocsp_module.OCSP_RESPONSE_VALIDATION_CACHE = original_validation_cache

    except ImportError:
        # If modules not available, just yield the directory
        yield str(tmpdir)
    finally:
        # monkeypatch will automatically restore the original environment variable

        # Reset cache dir back to original state
        try:
            import snowflake.connector.ocsp_snowflake as ocsp_module

            ocsp_module.OCSPCache.reset_cache_dir()
        except ImportError:
            pass


def create_x509_cert(hash_algorithm):
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=1024, backend=default_backend()
    )

    # Generate a public key
    public_key = private_key.public_key()

    # Create a certificate
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
        ]
    )

    issuer = subject

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now())
        .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        )
        .sign(private_key, hash_algorithm, default_backend())
    )


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


def test_ocsp():
    """OCSP tests."""
    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP()
    for url in TARGET_HOSTS:
        connection = _openssl_connect(url, timeout=5)
        assert ocsp.validate(url, connection), f"Failed to validate: {url}"


def test_ocsp_wo_cache_server():
    """OCSP Tests with Cache Server Disabled."""
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(use_ocsp_cache_server=False)
    for url in TARGET_HOSTS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), f"Failed to validate: {url}"


def test_ocsp_wo_cache_file(monkeypatch):
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
    monkeypatch.setenv("SF_OCSP_RESPONSE_CACHE_DIR", "/etc")
    OCSPCache.reset_cache_dir()

    try:
        ocsp = SFOCSP()
        for url in TARGET_HOSTS:
            connection = _openssl_connect(url)
            assert ocsp.validate(url, connection), f"Failed to validate: {url}"
    finally:
        OCSPCache.reset_cache_dir()


def test_ocsp_fail_open_w_single_endpoint(monkeypatch):
    SnowflakeOCSP.clear_cache()

    try:
        OCSPCache.del_cache_file()
    except FileNotFoundError:
        # File doesn't exist, which is fine for this test
        pass

    monkeypatch.setenv("SF_OCSP_TEST_MODE", "true")
    monkeypatch.setenv("SF_TEST_OCSP_URL", "http://httpbin.org/delay/10")
    monkeypatch.setenv("SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT", "5")

    ocsp = SFOCSP(use_ocsp_cache_server=False)
    connection = _openssl_connect("snowflake.okta.com")

    assert ocsp.validate(
        "snowflake.okta.com", connection
    ), "Failed to validate: {}".format("snowflake.okta.com")


@pytest.mark.skipif(
    ER_OCSP_RESPONSE_CERT_STATUS_REVOKED is None,
    reason="No ER_OCSP_RESPONSE_CERT_STATUS_REVOKED is available.",
)
def test_ocsp_fail_close_w_single_endpoint(monkeypatch):
    SnowflakeOCSP.clear_cache()

    monkeypatch.setenv("SF_OCSP_TEST_MODE", "true")
    monkeypatch.setenv("SF_TEST_OCSP_URL", "http://httpbin.org/delay/10")
    monkeypatch.setenv("SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT", "5")

    OCSPCache.del_cache_file()

    ocsp = SFOCSP(use_ocsp_cache_server=False, use_fail_open=False)
    connection = _openssl_connect("snowflake.okta.com")

    with pytest.raises(RevocationCheckError) as ex:
        ocsp.validate("snowflake.okta.com", connection)

    assert (
        ex.value.errno == ER_OCSP_RESPONSE_FETCH_FAILURE
    ), "Connection should have failed"


def test_ocsp_bad_validity(monkeypatch):
    SnowflakeOCSP.clear_cache()

    monkeypatch.setenv("SF_OCSP_TEST_MODE", "true")
    monkeypatch.setenv("SF_TEST_OCSP_FORCE_BAD_RESPONSE_VALIDITY", "true")

    try:
        OCSPCache.del_cache_file()
    except FileNotFoundError:
        # File doesn't exist, which is fine for this test
        pass

    ocsp = SFOCSP(use_ocsp_cache_server=False)
    connection = _openssl_connect("snowflake.okta.com")

    assert ocsp.validate(
        "snowflake.okta.com", connection
    ), "Connection should have passed with fail open"


def test_ocsp_single_endpoint(monkeypatch):
    monkeypatch.setenv("SF_OCSP_ACTIVATE_NEW_ENDPOINT", "True")
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP()
    ocsp.OCSP_CACHE_SERVER.NEW_DEFAULT_CACHE_SERVER_BASE_URL = "https://snowflake.preprod3.us-west-2-dev.external-zone.snowflakecomputing.com:8085/ocsp/"
    connection = _openssl_connect("snowflake.okta.com")
    assert ocsp.validate(
        "snowflake.okta.com", connection
    ), "Failed to validate: {}".format("snowflake.okta.com")


def test_ocsp_by_post_method():
    """OCSP tests."""
    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(use_post_method=True)
    for url in TARGET_HOSTS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), f"Failed to validate: {url}"


def test_ocsp_with_file_cache(tmpdir):
    """OCSP tests and the cache server and file."""
    tmp_dir = str(tmpdir.mkdir("ocsp_response_cache"))
    cache_file_name = path.join(tmp_dir, "cache_file.txt")

    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(ocsp_response_cache_uri="file://" + cache_file_name)
    for url in TARGET_HOSTS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), f"Failed to validate: {url}"


@pytest.mark.skipolddriver
def test_ocsp_with_bogus_cache_files(
    tmpdir, random_ocsp_response_validation_cache, monkeypatch
):
    with mock.patch(
        "snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE",
        random_ocsp_response_validation_cache,
    ):
        from snowflake.connector.ocsp_snowflake import OCSPResponseValidationResult

        """Attempts to use bogus OCSP response data."""
        cache_file_name, target_hosts = _store_cache_in_file(monkeypatch, tmpdir)

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
            connection = _openssl_connect(hostname)
            assert ocsp.validate(hostname, connection), "Failed to validate: {}".format(
                hostname
            )


@pytest.mark.skipolddriver
def test_ocsp_with_outdated_cache(
    tmpdir, random_ocsp_response_validation_cache, monkeypatch
):
    with mock.patch(
        "snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE",
        random_ocsp_response_validation_cache,
    ):
        from snowflake.connector.ocsp_snowflake import OCSPResponseValidationResult

        """Attempts to use outdated OCSP response cache file."""
        cache_file_name, target_hosts = _store_cache_in_file(monkeypatch, tmpdir)

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


def _store_cache_in_file(monkeypatch, tmpdir):
    monkeypatch.setenv("SF_OCSP_RESPONSE_CACHE_DIR", str(tmpdir))
    OCSPCache.reset_cache_dir()
    filename = path.join(str(tmpdir), "ocsp_response_cache.json")

    # cache OCSP response
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(
        ocsp_response_cache_uri="file://" + filename, use_ocsp_cache_server=False
    )
    for hostname in TARGET_HOSTS:
        connection = _openssl_connect(hostname)
        assert ocsp.validate(hostname, connection), "Failed to validate: {}".format(
            hostname
        )
    assert path.exists(filename), "OCSP response cache file"
    return filename, TARGET_HOSTS


def test_ocsp_with_invalid_cache_file():
    """OCSP tests with an invalid cache file."""
    SnowflakeOCSP.clear_cache()  # reset the memory cache
    ocsp = SFOCSP(ocsp_response_cache_uri="NEVER_EXISTS")
    for url in TARGET_HOSTS[0:1]:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), f"Failed to validate: {url}"


def test_ocsp_cache_when_server_is_down(tmpdir):
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
            "snowflake.connector.ocsp_snowflake.SnowflakeOCSP._fetch_ocsp_response",
            side_effect=BrokenPipeError("fake error"),
        ), mock.patch(
            "snowflake.connector.ocsp_snowflake.SnowflakeOCSP.is_cert_id_in_cache",
            return_value=(
                False,
                None,
            ),  # Force cache miss to trigger _fetch_ocsp_response
        ):
            ocsp = SFOCSP(use_ocsp_cache_server=False, use_fail_open=True)

            # The main test: validation should succeed with fail-open behavior
            # even when server is down (BrokenPipeError)
            connection = _openssl_connect("snowflake.okta.com")
            result = ocsp.validate("snowflake.okta.com", connection)

            # With fail-open enabled, validation should succeed despite server being down
            # The result should not be None (which would indicate complete failure)
            assert (
                result is not None
            ), "OCSP validation should succeed with fail-open when server is down"


def test_concurrent_ocsp_requests(tmpdir):
    """Run OCSP revocation checks in parallel. The memory and file caches are deleted randomly."""
    cache_file_name = path.join(str(tmpdir), "cache_file.txt")
    SnowflakeOCSP.clear_cache()  # reset the memory cache

    target_hosts = TARGET_HOSTS * 5
    pool = ThreadPoolExecutor(len(target_hosts))
    for hostname in target_hosts:
        pool.submit(_validate_certs_using_ocsp, hostname, cache_file_name)
    pool.shutdown()


def _validate_certs_using_ocsp(url, cache_file_name):
    """Validate OCSP response. Deleting memory cache and file cache randomly."""
    logger = logging.getLogger("test")
    import random
    import time

    time.sleep(random.randint(0, 3))
    if random.random() < 0.2:
        logger.info("clearing up cache: OCSP_VALIDATION_CACHE")
        SnowflakeOCSP.clear_cache()
    if random.random() < 0.05:
        logger.info("deleting a cache file: %s", cache_file_name)
        SnowflakeOCSP.delete_cache_file()

    connection = _openssl_connect(url)
    ocsp = SFOCSP(ocsp_response_cache_uri="file://" + cache_file_name)
    ocsp.validate(url, connection)


@pytest.mark.skip(reason="certificate expired.")
def test_ocsp_revoked_certificate():
    """Tests revoked certificate."""
    revoked_cert = path.join(THIS_DIR, "../data", "cert_tests", "revoked_certs.pem")

    SnowflakeOCSP.clear_cache()  # reset the memory cache
    ocsp = SFOCSP()

    with pytest.raises(OperationalError) as ex:
        ocsp.validate_certfile(revoked_cert)
    assert ex.value.errno == ex.value.errno == ER_OCSP_RESPONSE_CERT_STATUS_REVOKED


def test_ocsp_incomplete_chain():
    """Tests incomplete chained certificate."""
    incomplete_chain_cert = path.join(
        THIS_DIR, "../data", "cert_tests", "incomplete-chain.pem"
    )

    SnowflakeOCSP.clear_cache()  # reset the memory cache
    ocsp = SFOCSP()

    with pytest.raises(OperationalError) as ex:
        ocsp.validate_certfile(incomplete_chain_cert)
    assert "CA certificate is NOT found" in ex.value.msg


def test_building_retry_url():
    # privatelink retry url
    OCSP_SERVER = OCSPServer()
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = (
        "http://ocsp.us-east-1.snowflakecomputing.com/ocsp_response_cache.json"
    )
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert (
        OCSP_SERVER.OCSP_RETRY_URL
        == "http://ocsp.us-east-1.snowflakecomputing.com/retry/{0}/{1}"
    )

    assert (
        OCSP_SERVER.generate_get_url("http://oneocsp.microsoft.com", "1234")
        == "http://ocsp.us-east-1.snowflakecomputing.com/retry/oneocsp.microsoft.com/1234"
    )
    assert (
        OCSP_SERVER.generate_get_url("http://oneocsp.microsoft.com/", "1234")
        == "http://ocsp.us-east-1.snowflakecomputing.com/retry/oneocsp.microsoft.com/1234"
    )
    assert (
        OCSP_SERVER.generate_get_url("http://oneocsp.microsoft.com/ocsp", "1234")
        == "http://ocsp.us-east-1.snowflakecomputing.com/retry/oneocsp.microsoft.com/ocsp/1234"
    )

    # ensure we also handle port
    assert (
        OCSP_SERVER.generate_get_url("http://oneocsp.microsoft.com:8080", "1234")
        == "http://ocsp.us-east-1.snowflakecomputing.com/retry/oneocsp.microsoft.com:8080/1234"
    )
    assert (
        OCSP_SERVER.generate_get_url("http://oneocsp.microsoft.com:8080/", "1234")
        == "http://ocsp.us-east-1.snowflakecomputing.com/retry/oneocsp.microsoft.com:8080/1234"
    )
    assert (
        OCSP_SERVER.generate_get_url("http://oneocsp.microsoft.com:8080/ocsp", "1234")
        == "http://ocsp.us-east-1.snowflakecomputing.com/retry/oneocsp.microsoft.com:8080/ocsp/1234"
    )

    # ensure we handle slash correctly
    assert (
        OCSP_SERVER.generate_get_url(
            "http://oneocsp.microsoft.com:8080/ocsp", "aa//bb/"
        )
        == "http://ocsp.us-east-1.snowflakecomputing.com/retry/oneocsp.microsoft.com:8080/ocsp/aa%2F%2Fbb%2F"
    )

    # privatelink retry url with port
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = (
        "http://ocsp.us-east-1.snowflakecomputing.com:80/ocsp_response_cache" ".json"
    )
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert (
        OCSP_SERVER.OCSP_RETRY_URL
        == "http://ocsp.us-east-1.snowflakecomputing.com:80/retry/{0}/{1}"
    )

    # non-privatelink retry url
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = (
        "http://ocsp.snowflakecomputing.com/ocsp_response_cache.json"
    )
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert OCSP_SERVER.OCSP_RETRY_URL is None

    # non-privatelink retry url with port
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = (
        "http://ocsp.snowflakecomputing.com:80/ocsp_response_cache.json"
    )
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert OCSP_SERVER.OCSP_RETRY_URL is None


def test_building_new_retry(monkeypatch):
    OCSP_SERVER = OCSPServer()
    OCSP_SERVER.OCSP_RETRY_URL = None
    hname = "a1.us-east-1.snowflakecomputing.com"
    monkeypatch.setenv("SF_OCSP_ACTIVATE_NEW_ENDPOINT", "true")
    OCSP_SERVER.reset_ocsp_endpoint(hname)
    assert (
        OCSP_SERVER.CACHE_SERVER_URL
        == "https://ocspssd.us-east-1.snowflakecomputing.com/ocsp/fetch"
    )

    assert (
        OCSP_SERVER.OCSP_RETRY_URL
        == "https://ocspssd.us-east-1.snowflakecomputing.com/ocsp/retry"
    )

    hname = "a1-12345.global.snowflakecomputing.com"
    OCSP_SERVER.reset_ocsp_endpoint(hname)
    assert (
        OCSP_SERVER.CACHE_SERVER_URL
        == "https://ocspssd-12345.global.snowflakecomputing.com/ocsp/fetch"
    )

    assert (
        OCSP_SERVER.OCSP_RETRY_URL
        == "https://ocspssd-12345.global.snowflakecomputing.com/ocsp/retry"
    )

    hname = "snowflake.okta.com"
    OCSP_SERVER.reset_ocsp_endpoint(hname)
    assert (
        OCSP_SERVER.CACHE_SERVER_URL
        == "https://ocspssd.snowflakecomputing.com/ocsp/fetch"
    )

    assert (
        OCSP_SERVER.OCSP_RETRY_URL
        == "https://ocspssd.snowflakecomputing.com/ocsp/retry"
    )


@pytest.mark.parametrize(
    "hash_algorithm",
    [
        hashes.SHA256(),
        hashes.SHA384(),
        hashes.SHA512(),
        hashes.SHA3_256(),
        hashes.SHA3_384(),
        hashes.SHA3_512(),
    ],
)
def test_signature_verification(hash_algorithm):
    cert = create_x509_cert(hash_algorithm)
    # in snowflake, we use lib asn1crypto to load certificate, not using lib cryptography
    asy1_509_cert = asn1crypto509.Certificate.load(cert.public_bytes(Encoding.DER))

    # sha3 family is not recognized by asn1crypto library
    if hash_algorithm.name.startswith("sha3-"):
        with pytest.raises(ValueError):
            SFOCSP().verify_signature(
                asy1_509_cert.hash_algo,
                cert.signature,
                asy1_509_cert,
                asy1_509_cert["tbs_certificate"],
            )
    else:
        SFOCSP().verify_signature(
            asy1_509_cert.hash_algo,
            cert.signature,
            asy1_509_cert,
            asy1_509_cert["tbs_certificate"],
        )


def test_ocsp_server_domain_name():
    default_ocsp_server = OCSPServer()
    assert (
        default_ocsp_server.DEFAULT_CACHE_SERVER_URL
        == "http://ocsp.snowflakecomputing.com"
        and default_ocsp_server.NEW_DEFAULT_CACHE_SERVER_BASE_URL
        == "https://ocspssd.snowflakecomputing.com/ocsp/"
        and default_ocsp_server.CACHE_SERVER_URL
        == f"{default_ocsp_server.DEFAULT_CACHE_SERVER_URL}/{OCSPCache.OCSP_RESPONSE_CACHE_FILE_NAME}"
    )

    default_ocsp_server.reset_ocsp_endpoint("test.snowflakecomputing.cn")
    assert (
        default_ocsp_server.CACHE_SERVER_URL
        == "https://ocspssd.snowflakecomputing.cn/ocsp/fetch"
        and default_ocsp_server.OCSP_RETRY_URL
        == "https://ocspssd.snowflakecomputing.cn/ocsp/retry"
    )

    default_ocsp_server.reset_ocsp_endpoint("test.privatelink.snowflakecomputing.cn")
    assert (
        default_ocsp_server.CACHE_SERVER_URL
        == "https://ocspssd.test.privatelink.snowflakecomputing.cn/ocsp/fetch"
        and default_ocsp_server.OCSP_RETRY_URL
        == "https://ocspssd.test.privatelink.snowflakecomputing.cn/ocsp/retry"
    )

    default_ocsp_server.reset_ocsp_endpoint("cn-12345.global.snowflakecomputing.cn")
    assert (
        default_ocsp_server.CACHE_SERVER_URL
        == "https://ocspssd-12345.global.snowflakecomputing.cn/ocsp/fetch"
        and default_ocsp_server.OCSP_RETRY_URL
        == "https://ocspssd-12345.global.snowflakecomputing.cn/ocsp/retry"
    )

    default_ocsp_server.reset_ocsp_endpoint("test.random.com")
    assert (
        default_ocsp_server.CACHE_SERVER_URL
        == "https://ocspssd.snowflakecomputing.com/ocsp/fetch"
        and default_ocsp_server.OCSP_RETRY_URL
        == "https://ocspssd.snowflakecomputing.com/ocsp/retry"
    )

    default_ocsp_server = OCSPServer(top_level_domain="cn")
    assert (
        default_ocsp_server.DEFAULT_CACHE_SERVER_URL
        == "http://ocsp.snowflakecomputing.cn"
        and default_ocsp_server.NEW_DEFAULT_CACHE_SERVER_BASE_URL
        == "https://ocspssd.snowflakecomputing.cn/ocsp/"
        and default_ocsp_server.CACHE_SERVER_URL
        == f"{default_ocsp_server.DEFAULT_CACHE_SERVER_URL}/{OCSPCache.OCSP_RESPONSE_CACHE_FILE_NAME}"
    )

    ocsp = SFOCSP(hostname="test.snowflakecomputing.cn")
    assert (
        ocsp.OCSP_CACHE_SERVER.DEFAULT_CACHE_SERVER_URL
        == "http://ocsp.snowflakecomputing.cn"
        and ocsp.OCSP_CACHE_SERVER.NEW_DEFAULT_CACHE_SERVER_BASE_URL
        == "https://ocspssd.snowflakecomputing.cn/ocsp/"
        and ocsp.OCSP_CACHE_SERVER.CACHE_SERVER_URL
        == f"{default_ocsp_server.DEFAULT_CACHE_SERVER_URL}/{OCSPCache.OCSP_RESPONSE_CACHE_FILE_NAME}"
    )


@pytest.mark.skipolddriver
def test_privatelink_ocsp_cache_url_is_per_connection(monkeypatch):
    """SNOW-3675581: a PrivateLink host's OCSP cache URL is derived from that
    connection's own hostname and stored on the per-connection OCSPServer,
    without touching the process-global SF_OCSP_RESPONSE_CACHE_SERVER_URL. Two
    connections with different hosts in the same process each keep their own
    cache URL and do not affect one another."""
    monkeypatch.delenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", raising=False)
    monkeypatch.delenv("SF_OCSP_ACTIVATE_NEW_ENDPOINT", raising=False)

    host_a = "accta.us-east-1.privatelink.snowflakecomputing.com"
    host_b = "acctb.us-west-2.privatelink.snowflakecomputing.com"

    ocsp_a = SFOCSP(hostname=host_a)
    ocsp_b = SFOCSP(hostname=host_b)

    assert (
        ocsp_a.OCSP_CACHE_SERVER.CACHE_SERVER_URL
        == f"http://ocsp.{host_a}/{OCSPCache.OCSP_RESPONSE_CACHE_FILE_NAME}"
    )
    assert (
        ocsp_b.OCSP_CACHE_SERVER.CACHE_SERVER_URL
        == f"http://ocsp.{host_b}/{OCSPCache.OCSP_RESPONSE_CACHE_FILE_NAME}"
    )
    # No process-global env var was written -> connections stay independent.
    assert "SF_OCSP_RESPONSE_CACHE_SERVER_URL" not in os.environ


@pytest.mark.skipolddriver
def test_operator_ocsp_cache_url_takes_precedence_over_privatelink(monkeypatch):
    """An operator-set SF_OCSP_RESPONSE_CACHE_SERVER_URL (trusted, process-wide)
    wins over the connector-derived PrivateLink URL."""
    monkeypatch.delenv("SF_OCSP_ACTIVATE_NEW_ENDPOINT", raising=False)
    monkeypatch.setenv(
        "SF_OCSP_RESPONSE_CACHE_SERVER_URL", "http://operator.example/cache.json"
    )
    ocsp = SFOCSP(hostname="acct.us-east-1.privatelink.snowflakecomputing.com")
    assert (
        ocsp.OCSP_CACHE_SERVER.CACHE_SERVER_URL == "http://operator.example/cache.json"
    )


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "host,is_privatelink",
    [
        ("acct.us-east-1.privatelink.snowflakecomputing.com", True),
        ("acct.privatelink.snowflakecomputing.cn", True),
        ("ACCT.PrivateLink.SnowflakeComputing.com", True),  # case-insensitive
        (
            "my_account.us-east-1.privatelink.snowflakecomputing.com",
            True,
        ),  # underscore in account
        ("my_acct.privatelink.snowflakecomputing.com", True),  # underscore only
        (
            "testacct.us-east-1.aws.privatelink.snowflakecomputing.com",
            True,
        ),  # multi-label regional prefix
        ("testacct.privatelink.snowflakecomputing.mil", True),  # alternate TLD
        ("acct.privatelink.snowflakecomputing.com.", True),  # FQDN trailing dot
        (
            "acct.privatelink.snowflakecomputing.com.:443",
            True,
        ),  # FQDN trailing dot + port
        ("  acct.privatelink.snowflakecomputing.com  ", True),  # surrounding whitespace
        # Hosts that merely contain the PrivateLink domain as a non-terminal label:
        ("acct.privatelink.snowflakecomputing.com.unrelated.example", False),
        ("acct.privatelink.snowflakecomputing.unrelated.example", False),
        ("privatelink.snowflakecomputing.com.unrelated.example", False),
        # Well-formed hosts whose apex is not a recognized Snowflake domain.
        ("evil.privatelink.totally-unrelated.example", False),
        # Characters a URL parser may treat as ending the authority. Each of these
        # carries a recognized Snowflake domain but resolves to something else, so
        # the character allow-list has to reject them rather than enumerate them.
        ("acct.privatelink.snowflakecomputing.com@other.example", False),
        ("other.example x.privatelink.snowflakecomputing.com", False),
        ("acct.privatelink.snowflakecomputing.com;x.example", False),
        ("acct.privatelink.snowflakecomputing.com/x.example", False),
        # Non-ASCII that full Unicode case folding would map into the recognized
        # apex (U+212A KELVIN SIGN -> "k") while DNS resolves the original name.
        ("acct.privatelink.snowflaKecomputing.com", False),
        # Malformed label structure.
        ("acct..privatelink.snowflakecomputing.com", False),
        ("", False),
        # Not a PrivateLink host at all.
        ("acct.us-east-1.snowflakecomputing.com", False),
        ("unrelated.example", False),
    ],
)
def test_privatelink_host_detection_is_label_boundary_anchored(host, is_privatelink):
    """SNOW-3675581: only a host that genuinely *ends* at a recognized Snowflake
    domain, carries a ".privatelink." label and is made purely of hostname
    characters drives the OCSP cache URL. Anything else falls through to the
    default cache URL."""
    from snowflake.connector.ocsp_snowflake import OCSPServer

    assert OCSPServer._is_privatelink_host(host) is is_privatelink


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "host,expected_authority",
    [
        (
            "ACCT.PrivateLink.SnowflakeComputing.com",
            "acct.privatelink.snowflakecomputing.com",
        ),
        (
            "acct.privatelink.snowflakecomputing.com.",
            "acct.privatelink.snowflakecomputing.com",
        ),
        (
            "acct.privatelink.snowflakecomputing.com:443",
            "acct.privatelink.snowflakecomputing.com",
        ),
        # The gate reads the host up to the first ':', so the cache URL must be
        # built from that same normalized value. Deriving it from the raw string
        # would authorize one authority and then contact another.
        (
            "acct.privatelink.snowflakecomputing.com:0@other.example",
            "acct.privatelink.snowflakecomputing.com",
        ),
    ],
)
def test_privatelink_cache_url_is_built_from_the_normalized_host(
    monkeypatch, host, expected_authority
):
    """The derived cache URL uses exactly the normalized host the gate judged,
    never the raw input."""
    monkeypatch.delenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", raising=False)
    monkeypatch.delenv("SF_OCSP_ACTIVATE_NEW_ENDPOINT", raising=False)

    ocsp = SFOCSP(hostname=host)

    assert ocsp.OCSP_CACHE_SERVER.CACHE_SERVER_URL == (
        f"http://ocsp.{expected_authority}/{OCSPCache.OCSP_RESPONSE_CACHE_FILE_NAME}"
    )


@pytest.mark.skipolddriver
def test_non_privatelink_host_uses_default_cache_url(monkeypatch):
    """A host that merely contains the PrivateLink domain as a non-terminal
    label falls through to the default OCSP cache URL, and its trailing labels
    do not appear in the derived URL."""
    monkeypatch.delenv("SF_OCSP_RESPONSE_CACHE_SERVER_URL", raising=False)
    monkeypatch.delenv("SF_OCSP_ACTIVATE_NEW_ENDPOINT", raising=False)

    ocsp = SFOCSP(hostname="acct.privatelink.snowflakecomputing.com.unrelated.example")
    url = ocsp.OCSP_CACHE_SERVER.CACHE_SERVER_URL

    assert "unrelated.example" not in url
    assert url.startswith("http://ocsp.snowflakecomputing.")

    assert (
        SnowflakeOCSP.OCSP_WHITELIST.match("www.snowflakecomputing.com")
        and SnowflakeOCSP.OCSP_WHITELIST.match("www.snowflakecomputing.cn")
        and SnowflakeOCSP.OCSP_WHITELIST.match("www.snowflakecomputing.com.cn")
        and not SnowflakeOCSP.OCSP_WHITELIST.match("www.snowflakecomputing.com.cn.com")
        and SnowflakeOCSP.OCSP_WHITELIST.match("s3.amazonaws.com")
        and SnowflakeOCSP.OCSP_WHITELIST.match("s3.amazonaws.cn")
        and SnowflakeOCSP.OCSP_WHITELIST.match("s3.amazonaws.com.cn")
        and not SnowflakeOCSP.OCSP_WHITELIST.match("s3.amazonaws.com.cn.com")
    )


@pytest.mark.skipolddriver
def test_json_cache_serialization_and_deserialization(tmpdir):
    from snowflake.connector.ocsp_snowflake import (
        OCSPResponseValidationResult,
        _OCSPResponseValidationResultCache,
    )

    cache_path = os.path.join(tmpdir, "cache.json")
    cert = asn1crypto509.Certificate.load(
        create_x509_cert(hashes.SHA256()).public_bytes(Encoding.DER)
    )
    cert_id = ocsp.CertId(
        {
            "hash_algorithm": {"algorithm": "sha1"},  # Minimal hash algorithm
            "issuer_name_hash": b"\0" * 20,  # Placeholder hash
            "issuer_key_hash": b"\0" * 20,  # Placeholder hash
            "serial_number": 1,  # Minimal serial number
        }
    )
    test_cache = _OCSPResponseValidationResultCache(file_path=cache_path)
    test_cache[(b"key1", b"key2", b"key3")] = OCSPResponseValidationResult(
        exception=None,
        issuer=cert,
        subject=cert,
        cert_id=cert_id,
        ocsp_response=b"response",
        ts=0,
        validated=True,
    )

    def verify(verify_method, write_cache):
        with io.BytesIO() as byte_stream:
            byte_stream.write(write_cache._serialize())
            byte_stream.seek(0)
            read_cache = _OCSPResponseValidationResultCache._deserialize(byte_stream)
            assert len(write_cache) == len(read_cache)
            verify_method(write_cache, read_cache)

    def verify_happy_path(origin_cache, loaded_cache):
        for (key1, value1), (key2, value2) in zip(
            origin_cache.items(), loaded_cache.items()
        ):
            assert key1 == key2
            for field in value1._fields:
                sub_field1 = getattr(value1, field)
                sub_field2 = getattr(value2, field)
                if field == "validated":
                    # SNOW-3675581: a verdict is never trusted across the disk
                    # boundary. Deserialization always resets `validated` to
                    # False (here the origin wrote True), so the entry is
                    # re-verified before it is trusted again.
                    assert sub_field2 is False
                    continue
                assert isinstance(sub_field1, type(sub_field2))
                if isinstance(sub_field1, asn1crypto.x509.Certificate):
                    for attr in [
                        "issuer",
                        "subject",
                        "serial_number",
                        "not_valid_before",
                        "not_valid_after",
                        "hash_algo",
                    ]:
                        assert getattr(sub_field1, attr) == getattr(sub_field2, attr)
                elif isinstance(sub_field1, asn1crypto.ocsp.CertId):
                    for attr in [
                        "hash_algorithm",
                        "issuer_name_hash",
                        "issuer_key_hash",
                        "serial_number",
                    ]:
                        assert sub_field1.native[attr] == sub_field2.native[attr]
                else:
                    assert sub_field1 == sub_field2

    def verify_none(origin_cache, loaded_cache):
        for (key1, value1), (key2, value2) in zip(
            origin_cache.items(), loaded_cache.items()
        ):
            assert key1 == key2 and value1 == value2

    def verify_exception(_, loaded_cache):
        """All cached exceptions are deserialized as RevocationCheckError (no dynamic import)."""
        exc_1 = loaded_cache[(b"key1", b"key2", b"key3")].exception
        exc_2 = loaded_cache[(b"key4", b"key5", b"key6")].exception
        exc_3 = loaded_cache[(b"key7", b"key8", b"key9")].exception
        assert (
            isinstance(exc_1, RevocationCheckError)
            and exc_1.raw_msg == "error"
            and exc_1.errno == 1
        )
        assert isinstance(exc_2, RevocationCheckError)
        assert exc_2.raw_msg == "value error"
        assert isinstance(exc_3, RevocationCheckError)
        assert exc_3.raw_msg == "json error: line 1 column 1 (char 0)"

    verify(verify_happy_path, copy.deepcopy(test_cache))

    origin_cache = copy.deepcopy(test_cache)
    origin_cache[(b"key1", b"key2", b"key3")] = OCSPResponseValidationResult(
        None, None, None, None, None, None, False
    )
    verify(verify_none, origin_cache)

    origin_cache = copy.deepcopy(test_cache)
    origin_cache.update(
        {
            (b"key1", b"key2", b"key3"): OCSPResponseValidationResult(
                exception=RevocationCheckError(msg="error", errno=1),
            ),
            (b"key4", b"key5", b"key6"): OCSPResponseValidationResult(
                exception=ValueError("value error"),
            ),
            (b"key7", b"key8", b"key9"): OCSPResponseValidationResult(
                exception=json.JSONDecodeError("json error", "doc", 0)
            ),
        }
    )
    verify(verify_exception, origin_cache)


def _build_ocsp_response_der(cert_id, status="good"):
    """Builds a minimal DER-encoded OCSP response containing a single response
    for *cert_id* with the given *status*. The signature is not real - tests
    that use this patch ``verify_signature`` to a no-op."""
    from asn1crypto import core as _core

    now = datetime.datetime.now(datetime.timezone.utc)
    if status == "good":
        cert_status = ocsp.CertStatus(name="good", value=_core.Null())
    elif status == "revoked":
        cert_status = ocsp.CertStatus(
            name="revoked",
            value=ocsp.RevokedInfo({"revocation_time": now}),
        )
    else:
        raise ValueError(status)

    single = ocsp.SingleResponse(
        {
            "cert_id": cert_id,
            "cert_status": cert_status,
            "this_update": now - datetime.timedelta(hours=1),
            "next_update": now + datetime.timedelta(days=1),
        }
    )
    tbs = ocsp.ResponseData(
        {
            "responder_id": ocsp.ResponderId(name="by_key", value=b"\x11" * 20),
            "produced_at": now,
            "responses": [single],
        }
    )
    basic = ocsp.BasicOCSPResponse(
        {
            "tbs_response_data": tbs,
            "signature_algorithm": {"algorithm": "sha256_rsa"},
            "signature": b"\x00" * 32,
        }
    )
    return ocsp.OCSPResponse(
        {
            "response_status": "successful",
            "response_bytes": ocsp.ResponseBytes(
                {
                    "response_type": "basic_ocsp_response",
                    "response": basic,
                }
            ),
        }
    ).dump()


def _make_cert_id(serial):
    return ocsp.CertId(
        {
            "hash_algorithm": {"algorithm": "sha1"},
            "issuer_name_hash": b"\x01" * 20,
            "issuer_key_hash": b"\x02" * 20,
            "serial_number": serial,
        }
    )


@pytest.mark.skipolddriver
@pytest.mark.parametrize("status", ["good", "revoked"])
def test_process_ocsp_response_rejects_certid_mismatch(status):
    """SNOW-3675581: a validly-signed OCSP response whose CertID does not match
    the certificate being validated must be rejected, regardless of the status
    it carries."""
    from snowflake.connector.errorcode import ER_OCSP_RESPONSE_CERT_ID_MISMATCH

    sfocsp = SFOCSP()
    requested = _make_cert_id(serial=111)
    other = _make_cert_id(serial=999)  # same issuer, different serial
    ocsp_response = _build_ocsp_response_der(other, status=status)
    issuer = asn1crypto509.Certificate.load(
        create_x509_cert(hashes.SHA256()).public_bytes(Encoding.DER)
    )

    with mock.patch.object(SFOCSP, "verify_signature", return_value=None):
        with pytest.raises(RevocationCheckError) as exc_info:
            sfocsp.process_ocsp_response(issuer, requested, ocsp_response)

    assert exc_info.value.errno == ER_OCSP_RESPONSE_CERT_ID_MISMATCH


@pytest.mark.skipolddriver
def test_process_ocsp_response_accepts_matching_certid():
    """A response whose CertID matches the validated certificate must pass the
    CertID check (it may fail later for unrelated reasons, but never with the
    mismatch errno)."""
    from snowflake.connector.errorcode import ER_OCSP_RESPONSE_CERT_ID_MISMATCH

    sfocsp = SFOCSP()
    requested = _make_cert_id(serial=111)
    ocsp_response = _build_ocsp_response_der(requested, status="good")
    issuer = asn1crypto509.Certificate.load(
        create_x509_cert(hashes.SHA256()).public_bytes(Encoding.DER)
    )

    with mock.patch.object(SFOCSP, "verify_signature", return_value=None):
        try:
            sfocsp.process_ocsp_response(issuer, requested, ocsp_response)
        except RevocationCheckError as err:
            assert err.errno != ER_OCSP_RESPONSE_CERT_ID_MISMATCH


@pytest.mark.skipolddriver
@pytest.mark.parametrize(
    "errno_name",
    [
        "ER_OCSP_RESPONSE_CERT_STATUS_REVOKED",
        "ER_OCSP_RESPONSE_CERT_ID_MISMATCH",
        "ER_OCSP_RESPONSE_INVALID_SIGNATURE",
    ],
)
def test_fail_open_treats_definitive_results_as_authoritative(errno_name):
    """SNOW-3675581: in fail-open mode, a definitive result -- a REVOKED verdict,
    a CertID mismatch, or an invalid signature -- is authoritative and must still
    fail the connection. Fail-open only tolerates an unavailable / unreachable
    responder, not a definitive answer about the certificate.

    verify_fail_open propagates each of these definitive errnos under fail-open
    (the default mode), so the CertID binding
    (ER_OCSP_RESPONSE_CERT_ID_MISMATCH) stays effective.
    """
    from snowflake.connector import errorcode as _errorcode
    from snowflake.connector.ocsp_snowflake import OCSPTelemetryData

    errno = getattr(_errorcode, errno_name)
    ocsp = SFOCSP(use_fail_open=True)
    assert ocsp.is_enabled_fail_open()

    ex = RevocationCheckError(msg="definitive result", errno=errno)
    result = ocsp.verify_fail_open(ex, OCSPTelemetryData())

    assert (
        result is ex
    ), "a definitive OCSP result must propagate even in fail-open mode"


@pytest.mark.skipolddriver
def test_fail_open_tolerates_unavailable_responder():
    """A soft/transient failure (responder unreachable) is still tolerated in
    fail-open mode -- that is the purpose of fail-open, and this change must not
    alter it."""
    from snowflake.connector import errorcode as _errorcode
    from snowflake.connector.ocsp_snowflake import OCSPTelemetryData

    ocsp = SFOCSP(use_fail_open=True)
    assert ocsp.is_enabled_fail_open()

    ex = RevocationCheckError(
        msg="responder unreachable", errno=_errorcode.ER_OCSP_RESPONSE_UNAVAILABLE
    )
    result = ocsp.verify_fail_open(ex, OCSPTelemetryData())

    assert (
        result is None
    ), "an unavailable responder must still be tolerated in fail-open mode"


@pytest.mark.skipolddriver
def test_cached_ocsp_result_is_revalidated_before_use(tmp_path):
    """SNOW-3675581 (on-disk verdict cache): a memoized OCSPResponseValidationResult
    loaded from the on-disk OCSP_RESPONSE_VALIDATION_CACHE is re-verified before
    use.

    The validation-result cache is persisted to a file under CACHE_DIR and
    deserialized back into memory, `validated` flag included.
    _validate_certificates_sequential short-circuits on any entry whose
    `validated` is True, returning its memoized `exception` without re-running
    process_ocsp_response -- so the CertID binding, the CA-signature check, and
    the freshness check would otherwise be skipped.

    This stores an entry (bound to the real chain's CertID so it survives
    re-verification) whose response body says REVOKED but whose memoized verdict
    reads exception=None / validated=True, routes it through the
    serialize/deserialize disk boundary, and asserts the REVOKED status is still
    enforced -- confirming disk-loaded verdicts are recomputed on load.
    """
    from snowflake.connector.errorcode import ER_OCSP_RESPONSE_CERT_STATUS_REVOKED
    from snowflake.connector.ocsp_snowflake import (
        OCSPResponseValidationResult,
        OCSPTelemetryData,
    )

    ocsp = SFOCSP()

    # A real (issuer, subject) chain -> the CertID/cache key the validator computes.
    issuer = asn1crypto509.Certificate.load(
        create_x509_cert(hashes.SHA256()).public_bytes(Encoding.DER)
    )
    subject = asn1crypto509.Certificate.load(
        create_x509_cert(hashes.SHA256()).public_bytes(Encoding.DER)
    )
    cert_id, _ = ocsp.create_ocsp_request(issuer, subject)
    cache_key = ocsp.decode_cert_id_key(cert_id)

    # Cache entry whose response body says REVOKED (bound to the correct CertID,
    # so it is caught on re-check) while the memoized verdict reads
    # exception=None ("good") and validated=True.
    revoked_der = _build_ocsp_response_der(cert_id, status="revoked")
    cached_entry = OCSPResponseValidationResult(
        exception=None,
        issuer=issuer,
        subject=subject,
        cert_id=cert_id,
        ocsp_response=revoked_der,
        ts=int(time.time()),
        validated=True,
    )
    # Round-trip through the on-disk (de)serialization boundary: this is how a
    # cache file's contents re-enter OCSP_RESPONSE_VALIDATION_CACHE on load.
    loaded = OCSPResponseValidationResult._deserialize(cached_entry._serialize())

    test_cache = SFDictFileCache(
        file_path=str(tmp_path / "ocsp_validation_cache.json"), entry_lifetime=3600
    )
    test_cache[cache_key] = loaded

    # verify_signature is a no-op so the test needs no real CA key; the point is
    # that the REVOKED status must be honored, not that the signature is real.
    with mock.patch(
        "snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE", test_cache
    ):
        with mock.patch.object(SFOCSP, "verify_signature", return_value=None):
            with pytest.raises(RevocationCheckError) as exc_info:
                ocsp._validate(
                    "example.snowflakecomputing.com",
                    [(issuer, subject)],
                    OCSPTelemetryData(),
                    do_retry=False,
                    no_exception=False,
                )

    assert exc_info.value.errno == ER_OCSP_RESPONSE_CERT_STATUS_REVOKED
