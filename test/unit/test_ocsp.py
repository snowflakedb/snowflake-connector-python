#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import datetime
import logging
import os
import platform
import time
from concurrent.futures.thread import ThreadPoolExecutor
from os import environ, path
from unittest import mock

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


@pytest.fixture(autouse=True)
def random_ocsp_response_validation_cache():
    file_path = {
        "linux": os.path.join(
            "~",
            ".cache",
            "snowflake",
            f"ocsp_response_validation_cache{random_string()}",
        ),
        "darwin": os.path.join(
            "~",
            "Library",
            "Caches",
            "Snowflake",
            f"ocsp_response_validation_cache{random_string()}",
        ),
        "windows": os.path.join(
            "~",
            "AppData",
            "Local",
            "Snowflake",
            "Caches",
            f"ocsp_response_validation_cache{random_string()}",
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


def test_ocsp_wo_cache_file():
    """OCSP tests without File cache.

    Notes:
        Use /etc as a readonly directory such that no cache file is used.
    """
    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    OCSPCache.del_cache_file()
    environ["SF_OCSP_RESPONSE_CACHE_DIR"] = "/etc"
    OCSPCache.reset_cache_dir()

    try:
        ocsp = SFOCSP()
        for url in TARGET_HOSTS:
            connection = _openssl_connect(url)
            assert ocsp.validate(url, connection), f"Failed to validate: {url}"
    finally:
        del environ["SF_OCSP_RESPONSE_CACHE_DIR"]
        OCSPCache.reset_cache_dir()


def test_ocsp_fail_open_w_single_endpoint():
    SnowflakeOCSP.clear_cache()

    OCSPCache.del_cache_file()

    environ["SF_OCSP_TEST_MODE"] = "true"
    environ["SF_TEST_OCSP_URL"] = "http://httpbin.org/delay/10"
    environ["SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT"] = "5"

    ocsp = SFOCSP(use_ocsp_cache_server=False)
    connection = _openssl_connect("snowflake.okta.com")

    try:
        assert ocsp.validate(
            "snowflake.okta.com", connection
        ), "Failed to validate: {}".format("snowflake.okta.com")
    finally:
        del environ["SF_OCSP_TEST_MODE"]
        del environ["SF_TEST_OCSP_URL"]
        del environ["SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT"]


@pytest.mark.skipif(
    ER_OCSP_RESPONSE_CERT_STATUS_REVOKED is None,
    reason="No ER_OCSP_RESPONSE_CERT_STATUS_REVOKED is available.",
)
def test_ocsp_fail_close_w_single_endpoint():
    SnowflakeOCSP.clear_cache()

    environ["SF_OCSP_TEST_MODE"] = "true"
    environ["SF_TEST_OCSP_URL"] = "http://httpbin.org/delay/10"
    environ["SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT"] = "5"

    OCSPCache.del_cache_file()

    ocsp = SFOCSP(use_ocsp_cache_server=False, use_fail_open=False)
    connection = _openssl_connect("snowflake.okta.com")

    with pytest.raises(RevocationCheckError) as ex:
        ocsp.validate("snowflake.okta.com", connection)

    try:
        assert (
            ex.value.errno == ER_OCSP_RESPONSE_FETCH_FAILURE
        ), "Connection should have failed"
    finally:
        del environ["SF_OCSP_TEST_MODE"]
        del environ["SF_TEST_OCSP_URL"]
        del environ["SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT"]


def test_ocsp_bad_validity():
    SnowflakeOCSP.clear_cache()

    environ["SF_OCSP_TEST_MODE"] = "true"
    environ["SF_TEST_OCSP_FORCE_BAD_RESPONSE_VALIDITY"] = "true"

    OCSPCache.del_cache_file()

    ocsp = SFOCSP(use_ocsp_cache_server=False)
    connection = _openssl_connect("snowflake.okta.com")

    assert ocsp.validate(
        "snowflake.okta.com", connection
    ), "Connection should have passed with fail open"
    del environ["SF_OCSP_TEST_MODE"]
    del environ["SF_TEST_OCSP_FORCE_BAD_RESPONSE_VALIDITY"]


def test_ocsp_single_endpoint():
    environ["SF_OCSP_ACTIVATE_NEW_ENDPOINT"] = "True"
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP()
    ocsp.OCSP_CACHE_SERVER.NEW_DEFAULT_CACHE_SERVER_BASE_URL = "https://snowflake.preprod3.us-west-2-dev.external-zone.snowflakecomputing.com:8085/ocsp/"
    connection = _openssl_connect("snowflake.okta.com")
    assert ocsp.validate(
        "snowflake.okta.com", connection
    ), "Failed to validate: {}".format("snowflake.okta.com")

    del environ["SF_OCSP_ACTIVATE_NEW_ENDPOINT"]


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
def test_ocsp_with_bogus_cache_files(tmpdir, random_ocsp_response_validation_cache):
    with mock.patch(
        "snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE",
        random_ocsp_response_validation_cache,
    ):
        from snowflake.connector.ocsp_snowflake import OCSPResponseValidationResult

        """Attempts to use bogus OCSP response data."""
        cache_file_name, target_hosts = _store_cache_in_file(tmpdir)

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
def test_ocsp_with_outdated_cache(tmpdir, random_ocsp_response_validation_cache):
    with mock.patch(
        "snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE",
        random_ocsp_response_validation_cache,
    ):
        from snowflake.connector.ocsp_snowflake import OCSPResponseValidationResult

        """Attempts to use outdated OCSP response cache file."""
        cache_file_name, target_hosts = _store_cache_in_file(tmpdir)

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


def _store_cache_in_file(tmpdir, target_hosts=None):
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
        connection = _openssl_connect(hostname)
        assert ocsp.validate(hostname, connection), "Failed to validate: {}".format(
            hostname
        )
    assert path.exists(filename), "OCSP response cache file"
    return filename, target_hosts


def test_ocsp_with_invalid_cache_file():
    """OCSP tests with an invalid cache file."""
    SnowflakeOCSP.clear_cache()  # reset the memory cache
    ocsp = SFOCSP(ocsp_response_cache_uri="NEVER_EXISTS")
    for url in TARGET_HOSTS[0:1]:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), f"Failed to validate: {url}"


@mock.patch(
    "snowflake.connector.ocsp_snowflake.SnowflakeOCSP._fetch_ocsp_response",
    side_effect=BrokenPipeError("fake error"),
)
def test_ocsp_cache_when_server_is_down(
    mock_fetch_ocsp_response, tmpdir, random_ocsp_response_validation_cache
):
    with mock.patch(
        "snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE",
        random_ocsp_response_validation_cache,
    ):
        ocsp = SFOCSP()

        """Attempts to use outdated OCSP response cache file."""
        cache_file_name, target_hosts = _store_cache_in_file(tmpdir)

        # reading cache file
        OCSPCache.read_ocsp_response_cache_file(ocsp, cache_file_name)
        cache_data = snowflake.connector.ocsp_snowflake.OCSP_RESPONSE_VALIDATION_CACHE
        assert not cache_data, "no cache should present because of broken pipe"


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


def test_building_new_retry():
    OCSP_SERVER = OCSPServer()
    OCSP_SERVER.OCSP_RETRY_URL = None
    hname = "a1.us-east-1.snowflakecomputing.com"
    os.environ["SF_OCSP_ACTIVATE_NEW_ENDPOINT"] = "true"
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

    del os.environ["SF_OCSP_ACTIVATE_NEW_ENDPOINT"]


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

    cert = (
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
