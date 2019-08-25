#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import codecs
import json
import logging
import tempfile
import time
import os
import platform
from os import path
from os import environ


import pytest

from snowflake.connector import OperationalError
from snowflake.connector.compat import PY2
from snowflake.connector.errorcode import (ER_SERVER_CERTIFICATE_REVOKED, ER_INVALID_OCSP_RESPONSE_CODE)
from snowflake.connector.ocsp_snowflake import SnowflakeOCSP
from snowflake.connector.errors import RevocationCheckError

if PY2:
    from snowflake.connector.ocsp_pyasn1 import (
        SnowflakeOCSPPyasn1 as SFOCSP
    )
else:
    from snowflake.connector.ocsp_asn1crypto import (
        SnowflakeOCSPAsn1Crypto as SFOCSP
    )

from snowflake.connector.ocsp_snowflake import OCSPCache
from snowflake.connector.ssl_wrap_socket import _openssl_connect

for logger_name in ['test', 'snowflake.connector', 'botocore']:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(
        path.join(tempfile.gettempdir(), 'python_connector.log'))
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter(
        '%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - '
        '%(funcName)s() - %(levelname)s - %(message)s'))
    logger.addHandler(ch)

TARGET_HOSTS = [
    'ocspssd.us-east-1.snowflakecomputing.com',
    'sqs.us-west-2.amazonaws.com',
    'sfcsupport.us-east-1.snowflakecomputing.com',
    'sfcsupport.eu-central-1.snowflakecomputing.com',
    'sfc-dev1-regression.s3.amazonaws.com',
    'sfctest0.snowflakecomputing.com',
    'sfc-ds2-customer-stage.s3.amazonaws.com',
    'snowflake.okta.com',
    'sfcdev1.blob.core.windows.net',
    'sfc-aus-ds1-customer-stage.s3-ap-southeast-2.amazonaws.com',
]

THIS_DIR = path.dirname(path.realpath(__file__))

CACHE_ROOT_DIR = os.getenv('SF_OCSP_RESPONSE_CACHE_DIR') or \
                     os.path.expanduser("~") or tempfile.gettempdir()

if platform.system() == 'Windows':
    CACHE_DIR = path.join(CACHE_ROOT_DIR, 'AppData', 'Local', 'Snowflake',
                          'Caches')
elif platform.system() == 'Darwin':
    CACHE_DIR = path.join(CACHE_ROOT_DIR, 'Library', 'Caches', 'Snowflake')
else:
    CACHE_DIR = path.join(CACHE_ROOT_DIR, '.cache', 'snowflake')

CACHE_LOCATION = path.join(CACHE_DIR, "ocsp_response_cache.json")


def test_ocsp():
    """
    OCSP tests
    """
    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP()
    for url in TARGET_HOSTS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), \
            'Failed to validate: {0}'.format(url)


def test_ocsp_wo_cache_server():
    """
    OCSP Tests with Cache Server Disabled
    """
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(use_ocsp_cache_server=False)
    for url in TARGET_HOSTS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection),\
            'Failed to validate: {0}'.format(url)


def test_ocsp_fail_open_w_single_endpoint():
    SnowflakeOCSP.clear_cache()

    if os.path.exists(CACHE_LOCATION):
        os.remove(CACHE_LOCATION)

    environ["SF_OCSP_TEST_MODE"] = "true"
    environ["SF_TEST_OCSP_URL"] = "http://httpbin.org/delay/10"
    environ["SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT"] = "5"

    ocsp = SFOCSP(use_ocsp_cache_server=False)
    connection = _openssl_connect("snowflake.okta.com")

    try:
        assert ocsp.validate("snowflake.okta.com", connection), \
            'Failed to validate: {0}'.format("snowflake.okta.com")
    finally:
        del environ['SF_OCSP_TEST_MODE']
        del environ['SF_TEST_OCSP_URL']
        del environ['SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT']


def test_ocsp_fail_close_w_single_endpoint():
    SnowflakeOCSP.clear_cache()

    environ["SF_OCSP_TEST_MODE"] = "true"
    environ["SF_TEST_OCSP_URL"] = "http://httpbin.org/delay/10"
    environ["SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT"] = "5"

    if os.path.exists(CACHE_LOCATION):
        os.remove(CACHE_LOCATION)

    ocsp = SFOCSP(use_ocsp_cache_server=False, use_fail_open=False)
    connection = _openssl_connect("snowflake.okta.com")

    with pytest.raises(RevocationCheckError) as ex:
        ocsp.validate("snowflake.okta.com", connection)

    try:
        assert ex.value.errno == ER_INVALID_OCSP_RESPONSE_CODE, "Connection should have failed"
    finally:
        del environ['SF_OCSP_TEST_MODE']
        del environ['SF_TEST_OCSP_URL']
        del environ['SF_TEST_CA_OCSP_RESPONDER_CONNECTION_TIMEOUT']


def test_ocsp_bad_validity():
    SnowflakeOCSP.clear_cache()

    environ["SF_OCSP_TEST_MODE"] = "true"
    environ["SF_TEST_OCSP_FORCE_BAD_RESPONSE_VALIDITY"] = "true"

    if os.path.exists(CACHE_LOCATION):
        os.remove(CACHE_LOCATION)

    ocsp = SFOCSP(use_ocsp_cache_server=False)
    connection = _openssl_connect("snowflake.okta.com")

    assert ocsp.validate("snowflake.okta.com", connection), "Connection should have passed with fail open"
    del environ['SF_OCSP_TEST_MODE']
    del environ['SF_TEST_OCSP_FORCE_BAD_RESPONSE_VALIDITY']


def test_ocsp_single_endpoint():
    environ['SF_OCSP_ACTIVATE_NEW_ENDPOINT'] = 'True'
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP()
    ocsp.OCSP_CACHE_SERVER.NEW_DEFAULT_CACHE_SERVER_BASE_URL = \
        "https://snowflake.preprod2.us-west-2-dev.external-zone.snowflakecomputing.com:8085/ocsp/"
    connection = _openssl_connect("snowflake.okta.com")
    assert ocsp.validate("snowflake.okta.com", connection), \
        'Failed to validate: {0}'.format("snowflake.okta.com")

    del environ['SF_OCSP_ACTIVATE_NEW_ENDPOINT']


def test_ocsp_by_post_method():
    """
    OCSP tests
    """
    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(use_post_method=True)
    for url in TARGET_HOSTS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), \
            'Failed to validate: {0}'.format(url)


def test_ocsp_with_file_cache(tmpdir):
    """
    OCSP tests and the cache server and file
    """
    tmp_dir = str(tmpdir.mkdir('ocsp_response_cache'))
    cache_file_name = path.join(tmp_dir, 'cache_file.txt')

    # reset the memory cache
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    for url in TARGET_HOSTS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), \
            'Failed to validate: {0}'.format(url)


def test_ocsp_with_bogus_cache_files(tmpdir):
    """
    Attempt to use bogus OCSP response data
    """

    cache_file_name, target_hosts = _store_cache_in_file(tmpdir)

    ocsp = SFOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    OCSPCache.read_ocsp_response_cache_file(ocsp, cache_file_name)
    cache_data = OCSPCache.CACHE
    assert cache_data, "more than one cache entries should be stored."

    # setting bogus data
    current_time = int(time.time())
    for k, v in cache_data.items():
        cache_data[k] = (current_time, b'bogus')

    # write back the cache file
    OCSPCache.CACHE = cache_data
    OCSPCache.write_ocsp_response_cache_file(ocsp, cache_file_name)

    # forces to use the bogus cache file but it should raise errors
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    for hostname in target_hosts:
        connection = _openssl_connect(hostname)
        assert ocsp.validate(hostname, connection), \
            'Failed to validate: {0}'.format(hostname)


def test_ocsp_with_outdated_cache(tmpdir):
    """
    Attempt to use outdated OCSP response cache file
    """
    cache_file_name, target_hosts = _store_cache_in_file(tmpdir)

    ocsp = SFOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)

    # reading cache file
    OCSPCache.read_ocsp_response_cache_file(ocsp, cache_file_name)
    cache_data = OCSPCache.CACHE
    assert cache_data, "more than one cache entries should be stored."

    # setting outdated data
    current_time = int(time.time())
    for k, v in cache_data.items():
        cache_data[k] = (current_time - 48 * 60 * 60, v[1])

    # write back the cache file
    OCSPCache.CACHE = cache_data
    OCSPCache.write_ocsp_response_cache_file(ocsp, cache_file_name)

    # forces to use the bogus cache file but it should raise errors
    SnowflakeOCSP.clear_cache()  # reset the memory cache
    SFOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    assert SnowflakeOCSP.cache_size() == 0, \
        'must be empty. outdated cache should not be loaded'


def _store_cache_in_file(
        tmpdir, target_hosts=None, filename=None):
    if target_hosts is None:
        target_hosts = TARGET_HOSTS
    if filename is None:
        filename = path.join(str(tmpdir), 'cache_file.txt')

    # cache OCSP response
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(
        ocsp_response_cache_uri='file://' + filename,
        use_ocsp_cache_server=False)
    for hostname in target_hosts:
        connection = _openssl_connect(hostname)
        assert ocsp.validate(hostname, connection), \
            'Failed to validate: {0}'.format(hostname)
    assert path.exists(filename), "OCSP response cache file"
    return filename, target_hosts


def test_ocsp_with_invalid_cache_file():
    """
    OCSP tests with an invalid cache file
    """
    SnowflakeOCSP.clear_cache()  # reset the memory cache
    ocsp = SFOCSP(ocsp_response_cache_uri="NEVER_EXISTS")
    for url in TARGET_HOSTS[0:1]:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), \
            'Failed to validate: {0}'.format(url)


def test_concurrent_ocsp_requests(tmpdir):
    """
    Run OCSP revocation checks in parallel. The memory and file caches are
    deleted randomly.
    """
    from multiprocessing.pool import ThreadPool

    cache_file_name = path.join(str(tmpdir), 'cache_file.txt')
    SnowflakeOCSP.clear_cache()  # reset the memory cache

    target_hosts = TARGET_HOSTS * 5
    pool = ThreadPool(len(target_hosts))
    for hostname in target_hosts:
        pool.apply_async(_validate_certs_using_ocsp,
                         [hostname, cache_file_name])
    pool.close()
    pool.join()


def _validate_certs_using_ocsp(url, cache_file_name):
    """
    Validate OCSP response. Deleting memory cache and file cache randomly
    """
    logger = logging.getLogger('test')
    import time
    import random
    time.sleep(random.randint(0, 3))
    if random.random() < 0.2:
        logger.info('clearing up cache: OCSP_VALIDATION_CACHE')
        SnowflakeOCSP.clear_cache()
    if random.random() < 0.05:
        logger.info('deleting a cache file: %s', cache_file_name)
        SnowflakeOCSP.delete_cache_file()

    connection = _openssl_connect(url)
    ocsp = SFOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    ocsp.validate(url, connection)


def test_ocsp_revoked_certificate():
    """
    Test Revoked certificate.
    """
    revoked_cert = path.join(
        THIS_DIR, 'data', 'cert_tests', 'revoked_certs.pem')

    SnowflakeOCSP.clear_cache()  # reset the memory cache
    ocsp = SFOCSP()

    with pytest.raises(OperationalError) as ex:
        ocsp.validate_certfile(revoked_cert)
    assert ex.value.errno == ex.value.errno == ER_SERVER_CERTIFICATE_REVOKED


def test_ocsp_incomplete_chain():
    """
    Test incomplete chained certificate
    """
    incomplete_chain_cert = path.join(
        THIS_DIR, 'data', 'cert_tests', 'incomplete-chain.pem')

    SnowflakeOCSP.clear_cache()  # reset the memory cache
    ocsp = SFOCSP()

    with pytest.raises(OperationalError) as ex:
        ocsp.validate_certfile(incomplete_chain_cert)
    assert 'CA certificate is NOT found' in ex.value.msg


def test_ocsp_cache_merge(tmpdir):
    """
    Merge two OCSP response cache files
    """
    previous_cache_filename = path.join(str(tmpdir), 'cache_file1.txt')
    _store_cache_in_file(
        tmpdir,
        target_hosts=TARGET_HOSTS[0:3],
        filename=previous_cache_filename)

    current_cache_filename = path.join(str(tmpdir), 'cache_file2.txt')
    _store_cache_in_file(
        tmpdir,
        target_hosts=TARGET_HOSTS[4:],
        filename=current_cache_filename)

    latest_cache_filename = path.join(str(tmpdir), 'cache_file.txt')

    SnowflakeOCSP.clear_cache()  # reset the memory cache
    ocsp = SFOCSP()
    OCSPCache.merge_cache(
        ocsp,
        previous_cache_filename,
        current_cache_filename,
        latest_cache_filename)

    with codecs.open(previous_cache_filename) as f:
        prev = json.load(f)
    with codecs.open(current_cache_filename) as f:
        curr = json.load(f)
    with codecs.open(latest_cache_filename) as f:
        latest = json.load(f)

    assert len(latest) > len(prev)
    assert len(latest) > len(curr)
