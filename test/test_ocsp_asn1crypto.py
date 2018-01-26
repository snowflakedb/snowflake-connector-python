#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import logging
import os
import time
from os import path

import pytest

from snowflake.connector import OperationalError
from snowflake.connector import ocsp_asn1crypto
from snowflake.connector.ssl_wrap_socket import _openssl_connect

for logger_name in ['test', 'snowflake.connector', 'botocore']:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler('/tmp/python_connector.log')
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter(
        '%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - '
        '%(funcName)s() - %(levelname)s - %(message)s'))
    logger.addHandler(ch)

TARGET_HOSTS = [
    'sfcsupport.us-east-1.snowflakecomputing.com',
    'sfcsupport.eu-central-1.snowflakecomputing.com',
    'sfc-dev1-regression.s3.amazonaws.com',
    'sfctest0.snowflakecomputing.com',
    'sfc-ds2-customer-stage.s3.amazonaws.com',
    'snowflake.okta.com',
    'sfcdev1.blob.core.windows.net',
]

THIS_DIR = path.dirname(path.realpath(__file__))


def test_ocsp():
    """
    OCSP tests using asn1crypto and whatever default caches
    """
    ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_asn1crypto.SnowflakeOCSP()
    for url in TARGET_HOSTS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), \
            'Failed to validate: {0}'.format(url)


def test_ocsp_with_file_cache(tmpdir):
    """
    OCSP tests using asn1crypto and the file cache
    """
    tmp_dir = str(tmpdir.mkdir('ocsp_response_cache'))
    cache_file_name = path.join(tmp_dir, 'cache_file.txt')

    ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_asn1crypto.SnowflakeOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name,
    )
    for url in TARGET_HOSTS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), \
            'Failed to validate: {0}'.format(url)


def test_ocsp_with_server_cache(tmpdir):
    """
    OCSP tests using asn1crypto and the server cache and file cache
    """
    tmp_dir = str(tmpdir.mkdir('ocsp_response_cache'))
    cache_file_name = path.join(tmp_dir, 'cache_file.txt')

    ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_asn1crypto.SnowflakeOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name,
        use_ocsp_cache_server=True)
    for hosname in TARGET_HOSTS:
        connection = _openssl_connect(hosname)
        assert ocsp.validate(hosname, connection), \
            'Failed to validate: {0}'.format(hosname)


def test_ocsp_with_bogus_cache_files(tmpdir):
    """
    Attempt to use bogus OCSP response data
    """
    cache_file_name, target_hosts = _store_cache_in_file(tmpdir)

    # reading cache file
    cache_data = {}
    ocsp_asn1crypto.read_ocsp_response_cache_file(cache_file_name, cache_data)
    assert cache_data, "more than one cache entries should be stored."

    # setting bogus data
    current_time = int(time.time())
    for k, v in cache_data.items():
        cache_data[k] = (current_time, b'bogus')

    # write back the cache file
    ocsp_asn1crypto.write_ocsp_response_cache_file(cache_file_name, cache_data)

    # forces to use the bogus cache file but it should raise errors
    ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_asn1crypto.SnowflakeOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    for hostname in target_hosts:
        connection = _openssl_connect(hostname)
        assert ocsp.validate(hostname, connection), \
            'Failed to validate: {0}'.format(hostname)


def test_ocsp_with_dated_cache(tmpdir):
    """
    Attempt to use dated OCSP response cache file
    """
    cache_file_name, target_hosts = _store_cache_in_file(tmpdir)

    # reading cache file
    cache_data = {}
    ocsp_asn1crypto.read_ocsp_response_cache_file(cache_file_name, cache_data)
    assert cache_data, "more than one cache entries should be stored."

    # setting dated data
    current_time = int(time.time())
    for k, v in cache_data.items():
        cache_data[k] = (current_time - 48 * 60 * 60, v[1])

    # write back the cache file
    ocsp_asn1crypto.write_ocsp_response_cache_file(cache_file_name, cache_data)

    # forces to use the bogus cache file but it should raise errors
    ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp_asn1crypto.SnowflakeOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    assert not ocsp_asn1crypto.OCSP_VALIDATION_CACHE, 'must be empty'


def _store_cache_in_file(tmpdir):
    tmp_dir = str(tmpdir.mkdir('ocsp_response_cache'))
    cache_file_name = path.join(tmp_dir, 'cache_file.txt')
    # cache OCSP response
    ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_asn1crypto.SnowflakeOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    for hostname in TARGET_HOSTS:
        connection = _openssl_connect(hostname)
        assert ocsp.validate(hostname, connection), \
            'Failed to validate: {0}'.format(hostname)
    assert path.exists(cache_file_name), "OCSP response cache file"
    return cache_file_name, TARGET_HOSTS


def test_ocsp_with_invalid_cache_file():
    """
    OCSP tests with an invalid cache file
    """
    ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_asn1crypto.SnowflakeOCSP(
        ocsp_response_cache_uri="NEVER_EXISTS")
    for url in TARGET_HOSTS[0:1]:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), \
            'Failed to validate: {0}'.format(url)


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
        with ocsp_asn1crypto.OCSP_VALIDATION_CACHE_LOCK:
            ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}
    if random.random() < 0.05:
        logger.info('deleting a cache file: %s', cache_file_name)
        ocsp_asn1crypto._lock_cache_file(cache_file_name)
        try:
            os.unlink(cache_file_name)
        finally:
            ocsp_asn1crypto._unlock_cache_file(cache_file_name)
    connection = _openssl_connect(url)
    ocsp = ocsp_asn1crypto.SnowflakeOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    ocsp.validate(url, connection)


def test_concurrent_ocsp_requests(tmpdir):
    """
    Run OCSP revocation checks in parallel. The memory and file caches are
    deleted randomly.
    """
    from multiprocessing.pool import ThreadPool

    cache_file_name = path.join(str(tmpdir), 'cache_file.txt')
    ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}  # reset the memory cache

    target_hosts = TARGET_HOSTS * 5
    pool = ThreadPool(len(target_hosts))
    for hostname in target_hosts:
        pool.apply_async(_validate_certs_using_ocsp,
                         [hostname, cache_file_name])
    pool.close()
    pool.join()


def test_ocsp_revoked_certificate():
    """
    Test Revoked certificate.
    """
    revoked_cert = path.join(
        THIS_DIR, 'data', 'cert_tests', 'revoked_certs.pem')

    ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_asn1crypto.SnowflakeOCSP()

    with pytest.raises(OperationalError) as ex:
        ocsp.validate_certfile(revoked_cert)
    assert 'revoked' in ex.value.msg


def test_ocsp_incomplete_chain():
    """
    Test incomplete chained certificate
    """
    revoked_cert = path.join(
        THIS_DIR, 'data', 'cert_tests', 'incomplete-chain.pem')

    ocsp_asn1crypto.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_asn1crypto.SnowflakeOCSP()

    with pytest.raises(OperationalError) as ex:
        ocsp.validate_certfile(revoked_cert)
    assert 'CA certificate is NOT found' in ex.value.msg
