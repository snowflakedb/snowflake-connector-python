#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import logging
import os
import time
from copy import deepcopy
from os import path

import pytest

from snowflake.connector import ocsp_pyasn1
from snowflake.connector.ssl_wrap_socket import _openssl_connect
from snowflake.connector.compat import PY2

for logger_name in ['test', 'snowflake.connector', 'botocore']:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler('/tmp/python_connector.log')
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter(
        '%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - '
        '%(funcName)s() - %(levelname)s - %(message)s'))
    logger.addHandler(ch)

URLS = [
    'sqs.us-west-2.amazonaws.com',
    'sfc-dev1-regression.s3.amazonaws.com',
    'sfctest0.snowflakecomputing.com',
    'sfc-ds2-customer-stage.s3.amazonaws.com',
    'sfcdev1.blob.core.windows.net',
]


@pytest.mark.skipif(not PY2, reason="Python 2 only")
def test_ocsp():
    """
    OCSP tests for PyOpenSSL
    """
    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_pyasn1.SnowflakeOCSP()
    for url in URLS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), \
            'Failed to validate: {0}'.format(url)


@pytest.mark.skipif(not PY2, reason="Python 2 only")
def test_ocsp_with_file_cache(tmpdir):
    """
    OCSP tests for PyOpenSSL
    """
    tmp_dir = str(tmpdir.mkdir('ocsp_response_cache'))
    cache_file_name = path.join(tmp_dir, 'cache_file.txt')

    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_pyasn1.SnowflakeOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    for url in URLS:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), \
            'Failed to validate: {0}'.format(url)


@pytest.mark.skipif(not PY2, reason="Python 2 only")
def test_ocsp_generate_pair_of_certid_response(tmpdir):
    u"""
    Writes OCSP Response cache in a file.
    """
    tmp_dir = str(tmpdir.mkdir('ocsp_response_cache'))
    cache_file_name = path.join(tmp_dir, 'cache_file.txt')

    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_pyasn1.SnowflakeOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    urls = [
        'sfc-dev1-regression.s3.amazonaws.com',
        'sfctest0.snowflakecomputing.com',
        'sfc-ds2-customer-stage.s3.amazonaws.com',
        'snowflake.okta.com',
        'sfcdev1.blob.core.windows.net',
    ]

    # cache OCSP response
    current_time = int(time.time())
    cache_data = {}
    for url in urls:
        connection = _openssl_connect(url)
        assert ocsp.validate(url, connection), \
            'Failed to validate: {0}'.format(url)

    backup_cache_data = deepcopy(cache_data)

    # validate the certificate with cache
    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_pyasn1.SnowflakeOCSP(
        must_use_cache=True,
        ocsp_response_cache_uri='file://' + cache_file_name)
    for url in urls:
        connection = _openssl_connect(url)
        assert ocsp.validate(
            url, connection), \
            'Failed to validate: {0}'.format(url)

    # validate the certificate again with bogus cache data
    # this should be success too as OCSP module is supposed to retry
    # fetching data from the official OCSP server
    cache_file_name = path.join(tmp_dir, 'cache_file_bogus.txt')
    for k, v in cache_data.items():
        cache_data[k] = (current_time, b'bogus')
    ocsp_pyasn1.write_ocsp_response_cache_file(
        cache_file_name,
        cache_data)

    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_pyasn1.SnowflakeOCSP(
        must_use_cache=True,
        ocsp_response_cache_uri='file://' + cache_file_name)
    for url in urls:
        connection = _openssl_connect(url)
        assert ocsp.validate(
            url, connection), \
            'Failed to validate: {0}'.format(url)

    # validate the certificates again with invalid dated cache
    current_time = int(time.time())
    cache_data = deepcopy(backup_cache_data)
    for k, v in cache_data.items():
        cache_data[k] = (current_time - 48 * 60 * 60, v[1])  # 2 days ago
    cache_file_name = path.join(tmp_dir, 'cache_file_invaliddate.txt')
    ocsp_pyasn1.write_ocsp_response_cache_file(
        cache_file_name,
        cache_data)

    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    ocsp = ocsp_pyasn1.SnowflakeOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    for url in urls:
        connection = _openssl_connect(url)
        assert ocsp.validate(
            url, connection), \
            'Failed to validate: {0}'.format(url)


def _validate_urls(urls, must_use_cache=False, ocsp_response_cache_uri=None):
    ocsp = ocsp_pyasn1.SnowflakeOCSP(
        must_use_cache=must_use_cache,
        ocsp_response_cache_uri=ocsp_response_cache_uri)
    for url in urls:
        connection = _openssl_connect(url)
        ocsp.validate(url, connection)


@pytest.mark.skipif(not PY2, reason="Python 2 only")
def test_negative_ocsp_response_file_cache(tmpdir):
    tmp_dir = str(tmpdir.mkdir('ocsp_response_file_cache_negative'))
    urls = [
        'sfctest0.snowflakecomputing.com',
    ]

    cache_file_name = path.join(tmp_dir, 'cache_file.txt')

    # no cache is used
    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    _validate_urls(urls,
                   ocsp_response_cache_uri='file://' + cache_file_name)

    bogus_file = path.join(tmp_dir, 'bogus.txt')
    with open(bogus_file, 'w') as f:
        f.write('foobar')
    st = os.stat(bogus_file)
    os.chmod(bogus_file, st.st_mode & 0o400)  # no write access
    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    _validate_urls(urls,
                   ocsp_response_cache_uri='file://' + bogus_file)

    os.chmod(bogus_file, st.st_mode & 0o200)  # no read access
    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    _validate_urls(urls,
                   ocsp_response_cache_uri='file://' + bogus_file)

    os.chmod(bogus_file, st.st_mode & 0o000)  # no access
    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    _validate_urls(urls,
                   ocsp_response_cache_uri='file://' + bogus_file)


def _validate_certs_using_ocsp(url, cache_file_name):
    logger = logging.getLogger('test')
    import time
    import random
    time.sleep(random.randint(0, 3))
    if random.random() < 0.2:
        logger.info('clearing up cache: OCSP_VALIDATION_CACHE')
        with ocsp_pyasn1.OCSP_VALIDATION_CACHE_LOCK:
            ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}
    if random.random() < 0.05:
        logger.info('deleting a cache file: %s', cache_file_name)
        os.unlink(cache_file_name)
    connection = _openssl_connect(url)
    ocsp = ocsp_pyasn1.SnowflakeOCSP(
        ocsp_response_cache_uri='file://' + cache_file_name)
    ocsp.validate(url, connection)


@pytest.mark.skipif(not PY2, reason="Python 2 only")
def test_concurrent_ocsp_requests(tmpdir):
    from multiprocessing.pool import ThreadPool

    cache_file_name = path.join(str(tmpdir), 'cache_file.txt')
    ocsp_pyasn1.OCSP_VALIDATION_CACHE = {}  # reset the memory cache
    urls = URLS * 5
    pool = ThreadPool(len(urls))
    for url in urls:
        pool.apply_async(_validate_certs_using_ocsp, [url, cache_file_name])
    pool.close()
    pool.join()
