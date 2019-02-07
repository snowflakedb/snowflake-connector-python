# encoding=utf-8
# !/usr/bin/env python
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from snowflake.connector.ocsp_snowflake import OCSPCache


def test_building_retry_url():
    # privatelink retry url
    OCSPCache.ACTIVATE_SSD = False
    OCSPCache.RETRY_URL_PATTERN = None
    OCSPCache.CACHE_SERVER_URL = \
        'http://ocsp.us-east-1.snowflakecomputing.com/ocsp_response_cache.json'
    OCSPCache._reset_ocsp_dynamic_cache_server_url()
    assert OCSPCache.RETRY_URL_PATTERN == \
           'http://ocsp.us-east-1.snowflakecomputing.com/retry/{0}/{1}'

    # privatelink retry url with port
    OCSPCache.ACTIVATE_SSD = False
    OCSPCache.RETRY_URL_PATTERN = None
    OCSPCache.CACHE_SERVER_URL = \
        'http://ocsp.us-east-1.snowflakecomputing.com:80/ocsp_response_cache' \
        '.json'
    OCSPCache._reset_ocsp_dynamic_cache_server_url()
    assert OCSPCache.RETRY_URL_PATTERN == \
           'http://ocsp.us-east-1.snowflakecomputing.com:80/retry/{0}/{1}'

    # non-privatelink retry url
    OCSPCache.ACTIVATE_SSD = False
    OCSPCache.RETRY_URL_PATTERN = None
    OCSPCache.CACHE_SERVER_URL = \
        'http://ocsp.snowflakecomputing.com/ocsp_response_cache.json'
    OCSPCache._reset_ocsp_dynamic_cache_server_url()
    assert OCSPCache.RETRY_URL_PATTERN is None

    # non-privatelink retry url with port
    OCSPCache.ACTIVATE_SSD = False
    OCSPCache.RETRY_URL_PATTERN = None
    OCSPCache.CACHE_SERVER_URL = \
        'http://ocsp.snowflakecomputing.com:80/ocsp_response_cache.json'
    OCSPCache._reset_ocsp_dynamic_cache_server_url()
    assert OCSPCache.RETRY_URL_PATTERN is None

    # ssd enabled for privatelink retry url
    OCSPCache.ACTIVATE_SSD = True
    OCSPCache.RETRY_URL_PATTERN = None
    OCSPCache.CACHE_SERVER_URL = \
        'http://ocsp.us-east-1.snowflakecomputing.com/ocsp_response_cache.json'
    OCSPCache._reset_ocsp_dynamic_cache_server_url()
    assert OCSPCache.RETRY_URL_PATTERN == \
           'http://ocsp.us-east-1.snowflakecomputing.com/retry'

    # ssd enabled for privatelink retry url with port
    OCSPCache.ACTIVATE_SSD = True
    OCSPCache.RETRY_URL_PATTERN = None
    OCSPCache.CACHE_SERVER_URL = \
        'http://ocsp.us-east-1.snowflakecomputing.com:80/ocsp_response_cache' \
        '.json'
    OCSPCache._reset_ocsp_dynamic_cache_server_url()
    assert OCSPCache.RETRY_URL_PATTERN == \
           'http://ocsp.us-east-1.snowflakecomputing.com:80/retry'

    # ssd enabled for non-privatelink
    OCSPCache.ACTIVATE_SSD = True
    OCSPCache.RETRY_URL_PATTERN = None
    OCSPCache.CACHE_SERVER_URL = \
        'http://ocsp.snowflakecomputing.com/ocsp_response_cache.json'
    OCSPCache._reset_ocsp_dynamic_cache_server_url()
    assert OCSPCache.RETRY_URL_PATTERN == \
           'http://ocsp.snowflakecomputing.com/retry'

    # ssd enabled for non-privatelink with port
    OCSPCache.ACTIVATE_SSD = True
    OCSPCache.RETRY_URL_PATTERN = None
    OCSPCache.CACHE_SERVER_URL = \
        'http://ocsp.snowflakecomputing.com:80/ocsp_response_cache.json'
    OCSPCache._reset_ocsp_dynamic_cache_server_url()
    assert OCSPCache.RETRY_URL_PATTERN == \
           'http://ocsp.snowflakecomputing.com/retry'
